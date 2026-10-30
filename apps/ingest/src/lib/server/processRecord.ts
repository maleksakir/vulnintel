import type {
  EpssPatch,
  KevPatch,
  NormalizedCveRecord,
  SsvcDecision,
} from '@threat-lens/contracts';
import type { Env } from '../../types';
import { buildEmbedText, embed } from './embed';
import { computeStateHash, computeTextHash } from './hash';

interface CurrentRow {
  text_hash: string;
  state_hash: string;
  kev_listed: number;
  epss_score: number | null;
  epss_percentile: number | null;
  ssvc_exploitation: string | null;
  ssvc_automatable: string | null;
  ssvc_technical_impact: string | null;
}

export interface ProcessOptions {
  opType?: 'UPSERT_ALL' | 'VECTORIZE_ONLY';
  vector?: number[];
}

/**
 * Persists one NormalizedCveRecord using the two-hash strategy (§5.1.4).
 *
 * Decision table:
 *   text changed  → full D1 write  + new embedding + Vectorize upsert
 *   state only    → D1 state write + metadata-only Vectorize upsert (no AI call)
 *   no change     → skip (no-op)
 *
 * On D1 failure  → enqueue UPSERT_ALL  to retry queue.
 * On AI failure  → enqueue VECTORIZE_ONLY (no vector; will re-embed on retry).
 * On Vec failure → enqueue VECTORIZE_ONLY with pre-computed vector.
 */
export async function processRecord(
  record: NormalizedCveRecord,
  env: Env,
  ctx: ExecutionContext,
  opts: ProcessOptions = {},
): Promise<void> {
  const t0 = Date.now();
  const topVendors = [...new Set(record.cpes.map((c) => c.vendor))].sort().slice(0, 5);
  const topVendor = topVendors[0] ?? null;

  const textHash = await computeTextHash(record);

  const cur = await env.DB.prepare(
    `SELECT c.text_hash, c.state_hash,
            COALESCE(s.kev_listed, 0)    AS kev_listed,
            s.epss_score,
            s.epss_percentile,
            s.ssvc_exploitation,
            s.ssvc_automatable,
            s.ssvc_technical_impact
     FROM cve c
     LEFT JOIN cve_state s USING (cve_id)
     WHERE c.cve_id = ?`,
  )
    .bind(record.cveId)
    .first<CurrentRow>();

  const kevListed = (cur?.kev_listed ?? 0) === 1;
  const epssScore = cur?.epss_score ?? null;
  const epssPercentile = cur?.epss_percentile ?? null;

  const stateHash = await computeStateHash(
    record.severity,
    record.cvss?.base ?? null,
    kevListed,
    epssScore,
    topVendor,
  );

  const textChanged = !cur || cur.text_hash !== textHash;
  const stateChanged = !cur || cur.state_hash !== stateHash;
  const forceAll = opts.opType === 'UPSERT_ALL';
  const forceVec = opts.opType === 'VECTORIZE_ONLY';

  // SSVC is deliberately NOT folded into text_hash or state_hash (both have
  // fixed, documented purposes — see hash.ts and docs/spec/03-system-
  // blueprints.md) — it gets its own change-detection guard, the same shape
  // as applyKevPatch's own comparison below. Compared field-by-field against
  // only the enum values, NEVER record.ssvc's decidedAt timestamp: CISA can
  // re-stamp the identical decision with a new timestamp, and that alone
  // must not count as a change (every re-ingest would otherwise needlessly
  // rewrite cve_state). An incoming null/undefined field means "this
  // ingest pass has no opinion," not "change it to null" — only a concrete
  // incoming value that differs from what's stored counts.
  const incomingSsvc = record.ssvc ?? null;
  const ssvcChanged =
    (incomingSsvc?.exploitation != null &&
      incomingSsvc.exploitation !== (cur?.ssvc_exploitation ?? null)) ||
    (incomingSsvc?.automatable != null &&
      incomingSsvc.automatable !== (cur?.ssvc_automatable ?? null)) ||
    (incomingSsvc?.technicalImpact != null &&
      incomingSsvc.technicalImpact !== (cur?.ssvc_technical_impact ?? null));

  if (!textChanged && !stateChanged && !forceAll && !forceVec) {
    if (ssvcChanged) {
      // Text/state unchanged but SSVC is new/different: one additional
      // single-row cve_state upsert, nothing else — no KV delete (the
      // existing cve:{id} cache TTL is short enough already, per this
      // function's own invalidation elsewhere), no Vectorize call, no AI
      // call. Zero extra D1 reads: `cur` above already carries everything
      // needed.
      await applySsvcOnly(record.cveId, incomingSsvc, env);
      emitAnalytics(env, record, 'SSVC', forceAll, t0, kevListed, epssScore, epssPercentile);
      return;
    }
    emitAnalytics(env, record, 'SKIP', forceAll, t0, kevListed, epssScore, epssPercentile);
    return;
  }

  // ── D1 writes ────────────────────────────────────────────────────────────
  if (!forceVec) {
    try {
      await writeD1(
        record,
        textHash,
        stateHash,
        kevListed,
        epssScore,
        epssPercentile,
        Date.now(),
        env,
      );
    } catch (err) {
      await env.RETRY_QUEUE.send({
        attempt: 1,
        source: record.source,
        cveId: record.cveId,
        normalizedRecord: record,
        opType: 'UPSERT_ALL',
        lastError: { code: 'D1_WRITE_FAILED', message: String(err), occurredAt: Date.now() },
      });
      throw err;
    }
  }

  // ── Vectorize ─────────────────────────────────────────────────────────────
  if (textChanged || forceAll) {
    let vec: number[];
    try {
      vec = opts.vector ?? (await embed(env.AI, buildEmbedText(record)));
    } catch (err) {
      await env.RETRY_QUEUE.send({
        attempt: 1,
        source: record.source,
        cveId: record.cveId,
        normalizedRecord: record,
        opType: 'VECTORIZE_ONLY',
        lastError: { code: 'AI_EMBED_FAILED', message: String(err), occurredAt: Date.now() },
      });
      throw err;
    }

    try {
      await env.VECTORIZE.upsert([
        {
          id: record.cveId,
          values: vec,
          metadata: buildVecMeta(record, kevListed, epssPercentile, topVendor),
        },
      ]);
    } catch (err) {
      await env.RETRY_QUEUE.send({
        attempt: 1,
        source: record.source,
        cveId: record.cveId,
        normalizedRecord: record,
        opType: 'VECTORIZE_ONLY',
        vector: vec,
        lastError: {
          code: 'VECTORIZE_UPSERT_FAILED',
          message: String(err),
          occurredAt: Date.now(),
        },
      });
      throw err;
    }
  } else if (stateChanged || forceVec) {
    // Metadata-only update — reuse stored vector to avoid an AI call.
    const [existing] = await env.VECTORIZE.getByIds([record.cveId]);
    if (existing?.values?.length) {
      await env.VECTORIZE.upsert([
        {
          id: record.cveId,
          values: existing.values,
          metadata: buildVecMeta(record, kevListed, epssPercentile, topVendor),
        },
      ]);
    }
    // No existing vector → Vectorize will be backfilled on the next daily run.
  }

  // Only issue the KV delete when a prior record existed. A brand-new CVE
  // (!cur) was never cached under `cve:{id}` to begin with — there is
  // nothing to invalidate, so the delete is pure waste. At realistic
  // new-CVE volume (hundreds/day once NVD ingestion actually lands records
  // — see nvdQueue.ts) this alone could consume a meaningful share of the
  // 1,000/day KV write+delete cap, the same shape as the 2026-10-27
  // incident documented in CLAUDE.md.
  if (cur) {
    ctx.waitUntil(env.CACHE.delete(`cve:${record.cveId}`));
  }

  emitAnalytics(
    env,
    record,
    textChanged ? 'FULL' : 'STATE',
    forceAll,
    t0,
    kevListed,
    epssScore,
    epssPercentile,
  );
}

// ── SSVC-only patch ──────────────────────────────────────────────────────────
// Used only from the "text/state unchanged but SSVC is new/different" branch
// above. `ON CONFLICT ... COALESCE(excluded.x, x)` means an incoming null
// field (already filtered out of `ssvcChanged` above, but still possible on
// the other two fields of the same incomingSsvc) never clears a previously
// stored value — same contract as writeD1's cve_state upsert below.
async function applySsvcOnly(cveId: string, ssvc: SsvcDecision | null, env: Env): Promise<void> {
  await env.DB.prepare(
    `INSERT INTO cve_state
       (cve_id, kev_listed, ssvc_exploitation, ssvc_automatable, ssvc_technical_impact, ssvc_updated_at, state_updated_at)
     VALUES (?, 0, ?, ?, ?, ?, ?)
     ON CONFLICT (cve_id) DO UPDATE SET
       ssvc_exploitation      = COALESCE(excluded.ssvc_exploitation, ssvc_exploitation),
       ssvc_automatable       = COALESCE(excluded.ssvc_automatable, ssvc_automatable),
       ssvc_technical_impact  = COALESCE(excluded.ssvc_technical_impact, ssvc_technical_impact),
       ssvc_updated_at        = COALESCE(excluded.ssvc_updated_at, ssvc_updated_at),
       state_updated_at       = excluded.state_updated_at`,
  )
    .bind(
      cveId,
      ssvc?.exploitation ?? null,
      ssvc?.automatable ?? null,
      ssvc?.technicalImpact ?? null,
      ssvc?.decidedAt ?? null,
      Date.now(),
    )
    .run();
}

// ── KEV patch ──────────────────────────────────────────────────────────────

export async function applyKevPatch(
  patch: KevPatch,
  env: Env,
  ctx: ExecutionContext,
): Promise<void> {
  const t0 = Date.now();

  const cur = await env.DB.prepare(
    `SELECT kev_listed, kev_date_added, kev_due_date, kev_required_action
     FROM cve_state WHERE cve_id = ?`,
  )
    .bind(patch.cveId)
    .first<{
      kev_listed: number;
      kev_date_added: number | null;
      kev_due_date: number | null;
      kev_required_action: string | null;
    }>();

  const unchanged =
    cur?.kev_listed === 1 &&
    cur.kev_date_added === patch.kevDateAdded &&
    cur.kev_due_date === patch.kevDueDate &&
    cur.kev_required_action === patch.kevRequiredAction;

  if (unchanged) {
    return;
  }

  await env.DB.prepare(
    `INSERT INTO cve_state
       (cve_id, kev_listed, kev_date_added, kev_due_date, kev_required_action, state_updated_at)
     VALUES (?, 1, ?, ?, ?, ?)
     ON CONFLICT (cve_id) DO UPDATE SET
       kev_listed          = 1,
       kev_date_added      = excluded.kev_date_added,
       kev_due_date        = excluded.kev_due_date,
       kev_required_action = excluded.kev_required_action,
       state_updated_at    = excluded.state_updated_at`,
  )
    .bind(patch.cveId, patch.kevDateAdded, patch.kevDueDate, patch.kevRequiredAction, Date.now())
    .run();

  // Recompute state_hash and propagate to cve row + Vectorize.
  const row = await env.DB.prepare(
    `SELECT c.severity, c.cvss_base,
            s.epss_score, s.epss_percentile,
            (SELECT vendor FROM cpe WHERE cve_id = c.cve_id LIMIT 1) AS top_vendor
     FROM cve c LEFT JOIN cve_state s USING (cve_id)
     WHERE c.cve_id = ?`,
  )
    .bind(patch.cveId)
    .first<{
      severity: string;
      cvss_base: number | null;
      epss_score: number | null;
      epss_percentile: number | null;
      top_vendor: string | null;
    }>();

  if (row) {
    const newStateHash = await computeStateHash(
      row.severity,
      row.cvss_base,
      true,
      row.epss_score,
      row.top_vendor,
    );
    await env.DB.prepare('UPDATE cve SET state_hash = ? WHERE cve_id = ?')
      .bind(newStateHash, patch.cveId)
      .run();

    const [existing] = await env.VECTORIZE.getByIds([patch.cveId]);
    if (existing?.values?.length) {
      const meta = (existing.metadata ?? {}) as Record<string, string | number | boolean>;
      await env.VECTORIZE.upsert([
        {
          id: patch.cveId,
          values: existing.values,
          metadata: { ...meta, kev_listed: 1 },
        },
      ]);
    }
  }

  ctx.waitUntil(
    Promise.all([env.CACHE.delete(`cve:${patch.cveId}`), env.CACHE.delete('threat:kev:list')]),
  );

  env.ANALYTICS.writeDataPoint({
    blobs: [patch.cveId, 'KEV', 'STATE', 'FRESH', '', '', ''],
    doubles: [Date.now() - t0, 0, 0, 1, 0],
    indexes: ['record_processed'],
  });
}

interface KevStateRow {
  cve_id: string;
  kev_listed: number;
  kev_date_added: number | null;
  kev_due_date: number | null;
  kev_required_action: string | null;
}

interface KevHashRow {
  cve_id: string;
  severity: string;
  cvss_base: number | null;
  epss_score: number | null;
  epss_percentile: number | null;
  top_vendor: string | null;
}

/**
 * Batched version of the KEV patch path. CISA ships a full KEV catalog
 * snapshot (1,000+ entries) on every 6-hourly run, not a delta — the old
 * `applyKevPatch`-per-entry loop (see `pipelines/kev.ts` pre-fix) issued a
 * change-detect SELECT per entry inline inside a single cron invocation, so
 * even a zero-change run spent ~1,000 D1 queries and blew the Free plan's
 * 50-D1-query-per-invocation cap after the first ~50 entries — the same
 * silent-mid-run-kill failure class as EPSS/NVD (see CLAUDE.md's D1-caps
 * bullet).
 *
 * This replaces that with a small, bounded, measurable D1-query count that
 * does not grow with the number of CHANGED entries:
 *
 *   • 1 batched read per 100-entry chunk (`WHERE cve_id IN (...)`) for the
 *     change-detect (D1's 100-bound-param-per-query cap — same chunking as
 *     applyEpssPatchBatch).
 *   • for the entries that actually changed: 1 more batched read per
 *     100-entry chunk to pull the severity/cvss/epss/top_vendor needed to
 *     recompute state_hash; then two `db.batch()` writes (one for the
 *     cve_state upserts, one for the cve.state_hash updates), each counting
 *     as ONE query toward the budget regardless of statement count.
 *   • Vectorize getByIds / upsert are each a single multi-id call for the
 *     whole changed set, not one per entry.
 *
 * For a worst-case message of KEV_MESSAGE_CHUNK_SIZE (see pipelines/kev.ts)
 * entries that ALL changed, the D1-query count is
 * ~ceil(n/100) read + ceil(n/100) read + ceil(changed/500) batch +
 * ceil(changed/500) batch — a few queries, not n of them. Callers
 * (pipelines/kevQueue.ts) send one message per consumer invocation
 * (`max_batch_size = 1` in wrangler.toml) so each gets its own fresh budget.
 *
 * Internally defensive regardless of `patches.length`, exactly like
 * applyEpssPatchBatch: both reads chunk at SELECT_PARAM_CHUNK_SIZE and both
 * writes sub-batch at WRITE_SUB_BATCH_SIZE, so a caller cannot accidentally
 * build an over-cap query.
 *
 * Returns a `{ processed, changed }` count for the consumer's telemetry.
 */
export async function applyKevPatchBatch(
  patches: KevPatch[],
  env: Env,
  ctx: ExecutionContext,
): Promise<{ processed: number; changed: number }> {
  if (patches.length === 0) return { processed: 0, changed: 0 };

  // De-dupe within the message on cveId (CISA's catalog is already unique
  // per cveId, but a defensive guard keeps the IN-list param count honest
  // and avoids writing the same row twice in one db.batch()).
  const byCveId = new Map<string, KevPatch>();
  for (const p of patches) byCveId.set(p.cveId, p);
  const deduped = [...byCveId.values()];

  // ── 1. Change-detect read (chunked at 100 bound params) ──────────────────
  const current = new Map<string, KevStateRow>();
  for (let i = 0; i < deduped.length; i += SELECT_PARAM_CHUNK_SIZE) {
    const chunk = deduped.slice(i, i + SELECT_PARAM_CHUNK_SIZE);
    const placeholders = chunk.map(() => '?').join(',');
    const { results } = await env.DB.prepare(
      `SELECT cve_id, kev_listed, kev_date_added, kev_due_date, kev_required_action
       FROM cve_state WHERE cve_id IN (${placeholders})`,
    )
      .bind(...chunk.map((p) => p.cveId))
      .all<KevStateRow>();
    for (const r of results) current.set(r.cve_id, r);
  }

  const changed = deduped.filter((p) => {
    const cur = current.get(p.cveId);
    // Same comparison as applyKevPatch's `unchanged` guard, inverted.
    return !(
      cur?.kev_listed === 1 &&
      cur.kev_date_added === p.kevDateAdded &&
      cur.kev_due_date === p.kevDueDate &&
      cur.kev_required_action === p.kevRequiredAction
    );
  });

  if (changed.length === 0) return { processed: deduped.length, changed: 0 };

  // ── 2. cve_state upserts (batched) ───────────────────────────────────────
  const now = Date.now();
  for (let i = 0; i < changed.length; i += WRITE_SUB_BATCH_SIZE) {
    const sub = changed.slice(i, i + WRITE_SUB_BATCH_SIZE);
    await env.DB.batch(
      sub.map((p) =>
        env.DB.prepare(
          `INSERT INTO cve_state
             (cve_id, kev_listed, kev_date_added, kev_due_date, kev_required_action, state_updated_at)
           VALUES (?, 1, ?, ?, ?, ?)
           ON CONFLICT (cve_id) DO UPDATE SET
             kev_listed          = 1,
             kev_date_added      = excluded.kev_date_added,
             kev_due_date        = excluded.kev_due_date,
             kev_required_action = excluded.kev_required_action,
             state_updated_at    = excluded.state_updated_at`,
        ).bind(p.cveId, p.kevDateAdded, p.kevDueDate, p.kevRequiredAction, now),
      ),
    );
  }

  // ── 3. Recompute state_hash + propagate (batched read, then batched write)
  // Only for changed entries that have a cve row (a KEV entry can reference a
  // CVE this instance hasn't ingested yet — the cve_state upsert above still
  // records the KEV listing via its FK to cve, but if there is no cve row the
  // join below simply returns nothing for it and we skip the hash update,
  // exactly as the single-patch applyKevPatch does with its `if (row)` guard).
  const hashRows = new Map<string, KevHashRow>();
  for (let i = 0; i < changed.length; i += SELECT_PARAM_CHUNK_SIZE) {
    const chunk = changed.slice(i, i + SELECT_PARAM_CHUNK_SIZE);
    const placeholders = chunk.map(() => '?').join(',');
    const { results } = await env.DB.prepare(
      `SELECT c.cve_id, c.severity, c.cvss_base,
              s.epss_score, s.epss_percentile,
              (SELECT vendor FROM cpe WHERE cpe.cve_id = c.cve_id LIMIT 1) AS top_vendor
       FROM cve c LEFT JOIN cve_state s USING (cve_id)
       WHERE c.cve_id IN (${placeholders})`,
    )
      .bind(...chunk.map((p) => p.cveId))
      .all<KevHashRow>();
    for (const r of results) hashRows.set(r.cve_id, r);
  }

  const hashUpdates: { cveId: string; stateHash: string }[] = [];
  for (const row of hashRows.values()) {
    const newStateHash = await computeStateHash(
      row.severity,
      row.cvss_base,
      true,
      row.epss_score,
      row.top_vendor,
    );
    hashUpdates.push({ cveId: row.cve_id, stateHash: newStateHash });
  }

  for (let i = 0; i < hashUpdates.length; i += WRITE_SUB_BATCH_SIZE) {
    const sub = hashUpdates.slice(i, i + WRITE_SUB_BATCH_SIZE);
    await env.DB.batch(
      sub.map((u) =>
        env.DB.prepare('UPDATE cve SET state_hash = ? WHERE cve_id = ?').bind(u.stateHash, u.cveId),
      ),
    );
  }

  // ── 4. Vectorize metadata propagation (single multi-id read + write) ─────
  // getByIds/upsert take the whole changed set at once, so this is O(1) calls
  // regardless of how many entries changed — not one Vectorize round trip per
  // entry (which the per-entry applyKevPatch did). Only entries with an
  // existing stored vector are re-upserted (metadata-only, reusing the stored
  // values — no AI call), matching applyKevPatch's behavior.
  const idsWithCve = hashUpdates.map((u) => u.cveId);
  if (idsWithCve.length > 0) {
    const existing = await env.VECTORIZE.getByIds(idsWithCve);
    const toUpsert = existing
      .filter((e) => e?.values?.length)
      .map((e) => {
        const meta = (e.metadata ?? {}) as Record<string, string | number | boolean>;
        return { id: e.id, values: e.values as number[], metadata: { ...meta, kev_listed: 1 } };
      });
    if (toUpsert.length > 0) {
      await env.VECTORIZE.upsert(toUpsert);
    }
  }

  // ── 5. Cache invalidation ────────────────────────────────────────────────
  // One delete per changed cve:{id} key, plus the single shared KEV list key.
  // All changed entries fit in one batch-run of KV deletes via waitUntil, the
  // same pattern applyEpssPatchBatch uses. KEV runs 4x/day over a ~1,000-entry
  // catalog, but only genuinely-changed entries get a delete (the vast
  // majority of runs change nothing), so this stays well within the 1,000/day
  // KV write+delete cap — the whole reason the change-detect gate exists.
  ctx.waitUntil(
    Promise.all([
      ...changed.map((p) => env.CACHE.delete(`cve:${p.cveId}`)),
      env.CACHE.delete('threat:kev:list'),
    ]),
  );

  return { processed: deduped.length, changed: changed.length };
}

// ── EPSS patch ─────────────────────────────────────────────────────────────

interface EpssStateRow {
  cve_id: string;
  epss_score: number | null;
  epss_percentile: number | null;
}

// D1's bound-parameter cap is 100 per query, same on every plan
// (https://developers.cloudflare.com/d1/platform/limits/). The
// `WHERE cve_id IN (...)` read below binds one placeholder per patch, so it
// must never be built from more than this many patches at once.
const SELECT_PARAM_CHUNK_SIZE = 100;
// `db.batch()` counts as ONE query toward the 50-queries-per-invocation cap
// regardless of how many statements it holds, so this sub-batching is purely
// for memory/predictability, not to stay under that cap.
const WRITE_SUB_BATCH_SIZE = 500;

/**
 * Batched version of the EPSS patch path. FIRST.org ships a full daily
 * snapshot (250k+ rows), not a delta — a SELECT-per-row change check (the
 * previous approach) burns one D1 read per row, ~250k/day on its own. This
 * does one batch read per chunk (`WHERE cve_id IN (...)`) instead, and only
 * writes/invalidates cache for rows that actually changed.
 *
 * Internally defensive regardless of `patches.length`: the SELECT is chunked
 * to at most `SELECT_PARAM_CHUNK_SIZE` (100) bound params per query — D1's
 * hard per-query cap — so callers do not need to pre-chunk correctly
 * themselves. Callers are still expected to keep each call to a size that
 * fits comfortably within one invocation's 50-D1-query budget (see
 * `pipelines/epssQueue.ts`, which calls this once per queue message).
 */
export async function applyEpssPatchBatch(
  patches: EpssPatch[],
  env: Env,
  ctx: ExecutionContext,
): Promise<void> {
  if (patches.length === 0) return;

  const current = new Map<string, EpssStateRow>();
  for (let i = 0; i < patches.length; i += SELECT_PARAM_CHUNK_SIZE) {
    const chunk = patches.slice(i, i + SELECT_PARAM_CHUNK_SIZE);
    const placeholders = chunk.map(() => '?').join(',');
    const { results } = await env.DB.prepare(
      `SELECT cve_id, epss_score, epss_percentile FROM cve_state WHERE cve_id IN (${placeholders})`,
    )
      .bind(...chunk.map((p) => p.cveId))
      .all<EpssStateRow>();
    for (const r of results) current.set(r.cve_id, r);
  }

  const changed = patches.filter((p) => {
    const cur = current.get(p.cveId);
    return cur?.epss_score !== p.epssScore || cur?.epss_percentile !== p.epssPercentile;
  });

  if (changed.length === 0) return;

  const now = Date.now();
  for (let i = 0; i < changed.length; i += WRITE_SUB_BATCH_SIZE) {
    const sub = changed.slice(i, i + WRITE_SUB_BATCH_SIZE);
    await env.DB.batch(
      sub.map((p) =>
        env.DB.prepare(
          `INSERT INTO cve_state
             (cve_id, kev_listed, epss_score, epss_percentile, epss_updated_at, state_updated_at)
           VALUES (?, 0, ?, ?, ?, ?)
           ON CONFLICT (cve_id) DO UPDATE SET
             epss_score       = excluded.epss_score,
             epss_percentile  = excluded.epss_percentile,
             epss_updated_at  = excluded.epss_updated_at,
             state_updated_at = excluded.state_updated_at`,
        ).bind(p.cveId, p.epssScore, p.epssPercentile, p.epssUpdatedAt, now),
      ),
    );
  }

  ctx.waitUntil(Promise.all(changed.map((p) => env.CACHE.delete(`cve:${p.cveId}`))));
}

// ── Helpers ────────────────────────────────────────────────────────────────

async function writeD1(
  record: NormalizedCveRecord,
  textHash: string,
  stateHash: string,
  kevListed: boolean,
  epssScore: number | null,
  epssPercentile: number | null,
  now: number,
  env: Env,
): Promise<void> {
  const db = env.DB;

  await db.batch([
    // CVE row
    db
      .prepare(
        `INSERT INTO cve
         (cve_id, published_at, last_modified_at, description,
          cvss_version, cvss_vector, cvss_base, cvss_exploitability, cvss_impact,
          severity, source, text_hash, state_hash, ingested_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
       ON CONFLICT (cve_id) DO UPDATE SET
         last_modified_at    = excluded.last_modified_at,
         description         = excluded.description,
         cvss_version        = excluded.cvss_version,
         cvss_vector         = excluded.cvss_vector,
         cvss_base           = excluded.cvss_base,
         cvss_exploitability = excluded.cvss_exploitability,
         cvss_impact         = excluded.cvss_impact,
         severity            = excluded.severity,
         source              = excluded.source,
         text_hash           = excluded.text_hash,
         state_hash          = excluded.state_hash,
         ingested_at         = excluded.ingested_at`,
      )
      .bind(
        record.cveId,
        record.publishedAt,
        record.lastModifiedAt,
        record.description,
        record.cvss?.version ?? null,
        record.cvss?.vector ?? null,
        record.cvss?.base ?? null,
        record.cvss?.exploitability ?? null,
        record.cvss?.impact ?? null,
        record.severity,
        record.source,
        textHash,
        stateHash,
        now,
      ),
    // cve_state — preserve existing kev fields. SSVC columns use the same
    // COALESCE(excluded.x, x) contract as epss_score/epss_percentile below:
    // an incoming null (record.ssvc absent, or this ingest pass has no
    // opinion on one of the three fields) means "no new info," never
    // "clear the stored value" — same reasoning applySsvcOnly above
    // documents. Zero extra statements: this is the SAME upsert
    // text/state-changed writes already made, just two more columns on it.
    db
      .prepare(
        `INSERT INTO cve_state
         (cve_id, kev_listed, epss_score, epss_percentile,
          ssvc_exploitation, ssvc_automatable, ssvc_technical_impact, ssvc_updated_at,
          state_updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (cve_id) DO UPDATE SET
         epss_score             = COALESCE(excluded.epss_score, epss_score),
         epss_percentile        = COALESCE(excluded.epss_percentile, epss_percentile),
         ssvc_exploitation      = COALESCE(excluded.ssvc_exploitation, ssvc_exploitation),
         ssvc_automatable       = COALESCE(excluded.ssvc_automatable, ssvc_automatable),
         ssvc_technical_impact  = COALESCE(excluded.ssvc_technical_impact, ssvc_technical_impact),
         ssvc_updated_at        = COALESCE(excluded.ssvc_updated_at, ssvc_updated_at),
         state_updated_at       = excluded.state_updated_at`,
      )
      .bind(
        record.cveId,
        kevListed ? 1 : 0,
        epssScore,
        epssPercentile,
        record.ssvc?.exploitation ?? null,
        record.ssvc?.automatable ?? null,
        record.ssvc?.technicalImpact ?? null,
        record.ssvc?.decidedAt ?? null,
        now,
      ),
    // provenance
    db
      .prepare(
        `INSERT INTO cve_source_provenance (cve_id, source, last_seen_at)
       VALUES (?, ?, ?)
       ON CONFLICT (cve_id, source) DO UPDATE SET last_seen_at = excluded.last_seen_at`,
      )
      .bind(record.cveId, record.source, now),
  ]);

  // CWEs
  if (record.cwes.length > 0) {
    const cweStmts: D1PreparedStatement[] = [
      db.prepare('DELETE FROM cve_cwe WHERE cve_id = ?').bind(record.cveId),
    ];
    for (const cweId of record.cwes) {
      cweStmts.push(
        db
          .prepare('INSERT OR IGNORE INTO cwe (cwe_id, name, category) VALUES (?, NULL, NULL)')
          .bind(cweId),
        db
          .prepare('INSERT OR IGNORE INTO cve_cwe (cve_id, cwe_id) VALUES (?, ?)')
          .bind(record.cveId, cweId),
      );
    }
    await db.batch(cweStmts);
  }

  // CPEs (cap at 500 per CVE to stay within D1 statement limits)
  const cpes = record.cpes.slice(0, 500);
  if (cpes.length > 0) {
    const cpeStmts: D1PreparedStatement[] = [
      db.prepare('DELETE FROM cpe WHERE cve_id = ?').bind(record.cveId),
    ];
    for (const cpe of cpes) {
      cpeStmts.push(
        db
          .prepare(
            `INSERT INTO cpe
             (cve_id, cpe_uri, part, vendor, product, version,
              version_start_including, version_start_excluding,
              version_end_including,   version_end_excluding, vulnerable)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
          )
          .bind(
            record.cveId,
            cpe.cpeUri,
            cpe.part ?? null,
            cpe.vendor,
            cpe.product,
            cpe.version ?? null,
            cpe.versionStartIncluding ?? null,
            cpe.versionStartExcluding ?? null,
            cpe.versionEndIncluding ?? null,
            cpe.versionEndExcluding ?? null,
            cpe.vulnerable ? 1 : 0,
          ),
      );
    }
    await db.batch(cpeStmts);
  }

  // References (cap at 200)
  const refs = record.references.slice(0, 200);
  if (refs.length > 0) {
    const refStmts: D1PreparedStatement[] = [
      db.prepare('DELETE FROM cve_reference WHERE cve_id = ?').bind(record.cveId),
    ];
    for (const ref of refs) {
      refStmts.push(
        db
          .prepare('INSERT OR IGNORE INTO cve_reference (cve_id, url, tags) VALUES (?, ?, ?)')
          .bind(record.cveId, ref.url, ref.tags.join(',') || null),
      );
    }
    await db.batch(refStmts);
  }
}

function buildVecMeta(
  record: NormalizedCveRecord,
  kevListed: boolean,
  epssPercentile: number | null,
  topVendor: string | null,
): Record<string, string | number | boolean> {
  return {
    severity: record.severity,
    cvss_base: record.cvss?.base ?? 0,
    published_ms: record.publishedAt,
    kev_listed: kevListed ? 1 : 0,
    epss_percentile: epssPercentile ?? 0,
    top_vendor: topVendor ?? '',
  };
}

function emitAnalytics(
  env: Env,
  record: NormalizedCveRecord,
  op: string,
  isRetry: boolean,
  t0: number,
  kevListed: boolean,
  epssScore: number | null,
  epssPercentile: number | null,
): void {
  env.ANALYTICS.writeDataPoint({
    blobs: [record.cveId, record.source, op, isRetry ? 'RETRY' : 'FRESH', '', '', ''],
    doubles: [
      Date.now() - t0,
      record.cvss?.base ?? 0,
      record.publishedAt,
      kevListed ? 1 : 0,
      epssPercentile ?? 0,
    ],
    indexes: ['record_processed'],
  });
}
