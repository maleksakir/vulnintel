import type { NormalizedCveRecord, EpssPatch, KevPatch } from '@threat-lens/contracts';
import type { Env } from '../../types';
import { computeTextHash, computeStateHash } from './hash';
import { embed, buildEmbedText } from './embed';

interface CurrentRow {
  text_hash: string;
  state_hash: string;
  kev_listed: number;
  epss_score: number | null;
  epss_percentile: number | null;
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
  const topVendors = [...new Set(record.cpes.map(c => c.vendor))].sort().slice(0, 5);
  const topVendor = topVendors[0] ?? null;

  const textHash = await computeTextHash(record);

  const cur = await env.DB.prepare(
    `SELECT c.text_hash, c.state_hash,
            COALESCE(s.kev_listed, 0)    AS kev_listed,
            s.epss_score,
            s.epss_percentile
     FROM cve c
     LEFT JOIN cve_state s USING (cve_id)
     WHERE c.cve_id = ?`,
  ).bind(record.cveId).first<CurrentRow>();

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

  if (!textChanged && !stateChanged && !forceAll && !forceVec) {
    emitAnalytics(env, record, 'SKIP', forceAll, t0, kevListed, epssScore, epssPercentile);
    return;
  }

  // ── D1 writes ────────────────────────────────────────────────────────────
  if (!forceVec) {
    try {
      await writeD1(record, textHash, stateHash, kevListed, epssScore, epssPercentile, Date.now(), env);
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
      await env.VECTORIZE.upsert([{
        id: record.cveId,
        values: vec,
        metadata: buildVecMeta(record, kevListed, epssPercentile, topVendor),
      }]);
    } catch (err) {
      await env.RETRY_QUEUE.send({
        attempt: 1,
        source: record.source,
        cveId: record.cveId,
        normalizedRecord: record,
        opType: 'VECTORIZE_ONLY',
        vector: vec,
        lastError: { code: 'VECTORIZE_UPSERT_FAILED', message: String(err), occurredAt: Date.now() },
      });
      throw err;
    }
  } else if (stateChanged || forceVec) {
    // Metadata-only update — reuse stored vector to avoid an AI call.
    const [existing] = await env.VECTORIZE.getByIds([record.cveId]);
    if (existing?.values?.length) {
      await env.VECTORIZE.upsert([{
        id: record.cveId,
        values: existing.values,
        metadata: buildVecMeta(record, kevListed, epssPercentile, topVendor),
      }]);
    }
    // No existing vector → Vectorize will be backfilled on the next daily run.
  }

  ctx.waitUntil(env.CACHE.delete(`cve:${record.cveId}`));

  emitAnalytics(
    env, record,
    textChanged ? 'FULL' : 'STATE',
    forceAll,
    t0, kevListed, epssScore, epssPercentile,
  );
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
  ).bind(patch.cveId).first<{
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
  ).bind(patch.cveId, patch.kevDateAdded, patch.kevDueDate, patch.kevRequiredAction, Date.now()).run();

  // Recompute state_hash and propagate to cve row + Vectorize.
  const row = await env.DB.prepare(
    `SELECT c.severity, c.cvss_base,
            s.epss_score, s.epss_percentile,
            (SELECT vendor FROM cpe WHERE cve_id = c.cve_id LIMIT 1) AS top_vendor
     FROM cve c LEFT JOIN cve_state s USING (cve_id)
     WHERE c.cve_id = ?`,
  ).bind(patch.cveId).first<{
    severity: string;
    cvss_base: number | null;
    epss_score: number | null;
    epss_percentile: number | null;
    top_vendor: string | null;
  }>();

  if (row) {
    const newStateHash = await computeStateHash(
      row.severity, row.cvss_base, true, row.epss_score, row.top_vendor,
    );
    await env.DB.prepare('UPDATE cve SET state_hash = ? WHERE cve_id = ?')
      .bind(newStateHash, patch.cveId).run();

    const [existing] = await env.VECTORIZE.getByIds([patch.cveId]);
    if (existing?.values?.length) {
      const meta = (existing.metadata ?? {}) as Record<string, string | number | boolean>;
      await env.VECTORIZE.upsert([{
        id: patch.cveId,
        values: existing.values,
        metadata: { ...meta, kev_listed: 1 },
      }]);
    }
  }

  ctx.waitUntil(
    Promise.all([
      env.CACHE.delete(`cve:${patch.cveId}`),
      env.CACHE.delete('threat:kev:list'),
    ]),
  );

  env.ANALYTICS.writeDataPoint({
    blobs: [patch.cveId, 'KEV', 'STATE', 'FRESH', '', '', ''],
    doubles: [Date.now() - t0, 0, 0, 1, 0],
    indexes: ['record_processed'],
  });
}

// ── EPSS patch ─────────────────────────────────────────────────────────────

export async function applyEpssPatch(
  patch: EpssPatch,
  env: Env,
  ctx: ExecutionContext,
): Promise<void> {
  const cur = await env.DB.prepare(
    `SELECT epss_score, epss_percentile FROM cve_state WHERE cve_id = ?`,
  ).bind(patch.cveId).first<{ epss_score: number | null; epss_percentile: number | null }>();

  if (cur?.epss_score === patch.epssScore && cur.epss_percentile === patch.epssPercentile) {
    return;
  }

  await env.DB.prepare(
    `INSERT INTO cve_state
       (cve_id, kev_listed, epss_score, epss_percentile, epss_updated_at, state_updated_at)
     VALUES (?, 0, ?, ?, ?, ?)
     ON CONFLICT (cve_id) DO UPDATE SET
       epss_score       = excluded.epss_score,
       epss_percentile  = excluded.epss_percentile,
       epss_updated_at  = excluded.epss_updated_at,
       state_updated_at = excluded.state_updated_at`,
  ).bind(
    patch.cveId, patch.epssScore, patch.epssPercentile, patch.epssUpdatedAt, Date.now(),
  ).run();

  ctx.waitUntil(env.CACHE.delete(`cve:${patch.cveId}`));
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
    db.prepare(
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
    ).bind(
      record.cveId, record.publishedAt, record.lastModifiedAt, record.description,
      record.cvss?.version ?? null,
      record.cvss?.vector ?? null,
      record.cvss?.base ?? null,
      record.cvss?.exploitability ?? null,
      record.cvss?.impact ?? null,
      record.severity, record.source, textHash, stateHash, now,
    ),
    // cve_state — preserve existing kev fields
    db.prepare(
      `INSERT INTO cve_state
         (cve_id, kev_listed, epss_score, epss_percentile, state_updated_at)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT (cve_id) DO UPDATE SET
         epss_score       = COALESCE(excluded.epss_score, epss_score),
         epss_percentile  = COALESCE(excluded.epss_percentile, epss_percentile),
         state_updated_at = excluded.state_updated_at`,
    ).bind(record.cveId, kevListed ? 1 : 0, epssScore, epssPercentile, now),
    // provenance
    db.prepare(
      `INSERT INTO cve_source_provenance (cve_id, source, last_seen_at)
       VALUES (?, ?, ?)
       ON CONFLICT (cve_id, source) DO UPDATE SET last_seen_at = excluded.last_seen_at`,
    ).bind(record.cveId, record.source, now),
  ]);

  // CWEs
  if (record.cwes.length > 0) {
    const cweStmts: D1PreparedStatement[] = [
      db.prepare('DELETE FROM cve_cwe WHERE cve_id = ?').bind(record.cveId),
    ];
    for (const cweId of record.cwes) {
      cweStmts.push(
        db.prepare('INSERT OR IGNORE INTO cwe (cwe_id, name, category) VALUES (?, NULL, NULL)').bind(cweId),
        db.prepare('INSERT OR IGNORE INTO cve_cwe (cve_id, cwe_id) VALUES (?, ?)').bind(record.cveId, cweId),
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
        db.prepare(
          `INSERT INTO cpe
             (cve_id, cpe_uri, part, vendor, product, version,
              version_start_including, version_start_excluding,
              version_end_including,   version_end_excluding, vulnerable)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
        ).bind(
          record.cveId, cpe.cpeUri, cpe.part ?? null, cpe.vendor, cpe.product,
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
        db.prepare('INSERT OR IGNORE INTO cve_reference (cve_id, url, tags) VALUES (?, ?, ?)')
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
