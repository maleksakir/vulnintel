import type { MitreCweQueueMessage } from '@threat-lens/contracts';
import { CVE_ID_SHAPE, fetchMitreCweSupplement, type MitreCweResult } from '../adapters/mitre';
import type { Env } from '../types';

/** Bounded fetch concurrency — stays well under the ~6-simultaneous-
 *  connection-per-invocation ceiling noted in daily.ts's EPSS section and
 *  mirrored by pipelines/osv.ts's FETCH_CONCURRENCY. */
const MITRE_FETCH_CONCURRENCY = 6;

function isPlausibleMitreCweQueueMessage(m: unknown): m is MitreCweQueueMessage {
  if (typeof m !== 'object' || m === null) return false;
  const msg = m as Record<string, unknown>;
  return Array.isArray(msg.cveIds) && msg.cveIds.every((id) => typeof id === 'string');
}

/**
 * MITRE CWE gap-fill queue consumer (queue: `mitre-ingest` / `mitre-ingest-
 * staging`).
 *
 * `pipelines/daily.ts`'s NVD section only collects + chunks + enqueues CVE
 * IDs (records it saw with zero CWEs) — this is where the actual MITRE
 * lookup + D1 write happens, one message (≤20 CVE IDs) per invocation. Each
 * invocation gets its own fresh 50-D1-query budget, same reasoning as
 * nvdQueue.ts/epssQueue.ts/osv.ts's consumers.
 *
 * Worst case per invocation: 20 fetches (bounded concurrency
 * MITRE_FETCH_CONCURRENCY) + 1 D1 read (the qualifying-CVE recheck below) +
 * 1 D1 write (`db.batch()`, counts as ONE query) = ~22 operations total —
 * comfortably under the 50-D1-query cap (most of which aren't even D1
 * calls) and nowhere near Workers Free's external-subrequest ceiling.
 *
 * This path ONLY ever writes cwe/cve_cwe/cve_source_provenance rows — it
 * deliberately never touches text_hash, state_hash, Vectorize, Workers AI,
 * or the `cve:{id}` KV cache key (supplemental metadata only, invisible to
 * search ranking and the cache — see adapters/mitre.ts's header comment for
 * why). If NVD itself later supplies CWEs for the same CVE through its own
 * normal path, processRecord.ts's writeD1 DELETE-then-reinserts cve_cwe,
 * naturally superseding whatever this path wrote — correct precedence
 * (NVD's structured data wins over a free-text-regex guess), needing no
 * special handling here.
 */
export async function runMitreCweConsumer(
  message: MitreCweQueueMessage,
  env: Env,
  // Accepted for signature parity with the other queue consumers
  // (nvdQueue.ts/epssQueue.ts) and index.ts's uniform dispatch call —
  // unused here: this path has no KV/cache invalidation to defer (see the
  // header comment above for why).
  _ctx: ExecutionContext,
): Promise<void> {
  const t0 = Date.now();

  // Defensive runtime check on the dequeued body, same reasoning as
  // nvdQueue.ts/epssQueue.ts's isValid* checks: a malformed/corrupted
  // redelivery can never succeed no matter how many times it's retried.
  // Ack (drop) it immediately instead of throwing.
  if (!isPlausibleMitreCweQueueMessage(message)) {
    env.ANALYTICS.writeDataPoint({
      blobs: ['MITRE_QUEUE', 'MALFORMED_MESSAGE', '', '', '', '', ''],
      doubles: [Date.now() - t0, 0, 0, 0, 0],
      indexes: ['mitre_consumer_processed'],
    });
    return;
  }

  // Validate every CVE ID against CVE_ID_SHAPE BEFORE any of them is ever
  // used to build a URL or a D1 query — mirrors adapters/osv.ts's
  // OSV_ID_ALLOW check. An invalid id here can never succeed no matter how
  // many times it's retried, so it's dropped (counted, not silently lost),
  // not treated as a reason to retry the whole message.
  const validIds = message.cveIds.filter((id) => CVE_ID_SHAPE.test(id));
  const invalidCount = message.cveIds.length - validIds.length;

  if (validIds.length === 0) {
    env.ANALYTICS.writeDataPoint({
      blobs: ['MITRE_QUEUE', 'NO_VALID_IDS', '', '', '', '', ''],
      doubles: [Date.now() - t0, 0, 0, invalidCount, 0],
      indexes: ['mitre_consumer_processed'],
    });
    return;
  }

  // One D1 read up front: of the valid ids in this message, keep only
  // those where a `cve` row currently exists AND it currently has zero
  // cve_cwe rows. Re-checked at CONSUME time, not just at enqueue time —
  // time may have passed since daily.ts collected these ids, and this is
  // also the correctness guard against ever overriding NVD's own CWEs if
  // NVD later got them another way. A CVE that no longer qualifies (row
  // missing, e.g. aged out, or already has CWEs now) is simply skipped,
  // not an error. The LEFT JOIN + HAVING COUNT(...)=0 shape means a CVE ID
  // not present in `cve` at all is automatically excluded from `results`
  // too (no row to join against), satisfying the "row currently exists"
  // half of the guard in the same query.
  const placeholders = validIds.map(() => '?').join(',');
  const { results: qualifyingRows } = await env.DB.prepare(
    `SELECT c.cve_id
     FROM cve c
     LEFT JOIN cve_cwe cc ON cc.cve_id = c.cve_id
     WHERE c.cve_id IN (${placeholders})
     GROUP BY c.cve_id
     HAVING COUNT(cc.cwe_id) = 0`,
  )
    .bind(...validIds)
    .all<{ cve_id: string }>();

  const qualifying = qualifyingRows.map((r) => r.cve_id);

  if (qualifying.length === 0) {
    env.ANALYTICS.writeDataPoint({
      blobs: ['MITRE_QUEUE', 'OK', '', '', '', '', ''],
      doubles: [Date.now() - t0, 0, 0, invalidCount, 0],
      indexes: ['mitre_consumer_processed'],
    });
    return;
  }

  // Bounded-concurrency fetch against MITRE's public single-record
  // endpoint. A retryable fetch failure (429/5xx — see
  // adapters/mitre.ts's fetchMitreCweSupplement) is deliberately NOT
  // caught here: it propagates out of this function so index.ts's queue()
  // handler calls msg.retry() for the WHOLE message (same pattern
  // epssQueue.ts/osv.ts's fetch-batch consumer uses for a hard D1/fetch
  // failure) — the queue's own max_retries=3/DLQ mechanism handles it from
  // there. Already-qualifying ids re-fetched on a retry is wasted work but
  // harmless: step 2's qualifying re-check above runs fresh every attempt.
  const fetchResults: MitreCweResult[] = [];
  for (let i = 0; i < qualifying.length; i += MITRE_FETCH_CONCURRENCY) {
    const slice = qualifying.slice(i, i + MITRE_FETCH_CONCURRENCY);
    const settled = await Promise.all(slice.map((id) => fetchMitreCweSupplement(id)));
    fetchResults.push(...settled);
  }

  const gained = fetchResults.filter((r) => r.outcome === 'OK' && r.cwes.length > 0);

  if (gained.length === 0) {
    env.ANALYTICS.writeDataPoint({
      blobs: ['MITRE_QUEUE', 'OK', '', '', '', '', ''],
      doubles: [Date.now() - t0, qualifying.length, 0, invalidCount, 0],
      indexes: ['mitre_consumer_processed'],
    });
    return;
  }

  // One db.batch() call, only for CVEs that actually gained ≥1 new CWE.
  // Same placeholder-row convention processRecord.ts's writeD1 already uses
  // for CWEs from NVD (INSERT OR IGNORE INTO cwe ... NULL, NULL), and the
  // same provenance-upsert convention it uses for cve_source_provenance.
  const db = env.DB;
  const now = Date.now();

  const allNewCweIds = new Set<string>();
  for (const r of gained) {
    for (const cwe of r.cwes) allNewCweIds.add(cwe);
  }

  const stmts: D1PreparedStatement[] = [];
  for (const cweId of allNewCweIds) {
    stmts.push(
      db
        .prepare('INSERT OR IGNORE INTO cwe (cwe_id, name, category) VALUES (?, NULL, NULL)')
        .bind(cweId),
    );
  }
  for (const r of gained) {
    for (const cweId of r.cwes) {
      // EXISTS guard: a CVE that aged out between the qualifying read above
      // and this write can't cause a foreign-key failure that kills the
      // whole batch. OR IGNORE: the same CVE id landing in two overlapping
      // 48h-delta messages (or a queue redelivery) shouldn't fail the whole
      // batch on a cve_cwe primary-key conflict either — same convention as
      // processRecord.ts's own cve_cwe writes.
      stmts.push(
        db
          .prepare(
            'INSERT OR IGNORE INTO cve_cwe (cve_id, cwe_id) SELECT ?, ? WHERE EXISTS (SELECT 1 FROM cve WHERE cve_id = ?)',
          )
          .bind(r.cveId, cweId, r.cveId),
      );
    }
    stmts.push(
      db
        .prepare(
          `INSERT INTO cve_source_provenance (cve_id, source, last_seen_at)
           VALUES (?, 'MITRE', ?)
           ON CONFLICT (cve_id, source) DO UPDATE SET last_seen_at = excluded.last_seen_at`,
        )
        .bind(r.cveId, now),
    );
  }

  await db.batch(stmts);

  env.ANALYTICS.writeDataPoint({
    blobs: ['MITRE_QUEUE', 'OK', '', '', '', '', ''],
    doubles: [Date.now() - t0, qualifying.length, gained.length, invalidCount, 0],
    indexes: ['mitre_consumer_processed'],
  });
}
