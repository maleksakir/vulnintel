import type { OsvFetchItem, OsvPatch } from '@threat-lens/contracts';
import type { Env } from '../../types';
import { computeOsvContentHash } from './hash';

/**
 * Outcome of fetching + normalizing one OsvFetchItem (pipelines/osv.ts's
 * runOsvFetchBatch). Kept separate from OsvPatch itself so a 404/malformed/
 * network-failure outcome can be represented without a sentinel value on
 * the patch shape.
 */
export type OsvFetchResult =
  | { item: OsvFetchItem; outcome: 'OK'; patch: OsvPatch }
  /** OSV API returned 404 — withdrawn/removed, a valid outcome, not an error. */
  | { item: OsvFetchItem; outcome: 'NOT_FOUND' }
  /** Fetched fine, but normalizeOsvRecord rejected the shape (or the item's
   *  own osv_id failed validation before any fetch happened). */
  | {
      item: OsvFetchItem;
      outcome: 'MALFORMED';
      rawPayloadForQuarantine: string;
      errorMessage: string;
    }
  /** Network/HTTP error other than 404 — transient; left untouched so the
   *  next discovery pass's cursor overlap re-surfaces it. */
  | { item: OsvFetchItem; outcome: 'FETCH_FAILED'; errorMessage: string };

export interface OsvPatchApplyResult {
  written: number;
  skipped: number;
  unlinked: number;
  quarantined: number;
}

interface OsvStateRow {
  osv_id: string;
  modified_at: string;
  status: string;
  cve_ids: string;
  first_seen_at: number;
  content_hash: string | null;
}

// D1's bound-parameter cap is 100 per query on every plan. Both batch reads
// below are chunked at this regardless of how many results this invocation
// is handed (pipelines/osv.ts keeps that number small — ~20-25 — but this
// stays internally defensive the same way applyEpssPatchBatch does).
const SELECT_PARAM_CHUNK_SIZE = 100;

/**
 * Applies a batch of fetch results to D1. Exactly ONE db.batch() call for
 * all the writes this invocation produces (unchanged-record checked_at
 * bumps, changed-record cve_osv_affected replacement + osv_record_state
 * upsert, and cve_quarantine inserts for malformed records) — db.batch()
 * counts as a single query toward the 50-queries-per-invocation Free-plan
 * cap regardless of how many statements it holds (see
 * processRecord.ts/applyEpssPatchBatch's comment on the same point), and at
 * the batch sizes this path runs at (~20-25 items/invocation) there's no
 * reason to sub-batch for memory the way the 250k-row EPSS path does.
 *
 * Never touches cve/cpe/cve_reference/cve_cwe/text_hash/state_hash/
 * Vectorize — this is a genuinely separate write path from
 * processRecord.ts's (see CLAUDE.md: those tables are owned by NVD/MITRE
 * and overwritten on every write, which would churn/wipe OSV data placed
 * there).
 */
export async function applyOsvPatchBatch(
  results: OsvFetchResult[],
  env: Env,
  ctx: ExecutionContext,
): Promise<OsvPatchApplyResult> {
  const now = Date.now();
  let written = 0;
  let skipped = 0;
  let unlinked = 0;
  let quarantined = 0;

  if (results.length === 0) return { written, skipped, unlinked, quarantined };

  const db = env.DB;

  // ── 1. Batch-read existing osv_record_state for everything in this batch ──
  const osvIds = results.map((r) => r.item.osvId);
  const existingState = new Map<string, OsvStateRow>();
  for (let i = 0; i < osvIds.length; i += SELECT_PARAM_CHUNK_SIZE) {
    const chunk = osvIds.slice(i, i + SELECT_PARAM_CHUNK_SIZE);
    const placeholders = chunk.map(() => '?').join(',');
    const { results: rows } = await db
      .prepare(
        `SELECT osv_id, modified_at, status, cve_ids, first_seen_at, content_hash
         FROM osv_record_state WHERE osv_id IN (${placeholders})`,
      )
      .bind(...chunk)
      .all<OsvStateRow>();
    for (const row of rows) existingState.set(row.osv_id, row);
  }

  // ── 2. Content hashes for every successfully-normalized patch, and the
  //        union of every CVE id any of them alias to ──
  const withPatch = results.filter(
    (r): r is Extract<OsvFetchResult, { outcome: 'OK' }> => r.outcome === 'OK',
  );
  const contentHashes = new Map<string, string>();
  for (const r of withPatch) {
    contentHashes.set(r.item.osvId, await computeOsvContentHash(r.patch));
  }

  const allCveIds = new Set<string>();
  for (const r of withPatch) for (const id of r.patch.cveIds) allCveIds.add(id);

  const existingCveIds = new Set<string>();
  const cveIdList = [...allCveIds];
  for (let i = 0; i < cveIdList.length; i += SELECT_PARAM_CHUNK_SIZE) {
    const chunk = cveIdList.slice(i, i + SELECT_PARAM_CHUNK_SIZE);
    const placeholders = chunk.map(() => '?').join(',');
    const { results: rows } = await db
      .prepare(`SELECT cve_id FROM cve WHERE cve_id IN (${placeholders})`)
      .bind(...chunk)
      .all<{ cve_id: string }>();
    for (const row of rows) existingCveIds.add(row.cve_id);
  }

  // ── 3. Decide per-item status, build every statement up front ──
  const stmts: D1PreparedStatement[] = [];
  const invalidatedCveIds = new Set<string>();

  for (const r of results) {
    const item = r.item;
    const prior = existingState.get(item.osvId);

    if (r.outcome === 'FETCH_FAILED') {
      // Transient — leave state untouched. runOsvDiscovery's cursor overlap
      // window re-surfaces this osv_id on a later run.
      skipped++;
      continue;
    }

    if (r.outcome === 'MALFORMED') {
      stmts.push(
        db
          .prepare(
            `INSERT INTO cve_quarantine (source, cve_id, payload, error_code, error_message, quarantined_at)
             VALUES (?, NULL, ?, ?, ?, ?)`,
          )
          .bind(
            'OSV',
            r.rawPayloadForQuarantine,
            'OSV_PARSE_FAILED',
            r.errorMessage.slice(0, 500),
            now,
          ),
      );
      quarantined++;
      continue;
    }

    if (r.outcome === 'NOT_FOUND') {
      const priorCveIds = splitCveIds(prior?.cve_ids);
      stmts.push(...deleteAffectedStmts(db, item.osvId, priorCveIds));
      for (const id of priorCveIds) invalidatedCveIds.add(id);
      stmts.push(upsertStateStmt(db, item, 'WITHDRAWN', '', null, prior, now));
      written++;
      unlinked++;
      continue;
    }

    // r.outcome === 'OK'
    const patch = r.patch;
    const contentHash = contentHashes.get(item.osvId) ?? '';

    const status = patch.withdrawn
      ? 'WITHDRAWN'
      : patch.cveIds.length === 0
        ? 'NO_CVE_ALIAS'
        : patch.cveIds.some((id) => existingCveIds.has(id))
          ? 'LINKED'
          : 'CVE_NOT_INGESTED';

    // NOT just "OSV's own content is unchanged" — status must ALSO be
    // unchanged. content_hash deliberately doesn't cover "does this alias
    // CVE exist in `cve` yet", so a CVE_NOT_INGESTED record whose NVD/MITRE
    // row has since landed (status now computes to LINKED) must NOT be
    // skipped here even though OSV's own `modified`/content never changed —
    // that's exactly the re-link pass's promotion path.
    const unchanged =
      prior?.modified_at === patch.modified &&
      prior?.content_hash === contentHash &&
      prior?.status === status;

    if (unchanged) {
      stmts.push(
        db
          .prepare('UPDATE osv_record_state SET checked_at = ? WHERE osv_id = ?')
          .bind(now, item.osvId),
      );
      skipped++;
      continue;
    }

    const linkedCveIds =
      status === 'LINKED' ? patch.cveIds.filter((id) => existingCveIds.has(id)) : [];

    // Replace this osv_id's cve_osv_affected rows for every CVE it was
    // EVER associated with (prior's full alias list, a safe superset) plus
    // whatever it's linked to now — DELETEs on rows that never existed are
    // harmless no-ops, and this keeps the logic simple (always
    // delete-then-insert on change, never try to diff old vs. new ranges).
    const toDelete = new Set([...splitCveIds(prior?.cve_ids), ...linkedCveIds]);
    stmts.push(...deleteAffectedStmts(db, item.osvId, [...toDelete]));
    for (const id of toDelete) invalidatedCveIds.add(id);

    if (status === 'LINKED') {
      for (const cveId of linkedCveIds) {
        for (const pkg of patch.affected) {
          stmts.push(
            db
              .prepare(
                `INSERT INTO cve_osv_affected
                   (cve_id, osv_id, ecosystem, package_name, purl, ranges_json, fixed_versions)
                 VALUES (?, ?, ?, ?, ?, ?, ?)
                 ON CONFLICT (cve_id, osv_id, ecosystem, package_name) DO UPDATE SET
                   purl           = excluded.purl,
                   ranges_json    = excluded.ranges_json,
                   fixed_versions = excluded.fixed_versions`,
              )
              .bind(
                cveId,
                item.osvId,
                pkg.ecosystem,
                pkg.name,
                pkg.purl,
                JSON.stringify(pkg.ranges),
                pkg.fixedVersions.length > 0 ? pkg.fixedVersions.join(',') : null,
              ),
          );
        }
      }
    }

    stmts.push(upsertStateStmt(db, item, status, patch.cveIds.join(','), contentHash, prior, now));
    written++;
    if (status !== 'LINKED') unlinked++;
  }

  if (stmts.length > 0) {
    await db.batch(stmts);
  }

  if (invalidatedCveIds.size > 0) {
    ctx.waitUntil(Promise.all([...invalidatedCveIds].map((id) => env.CACHE.delete(`cve:${id}`))));
  }

  return { written, skipped, unlinked, quarantined };
}

function splitCveIds(csv: string | null | undefined): string[] {
  return csv ? csv.split(',').filter(Boolean) : [];
}

function upsertStateStmt(
  db: D1Database,
  item: OsvFetchItem,
  status: string,
  cveIds: string,
  contentHash: string | null,
  prior: OsvStateRow | undefined,
  now: number,
): D1PreparedStatement {
  return db
    .prepare(
      `INSERT INTO osv_record_state
         (osv_id, ecosystem_dir, modified_at, content_hash, status, cve_ids, first_seen_at, checked_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (osv_id) DO UPDATE SET
         ecosystem_dir = excluded.ecosystem_dir,
         modified_at   = excluded.modified_at,
         content_hash  = excluded.content_hash,
         status        = excluded.status,
         cve_ids       = excluded.cve_ids,
         checked_at    = excluded.checked_at`,
      // first_seen_at deliberately omitted from the UPDATE SET — leaving it
      // out (rather than e.g. COALESCE(excluded..., current)) preserves the
      // existing row's value on conflict; the bound value below only takes
      // effect on a fresh INSERT.
    )
    .bind(
      item.osvId,
      item.ecosystemDir,
      item.modified,
      contentHash,
      status,
      cveIds,
      prior?.first_seen_at ?? now,
      now,
    );
}

function deleteAffectedStmts(
  db: D1Database,
  osvId: string,
  cveIds: string[],
): D1PreparedStatement[] {
  if (cveIds.length === 0) return [];
  const out: D1PreparedStatement[] = [];
  // -1 to leave room for the leading osv_id bind param within the 100-param cap.
  const chunkSize = SELECT_PARAM_CHUNK_SIZE - 1;
  for (let i = 0; i < cveIds.length; i += chunkSize) {
    const chunk = cveIds.slice(i, i + chunkSize);
    const placeholders = chunk.map(() => '?').join(',');
    out.push(
      db
        .prepare(`DELETE FROM cve_osv_affected WHERE osv_id = ? AND cve_id IN (${placeholders})`)
        .bind(osvId, ...chunk),
    );
  }
  return out;
}
