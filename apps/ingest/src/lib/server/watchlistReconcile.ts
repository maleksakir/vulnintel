import type { Env } from '../../types';

// Watchlist match reconciliation — the engine behind the Phase 3 feature.
//
// Materializes `watchlist_match` rows: for every CVE modified since the last
// run whose CPEs match a watchlist's vendor/product subscription, upsert a
// match row (status 'NEW' on first match). Runs as its own queue-consumer
// invocation (pipelines/watchlistQueue.ts) with a fresh 50-D1-query budget,
// NOT inline in the daily cron — same reasoning as every other ingest path.
//
// Unlike OSV this is pure D1 (no external fetch), so it's a single
// invocation, not a two-phase discover/fetch. The per-invocation D1-query
// budget is the only hard constraint, and every loop below is bounded.

// D1's bound-parameter cap is 100 per query on every plan. The modified-CPE
// scan binds the vendor IN-list PLUS two extra params (sinceMs, the LIMIT), so
// the IN-list itself is capped at 98, not 100, to stay within the cap. (A
// 100-vendor chunk + 2 extra = 102 params → "too many SQL variables".)
const VENDOR_CHUNK_SIZE = 98;
// db.batch() counts as ONE query toward the 50-per-invocation cap regardless
// of statement count, so this only bounds memory/statement-size, not the
// query budget.
const WRITE_SUB_BATCH_SIZE = 500;
// Cap on CVEs processed per run. The cursor advances only as far as the
// newest CVE actually processed, so a large backlog (first run, or after a
// gap) is drained across multiple daily runs rather than blowing one
// invocation's budget. At this cap the worst-case query count is bounded:
// see the budget comment in reconcileWatchlistMatches.
const MAX_CVES_PER_RUN = 2000;
// First-ever run (no cursor row yet): look back this far rather than scanning
// the entire corpus. Forward-looking — existing CVEs that already match a
// subscription get picked up as they're next modified; a full historical
// backfill is a separate, explicit action (see reconcileWatchlistMatches'
// doc), not something a routine run should ever attempt.
const FIRST_RUN_LOOKBACK_MS = 72 * 60 * 60 * 1000;
const CURSOR_SAFETY_OVERLAP_MS = 60 * 60 * 1000; // 1h overlap, see below

const SYNC_KEY = 'watchlist_match';

interface SubscriptionRow {
  watchlist_id: number;
  vendor: string;
  product: string | null;
}

interface ModifiedCpeRow {
  cve_id: string;
  vendor: string;
  product: string;
  last_modified_at: number;
}

/** Test-only bound overrides; see reconcileWatchlistMatches. */
export interface ReconcileOptions {
  maxCvesPerRun?: number;
  vendorChunkSize?: number;
}

export interface ReconcileResult {
  cvesScanned: number;
  matchesWritten: number;
  cursorAdvancedToMs: number | null;
}

/**
 * Incremental watchlist match reconciliation.
 *
 * Budget (worst case, MAX_CVES_PER_RUN modified CVEs all matching):
 *   - 1 read: cursor
 *   - 1 read: all subscriptions (small — dozens, bounded by UI)
 *   - If no subscriptions exist, returns immediately (common case early on).
 *   - N reads: the modified-CPE scan, chunked by the DISTINCT vendor set at
 *     VENDOR_CHUNK_SIZE (98, leaving room for 2 extra binds). The vendor set
 *     is bounded by the subscription count, not by CVE count, so this is
 *     ceil(vendors/98) reads — a handful in practice.
 *   - ceil(matches / 500) batch writes for the upserts.
 *   - 1 write: cursor update.
 * Comfortably under 50 for any realistic subscription set. The CVE-count cap
 * bounds the match-write side; the vendor-count chunking bounds the read side.
 *
 * Idempotent: re-running over the same window re-upserts identical rows
 * (ON CONFLICT preserves status/note — a re-match never resets an analyst's
 * triage), so the CURSOR_SAFETY_OVERLAP_MS re-scan is harmless.
 */
export async function reconcileWatchlistMatches(
  env: Env,
  now: number = Date.now(),
  opts: ReconcileOptions = {},
): Promise<ReconcileResult> {
  // Both bounds are overridable DOWNWARD only (never above the constants), so
  // a test can reproduce a saturated multi-chunk scan without seeding 4,000
  // CVEs across 99 vendors. The 100-bound-parameter cap is still enforced by
  // the clamp on vendorChunkSize.
  const maxCvesPerRun = Math.min(opts.maxCvesPerRun ?? MAX_CVES_PER_RUN, MAX_CVES_PER_RUN);
  const vendorChunkSize = Math.min(opts.vendorChunkSize ?? VENDOR_CHUNK_SIZE, VENDOR_CHUNK_SIZE);
  // ── Subscriptions first: if none, there is nothing to match. ─────────────
  const subsRes = await env.DB.prepare(
    `SELECT watchlist_id, vendor, product FROM watchlist_subscription`,
  ).all<SubscriptionRow>();
  const subs = subsRes.results;
  if (subs.length === 0) {
    // Still advance the cursor so that when subscriptions are later added,
    // the first run doesn't re-scan a huge stale backlog — matches for a new
    // subscription are seeded by the API's own targeted backfill, not here.
    await bumpCursor(env, now, now);
    return { cvesScanned: 0, matchesWritten: 0, cursorAdvancedToMs: now };
  }

  // ── Cursor ────────────────────────────────────────────────────────────────
  const cursorRow = await env.DB.prepare(
    `SELECT last_cursor_ms FROM watchlist_sync_state WHERE key = ?`,
  )
    .bind(SYNC_KEY)
    .first<{ last_cursor_ms: number }>();
  const sinceMs =
    cursorRow?.last_cursor_ms != null
      ? cursorRow.last_cursor_ms - CURSOR_SAFETY_OVERLAP_MS
      : now - FIRST_RUN_LOOKBACK_MS;

  // Build the DISTINCT vendor set from subscriptions — the read filter.
  // Matching vendor-side in SQL (not fetching every modified CVE) keeps the
  // scan proportional to subscribed vendors, not to total CVE churn.
  const vendors = [...new Set(subs.map((s) => s.vendor))];

  // Index subscriptions for in-memory matching:
  //   vendor -> { allProducts: Set<watchlistId>, byProduct: Map<product, Set<watchlistId>> }
  const subIndex = new Map<
    string,
    { allProducts: Set<number>; byProduct: Map<string, Set<number>> }
  >();
  for (const s of subs) {
    let entry = subIndex.get(s.vendor);
    if (!entry) {
      entry = { allProducts: new Set(), byProduct: new Map() };
      subIndex.set(s.vendor, entry);
    }
    if (s.product === null) {
      entry.allProducts.add(s.watchlist_id);
    } else {
      let set = entry.byProduct.get(s.product);
      if (!set) {
        set = new Set();
        entry.byProduct.set(s.product, set);
      }
      set.add(s.watchlist_id);
    }
  }

  // ── Scan modified CPEs for subscribed vendors ─────────────────────────────
  // (cve_id, vendor, product) for CVEs modified since the cursor whose vendor
  // is subscribed. Chunked by the vendor set at the 100-param cap.
  const cpeRows: ModifiedCpeRow[] = [];
  // The LIMIT is applied PER CHUNK, so each chunk has its own high-water mark
  // and its own answer to "did I see everything in the window?". If any chunk
  // came back saturated it still has unprocessed rows above its own newest
  // row, so the cursor may only advance to the LOWEST saturated chunk's mark —
  // advancing to the global maximum (as this did) silently skipped every
  // unprocessed row below it, permanently, for anyone with more than 98
  // subscribed vendors.
  let saturatedFloorMs: number | null = null;
  for (let i = 0; i < vendors.length; i += vendorChunkSize) {
    const chunk = vendors.slice(i, i + vendorChunkSize);
    const placeholders = chunk.map(() => '?').join(',');
    const res = await env.DB.prepare(
      `SELECT DISTINCT p.cve_id, p.vendor, p.product, c.last_modified_at
       FROM cpe p
       JOIN cve c ON c.cve_id = p.cve_id
       WHERE p.vendor IN (${placeholders})
         AND c.last_modified_at > ?
       ORDER BY c.last_modified_at ASC
       LIMIT ?`,
    )
      .bind(...chunk, sinceMs, maxCvesPerRun)
      .all<ModifiedCpeRow>();
    cpeRows.push(...res.results);

    if (res.results.length >= maxCvesPerRun) {
      // Ordered ASC, so the last row is this chunk's newest processed CVE.
      const chunkMax = res.results[res.results.length - 1]!.last_modified_at;
      saturatedFloorMs =
        saturatedFloorMs === null ? chunkMax : Math.min(saturatedFloorMs, chunkMax);
    }
  }

  if (cpeRows.length === 0) {
    // Nothing modified in-window for subscribed vendors. Advance the cursor
    // to `now` so the window doesn't grow unbounded.
    await bumpCursor(env, now, now);
    return { cvesScanned: 0, matchesWritten: 0, cursorAdvancedToMs: now };
  }

  // ── Match in memory → (watchlist_id, cve_id) pairs ───────────────────────
  // Dedupe pairs: a watchlist can match a CVE via multiple CPE rows.
  const pairs = new Map<string, { watchlistId: number; cveId: string }>();
  const scannedCves = new Set<string>();
  let maxModified = sinceMs;
  for (const row of cpeRows) {
    scannedCves.add(row.cve_id);
    if (row.last_modified_at > maxModified) maxModified = row.last_modified_at;
    const entry = subIndex.get(row.vendor);
    if (!entry) continue;
    const watchlistIds = new Set<number>(entry.allProducts);
    const byProduct = entry.byProduct.get(row.product);
    if (byProduct) for (const id of byProduct) watchlistIds.add(id);
    for (const wid of watchlistIds) {
      pairs.set(`${wid}\u0000${row.cve_id}`, { watchlistId: wid, cveId: row.cve_id });
    }
  }

  // ── Upsert matches (batched). ON CONFLICT updates nothing that would
  // clobber triage: a re-match of an already-tracked CVE is a no-op on
  // status/note/first_matched_at — only brand-new (watchlist, cve) pairs
  // insert a 'NEW' row. This is what makes the safety-overlap re-scan and
  // repeated daily runs idempotent. ──────────────────────────────────────
  const pairList = [...pairs.values()];
  let matchesWritten = 0;
  for (let i = 0; i < pairList.length; i += WRITE_SUB_BATCH_SIZE) {
    const sub = pairList.slice(i, i + WRITE_SUB_BATCH_SIZE);
    await env.DB.batch(
      sub.map((p) =>
        env.DB.prepare(
          `INSERT INTO watchlist_match
             (watchlist_id, cve_id, status, note, first_matched_at, status_updated_at)
           VALUES (?, ?, 'NEW', NULL, ?, ?)
           ON CONFLICT (watchlist_id, cve_id) DO NOTHING`,
        ).bind(p.watchlistId, p.cveId, now, now),
      ),
    );
    matchesWritten += sub.length;
  }

  // ── Advance the cursor. With no saturated chunk, every in-window row was
  // processed and the newest one is a safe resume point. With one or more
  // saturated chunks, the resume point is the LOWEST of their high-water
  // marks: anything above that in a saturated chunk hasn't been read yet.
  // The next run re-reads the overlap and re-upserts (ON CONFLICT DO NOTHING
  // preserves triage), so re-scanning is free of side effects.
  //
  // Residual: if a single millisecond holds more than MAX_CVES_PER_RUN
  // matching rows, the floor equals the current cursor and it stops advancing.
  // Matches still get written every run (the scan restarts from the same
  // point), so nothing is lost — it just can't move past that cluster. At
  // 2,000 rows sharing one millisecond of NVD last_modified this is a
  // theoretical case, not an operational one.
  const cursorTargetMs = saturatedFloorMs ?? maxModified;
  await bumpCursor(env, cursorTargetMs, now);

  return {
    cvesScanned: scannedCves.size,
    matchesWritten,
    cursorAdvancedToMs: cursorTargetMs,
  };
}

async function bumpCursor(env: Env, cursorMs: number, now: number): Promise<void> {
  await env.DB.prepare(
    `INSERT INTO watchlist_sync_state (key, last_cursor_ms, last_run_at)
     VALUES (?, ?, ?)
     ON CONFLICT (key) DO UPDATE SET
       last_cursor_ms = MAX(last_cursor_ms, excluded.last_cursor_ms),
       last_run_at    = excluded.last_run_at`,
  )
    .bind(SYNC_KEY, cursorMs, now)
    .run();
}
