import type { Env } from '../../types';

// Dashboard rollup builders (migration 0014).
//
// getMetrics() used to compute five aggregates from the base tables on every
// cache miss, costing ~10M rows/day against a 5M/day cap — see 0014's header
// for the measurements. These builders pre-aggregate the same data at day
// grain so the read path sums a few hundred rows instead of scanning the
// corpus, and so that cost stops growing as the corpus deepens.
//
// Every builder is `DELETE` + `INSERT … SELECT … GROUP BY` inside ONE
// db.batch(). That shape matters for three separate reasons:
//
//   * Query budget. A Worker invocation gets 50 D1 queries on the Free plan
//     and db.batch() counts as one, so each rollup costs exactly 1 query no
//     matter how many buckets it produces. Aggregating in SQL rather than
//     reading rows into JS and writing them back is what makes that possible:
//     the 27k-row vendor rollup would otherwise need ~54 batched writes and
//     die partway through, which is the same mistake the SBOM import had to
//     be rescued from.
//   * Atomicity. The DELETE rides with the INSERT, so a failed invocation
//     cannot leave the dashboard reading an emptied rollup and silently
//     rendering zeros.
//   * Correctness. Clearing before reinserting lets a bucket SHRINK. A
//     severity moving HIGH -> CRITICAL, or a CVE ageing out, reduces a count;
//     an upsert-only pass would leave the stale higher number in place
//     forever.
//
// Day keys are INTEGER yyyymmdd (UTC), matching cve_metrics_daily from 0005.

/** The widest window the dashboard offers; bounds cve_rollup_vendor_daily. */
export const VENDOR_ROLLUP_DAYS = 90;
/**
 * Trailing window the vendor rollup rebuilds on an ordinary daily run.
 *
 * A published CVE's vendor set never changes, so only recent buckets really
 * move — but `kev_count` can change for any day when CISA adds an old CVE to
 * the KEV catalogue, so the full 90 days still has to be rebuilt periodically.
 * Doing that every day would write ~27k rows daily, a quarter of the 100k/day
 * free-tier write allowance, for buckets that are almost always identical.
 * 30 days daily plus a full pass weekly keeps writes around 9k/day.
 */
export const VENDOR_REFRESH_DAYS = 30;
/** How stale a full vendor rebuild may get before the next run forces one. */
const VENDOR_FULL_REBUILD_INTERVAL_MS = 7 * 86_400_000;
/** Trailing window a post-ingest refresh recomputes. */
export const REFRESH_DAYS = 7;

const DAY_MS = 86_400_000;

/** SQL expression turning a unix-ms column into an INTEGER yyyymmdd (UTC). */
const DAY_EXPR = (col: string) => `CAST(strftime('%Y%m%d', ${col} / 1000, 'unixepoch') AS INTEGER)`;

export interface RollupResult {
  /** Whether the vendor rollup did a full 90-day pass this run. */
  vendorFullRebuild: boolean;
  dailyDays: number;
  vendorDays: number;
}

/**
 * Rebuild the rollups. Called once a day from the aging sweep, AFTER its
 * deletes, so aged-out CVEs are already gone and no rollup retains counts for
 * rows that no longer exist.
 *
 * Query cost: 5 (three rollup batches, two prunes) plus one bookkeeping write.
 * Read cost: one pass over `cve` (~375k rows), one partial-index pass over
 * `cve_state` for KEV, and a 30- or 90-day-windowed pass over the cpe/cve
 * join. Versus the ~10M rows/day the uncached read path was spending to
 * answer the same questions.
 */
export async function rebuildAllRollups(env: Env, now: number = Date.now()): Promise<RollupResult> {
  const prior = await env.DB.prepare(
    `SELECT last_full_at FROM rollup_state WHERE rollup_key = 'vendor_daily'`,
  ).first<{ last_full_at: number | null }>();

  const vendorFullRebuild =
    prior?.last_full_at == null || now - prior.last_full_at >= VENDOR_FULL_REBUILD_INTERVAL_MS;
  const vendorDays = vendorFullRebuild ? VENDOR_ROLLUP_DAYS : VENDOR_REFRESH_DAYS;

  await rebuildDailyRollup(env, null);
  await rebuildKevRollup(env, null);
  await rebuildVendorRollup(env, now - vendorDays * DAY_MS);

  // Vendor buckets outside the retained window are dead weight.
  await env.DB.prepare(`DELETE FROM cve_rollup_vendor_daily WHERE day < ?`)
    .bind(dayKey(now - VENDOR_ROLLUP_DAYS * DAY_MS))
    .run();

  await markRollups(env, {
    now,
    fullKeys: vendorFullRebuild ? ['daily', 'kev_daily', 'vendor_daily'] : ['daily', 'kev_daily'],
    refreshKeys: vendorFullRebuild ? [] : ['vendor_daily'],
  });

  return { vendorFullRebuild, dailyDays: 0, vendorDays };
}

/**
 * Trailing-window refresh, for callers that land data outside the daily sweep
 * and want the dashboard to reflect it immediately.
 *
 * NOTE this deliberately does NOT catch a CVE published months ago whose
 * severity changed today — that row's day bucket is outside the window. The
 * daily FULL rebuild in the aging sweep is what makes the rollups exact; a
 * refresh only buys freshness for recent days, which is where essentially all
 * churn is.
 */
export async function refreshRecentRollups(
  env: Env,
  now: number = Date.now(),
): Promise<RollupResult> {
  const sinceMs = now - REFRESH_DAYS * DAY_MS;
  await rebuildDailyRollup(env, sinceMs);
  await rebuildKevRollup(env, sinceMs);
  await rebuildVendorRollup(env, sinceMs);

  await markRollups(env, {
    now,
    fullKeys: [],
    refreshKeys: ['daily', 'kev_daily', 'vendor_daily'],
  });

  return { vendorFullRebuild: false, dailyDays: REFRESH_DAYS, vendorDays: REFRESH_DAYS };
}

/** Published-CVE counts by (day, severity). `sinceMs === null` rebuilds all. */
async function rebuildDailyRollup(env: Env, sinceMs: number | null): Promise<void> {
  if (sinceMs === null) {
    await env.DB.batch([
      env.DB.prepare(`DELETE FROM cve_rollup_daily`),
      env.DB.prepare(
        `INSERT INTO cve_rollup_daily (day, severity, cve_count)
         SELECT ${DAY_EXPR('published_at')} AS day, severity, COUNT(*)
         FROM cve GROUP BY day, severity`,
      ),
    ]);
    return;
  }
  await env.DB.batch([
    env.DB.prepare(`DELETE FROM cve_rollup_daily WHERE day >= ?`).bind(dayKey(sinceMs)),
    env.DB.prepare(
      `INSERT INTO cve_rollup_daily (day, severity, cve_count)
       SELECT ${DAY_EXPR('published_at')} AS day, severity, COUNT(*)
       FROM cve WHERE published_at > ? GROUP BY day, severity`,
    ).bind(sinceMs),
  ]);
}

/**
 * KEV additions by kev_date_added day. `idx_state_kev_partial` is a partial
 * index on (kev_date_added) WHERE kev_listed = 1, so this reads only KEV rows
 * — a few thousand, not the whole cve_state table.
 */
async function rebuildKevRollup(env: Env, sinceMs: number | null): Promise<void> {
  const select = `SELECT ${DAY_EXPR('kev_date_added')} AS day, COUNT(*)
                  FROM cve_state
                  WHERE kev_listed = 1 AND kev_date_added IS NOT NULL`;
  if (sinceMs === null) {
    await env.DB.batch([
      env.DB.prepare(`DELETE FROM cve_rollup_kev_daily`),
      env.DB.prepare(`INSERT INTO cve_rollup_kev_daily (day, kev_count) ${select} GROUP BY day`),
    ]);
    return;
  }
  await env.DB.batch([
    env.DB.prepare(`DELETE FROM cve_rollup_kev_daily WHERE day >= ?`).bind(dayKey(sinceMs)),
    env.DB.prepare(
      `INSERT INTO cve_rollup_kev_daily (day, kev_count)
       ${select} AND kev_date_added > ? GROUP BY day`,
    ).bind(sinceMs),
  ]);
}

/**
 * Vendor exposure by (day, vendor) for CVEs published since `sinceMs`.
 *
 * cve_count is COUNT(DISTINCT cve_id), so a vendor listed under several CPE
 * rows on one CVE counts once and summing across days stays exact (a CVE has
 * exactly one published day, by definition).
 */
async function rebuildVendorRollup(env: Env, sinceMs: number): Promise<void> {
  await env.DB.batch([
    env.DB.prepare(`DELETE FROM cve_rollup_vendor_daily WHERE day >= ?`).bind(dayKey(sinceMs)),
    env.DB.prepare(
      `INSERT INTO cve_rollup_vendor_daily (day, vendor, cve_count, kev_count)
       SELECT ${DAY_EXPR('c.published_at')} AS day,
              p.vendor,
              COUNT(DISTINCT p.cve_id),
              COUNT(DISTINCT CASE WHEN s.kev_listed = 1 THEN p.cve_id END)
       FROM cve c
       JOIN cpe p ON p.cve_id = c.cve_id
       LEFT JOIN cve_state s ON s.cve_id = c.cve_id
       WHERE c.published_at > ?
       GROUP BY day, p.vendor`,
    ).bind(sinceMs),
  ]);
}

/**
 * One batched write for all three bookkeeping rows, so /admin/health can show
 * whether the dashboard's numbers are current. Without this, a rollup that
 * stopped rebuilding would serve stale aggregates indefinitely with nothing
 * to indicate it — the "stale OK status" failure mode CLAUDE.md records for
 * the aging sweep itself.
 */
async function markRollups(
  env: Env,
  opts: { now: number; fullKeys: string[]; refreshKeys: string[] },
): Promise<void> {
  const stmt = (key: string, full: boolean) =>
    env.DB.prepare(
      `INSERT INTO rollup_state
         (rollup_key, last_full_at, last_refresh_at, last_status, last_error, rows_written)
       VALUES (?, ?, ?, 'OK', NULL, 0)
       ON CONFLICT (rollup_key) DO UPDATE SET
         last_full_at    = COALESCE(excluded.last_full_at, last_full_at),
         last_refresh_at = excluded.last_refresh_at,
         last_status     = 'OK',
         last_error      = NULL`,
    ).bind(key, full ? opts.now : null, opts.now);

  const stmts = [
    ...opts.fullKeys.map((k) => stmt(k, true)),
    ...opts.refreshKeys.map((k) => stmt(k, false)),
  ];
  if (stmts.length > 0) await env.DB.batch(stmts);
}

/** unix ms → INTEGER yyyymmdd (UTC), the day key used by every rollup. */
export function dayKey(ms: number): number {
  const d = new Date(ms);
  return d.getUTCFullYear() * 10000 + (d.getUTCMonth() + 1) * 100 + d.getUTCDate();
}
