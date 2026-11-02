import { markIngestFinished, markIngestStarted } from '../lib/server/ingestRun';
import { type RollupResult, rebuildAllRollups } from '../lib/server/rollups';
import type { Env } from '../types';

const RETENTION_MONTHS = 24;
const QUOTA_RETENTION_DAYS = 7;
const AUDIT_RETENTION_DAYS = 90;
const DELETE_BATCH_SIZE = 500;
/**
 * 20, not 50, because a Worker invocation gets 50 D1 queries on the Free plan
 * and this run also has to rebuild the rollups and write the daily metrics
 * snapshot. At 50 delete batches the sweep spent its ENTIRE query budget on
 * deletes and everything after it would have been killed — another reason
 * this job never reached completion. 20 batches x 500 rows = 10,000 CVEs per
 * run, which drains the ~21,000-row backlog in about three days and then
 * trivially keeps up with steady state.
 */
const MAX_DELETE_BATCHES = 20;

/**
 * Aging sweep (cron: 30 2 * * *).
 *
 * Hard-deletes CVE records published more than 24 months ago UNLESS the CVE
 * is KEV-listed. CASCADE foreign keys clean up all child rows automatically.
 * After deletion, rebuilds the cpe_search FTS index and writes daily metrics.
 * Also runs tail-purge of quota ledgers, audit_log, and cve_quarantine tables
 * (folded here to stay within the 5-trigger Workers cap).
 *
 * D1 query budget (Free plan kills an invocation at its 51st query):
 *   2       ingest_run start/finish
 *   <=20    delete batches (one db.batch each)
 *   1       operational tail purge + orphaned match sweep
 *   1       cpe_search rebuild, only when something aged out
 *   6       rollup rebuilds, prunes and bookkeeping (lib/server/rollups.ts)
 *   6       daily metrics snapshot reads + write + rollup-day prune
 *   ------
 *   ~36 worst case. The delete batch count is capped at 20 specifically to
 *   leave room for the rest; at the previous 50 it consumed the whole budget.
 *
 * The delete runs in bounded batches, not one unconditional statement.
 * Found 2026-10-28: a single unbatched DELETE against the full backlog (plus
 * cascading FK deletes across cpe/cve_reference/FTS5 shadow tables, plus an
 * unconditional full cpe_search rebuild afterward) had been silently
 * exceeding the Worker's CPU/time budget and getting killed mid-run for
 * ~2 months — markIngestStarted recorded each attempt, but the kill
 * happened before markIngestFinished ever ran, so `ingest_run` kept
 * reporting a stale "OK" from the last run small enough to finish while a
 * ~21,000-row backlog silently accumulated (a meaningful share of the D1
 * free-tier 500MB cap). Batching bounds the worst case per invocation
 * regardless of how large the backlog gets.
 */
export async function runAgingSweep(env: Env, ctx: ExecutionContext): Promise<void> {
  const startedAt = Date.now();
  const cutoffMs = startedAt - RETENTION_MONTHS * 30.44 * 24 * 60 * 60 * 1000;

  await markIngestStarted(env, 'AGING');

  let agedOut = 0;
  let lastError: string | undefined;
  let rollups: RollupResult | null = null;

  try {
    // Delete expired CVEs in bounded batches (CASCADE handles child rows for
    // every real table; cve_search is a virtual table, so it needs the
    // explicit delete below).
    //
    // Migration 0013 removed the per-row `cve_fts_delete` trigger, so this
    // loop owns FTS cleanup. That trigger's `WHERE cve_id = old.cve_id` was a
    // full scan of the FTS index PER DELETED ROW, because
    // `cve_search.cve_id` is FTS5 UNINDEXED — hundreds of full scans per
    // batch, which is what had really been killing this job mid-run for
    // ~2 months. Now it is one scan per batch.
    //
    // Both statements take the SAME subquery rather than a list of ids bound
    // as parameters, which keeps the batch to ONE query and sidesteps the
    // 100-bound-parameter cap that would otherwise force batches of 90.
    // `ORDER BY published_at, cve_id` makes the LIMITed set deterministic, so
    // the two statements provably address the same rows; the FTS delete runs
    // first and doesn't touch `cve`, so the second sees the same set.
    const expiredSubquery = `SELECT cve_id FROM cve
         WHERE published_at < ?
           AND cve_id NOT IN (SELECT cve_id FROM cve_state WHERE kev_listed = 1)
         ORDER BY published_at ASC, cve_id ASC
         LIMIT ?`;

    for (let i = 0; i < MAX_DELETE_BATCHES; i++) {
      const results = await env.DB.batch([
        env.DB.prepare(`DELETE FROM cve_search WHERE cve_id IN (${expiredSubquery})`).bind(
          cutoffMs,
          DELETE_BATCH_SIZE,
        ),
        env.DB.prepare(`DELETE FROM cve WHERE cve_id IN (${expiredSubquery})`).bind(
          cutoffMs,
          DELETE_BATCH_SIZE,
        ),
      ]);

      // results[1] is the `cve` delete; its changes count is the real tally
      // (results[0] counts FTS rows, which can differ if a CVE was somehow
      // never indexed).
      const batchDeleted = results[1]?.meta.changes ?? 0;
      agedOut += batchDeleted;
      if (batchDeleted < DELETE_BATCH_SIZE) break; // caught up
    }

    // Tail-purge operational tables.
    const quotaCutoffDay = isoDay(new Date(startedAt - QUOTA_RETENTION_DAYS * 86400000));
    const auditCutoffMs = startedAt - AUDIT_RETENTION_DAYS * 86400000;

    await env.DB.batch([
      env.DB.prepare('DELETE FROM search_quota_ledger WHERE day < ?').bind(quotaCutoffDay),
      env.DB.prepare('DELETE FROM search_quota_ip_ledger WHERE bucket < ?').bind(quotaCutoffDay),
      env.DB.prepare('DELETE FROM audit_log WHERE occurred_at < ?').bind(auditCutoffMs),
      env.DB.prepare('DELETE FROM cve_quarantine WHERE quarantined_at < ?').bind(auditCutoffMs),
      // Long-expired risk acceptances (Phase 4 remediation). An acceptance
      // auto-reactivates the instant it expires (derived read), so an expired
      // row is purely a historical audit record — keep it for the same 90-day
      // window as audit_log, then prune. `IF NOT EXISTS`-created table (0012);
      // a plain DELETE is a no-op if the table somehow isn't there yet.
      env.DB.prepare('DELETE FROM cve_risk_acceptance WHERE expires_at < ?').bind(auditCutoffMs),
      // Orphaned match rows. watchlist_match.cve_id and
      // asset_component_match.cve_id are deliberately NOT foreign keys
      // (migrations 0009/0011 — a match must survive a CVE that hasn't been
      // ingested yet), so the CASCADE above doesn't reach them and the CVE
      // delete at the top of this sweep leaves them behind. Both migrations
      // say this tail sweeps them; until now it didn't, so they accumulated
      // against a 500MB D1 cap that a DELETE cannot reclaim. Bounded by
      // DELETE_BATCH_SIZE per run; the tables are small, so one batch a day
      // keeps up.
      // Both tables are WITHOUT ROWID, so the bound set is a batch of DISTINCT
      // orphaned cve_ids rather than rowids. Row count per run is therefore
      // DELETE_BATCH_SIZE x (watchlists/components referencing those CVEs),
      // still bounded, and the next run picks up any remainder.
      //
      // Only NEW (nobody looked at it) and terminal RESOLVED/IGNORED matches
      // go — exactly what 0009 promises. TRIAGING and ACKNOWLEDGED mean an
      // analyst is mid-decision, and 0009's whole reason for not making
      // cve_id a foreign key is that such a decision must outlive its CVE.
      env.DB.prepare(
        `DELETE FROM watchlist_match WHERE cve_id IN (
           SELECT DISTINCT m.cve_id FROM watchlist_match m
           WHERE m.status IN ('NEW','RESOLVED','IGNORED')
             AND NOT EXISTS (SELECT 1 FROM cve c WHERE c.cve_id = m.cve_id)
           LIMIT ?
         ) AND status IN ('NEW','RESOLVED','IGNORED')`,
      ).bind(DELETE_BATCH_SIZE),
      env.DB.prepare(
        `DELETE FROM asset_component_match WHERE cve_id IN (
           SELECT DISTINCT m.cve_id FROM asset_component_match m
           WHERE NOT EXISTS (SELECT 1 FROM cve c WHERE c.cve_id = m.cve_id)
           LIMIT ?
         )`,
      ).bind(DELETE_BATCH_SIZE),
    ]);

    // Rebuild cpe_search FTS after bulk delete (one-shot cheaper than
    // per-row trigger) — only when something was actually deleted. This
    // was previously unconditional: a full rebuild over 260k+ cpe rows
    // every single day regardless of whether any aging occurred was itself
    // a meaningful, avoidable share of this job's cost.
    if (agedOut > 0) {
      await env.DB.batch([
        env.DB.prepare('DELETE FROM cpe_search'),
        env.DB.prepare(
          `INSERT INTO cpe_search (vendor, product)
           SELECT DISTINCT vendor, product FROM cpe`,
        ),
      ]);
    }

    // ── Dashboard rollups (migration 0014) ────────────────────────────────
    // Rebuilt AFTER the deletes above, so aged-out CVEs can't leave counts
    // behind. This is what moved the dashboard off computing ~10M rows/day of
    // aggregates on its read path; see lib/server/rollups.ts.
    rollups = await rebuildAllRollups(env, startedAt);

    // ── Daily metrics snapshot ────────────────────────────────────────────
    // Derived FROM the rollups just built, not from another pass over `cve`.
    // The severity totals are a sum over ~4,400 rollup rows instead of a
    // 375k-row table scan, and the KEV total comes from the KEV rollup, so
    // this snapshot now costs effectively nothing.
    const metricDate = dateToInt(new Date(startedAt));

    const [sevRes, kevRes, stateRow, cpeRow] = await Promise.all([
      env.DB.prepare(
        `SELECT severity, SUM(cve_count) AS n FROM cve_rollup_daily GROUP BY severity`,
      ).all<{ severity: string; n: number }>(),
      env.DB.prepare(`SELECT SUM(kev_count) AS n FROM cve_rollup_kev_daily`).first<{
        n: number | null;
      }>(),
      // ONE pass over cve_state for all three things we need from it. These
      // were three separate full scans across the sweep and /admin/health;
      // merging them is worth ~750k rows/day on a 5M/day budget.
      env.DB.prepare(
        `SELECT COUNT(*)                                            AS rows_total,
                SUM(kev_listed)                                     AS kev_rows,
                AVG(CASE WHEN epss_updated_at > ? THEN epss_percentile END) AS mean_epss_7d
         FROM cve_state`,
      )
        .bind(startedAt - 7 * 86400000)
        .first<{ rows_total: number; kev_rows: number | null; mean_epss_7d: number | null }>(),
      env.DB.prepare(`SELECT COUNT(*) AS n FROM cpe`).first<{ n: number }>(),
    ]);

    const bySeverity = new Map<string, number>();
    for (const r of sevRes.results) bySeverity.set(r.severity, r.n ?? 0);
    const totalCves = [...bySeverity.values()].reduce((a, b) => a + b, 0);

    {
      // /admin/health used to read these five counts with a query that scanned
      // 505k rows on every load. It now reads this snapshot instead, so the
      // counts are computed once a day here rather than once per page view.
      const metrics: Array<[string, number]> = [
        ['total_cves', totalCves],
        ['severity_critical', bySeverity.get('CRITICAL') ?? 0],
        ['severity_high', bySeverity.get('HIGH') ?? 0],
        ['severity_medium', bySeverity.get('MEDIUM') ?? 0],
        ['severity_low', bySeverity.get('LOW') ?? 0],
        ['severity_none', bySeverity.get('NONE') ?? 0],
        ['kev_listed', kevRes?.n ?? stateRow?.kev_rows ?? 0],
        ['cve_state_rows', stateRow?.rows_total ?? 0],
        ['cpe_rows', cpeRow?.n ?? 0],
        ['mean_epss_percentile_7d', stateRow?.mean_epss_7d ?? 0],
        ['aged_out', agedOut],
      ];

      await env.DB.batch(
        metrics.map(([key, val]) =>
          env.DB.prepare(
            `INSERT INTO cve_metrics_daily (metric_date, metric_key, value)
             VALUES (?, ?, ?)
             ON CONFLICT (metric_date, metric_key) DO UPDATE SET value = excluded.value`,
          ).bind(metricDate, key, val),
        ),
      );
    }

    // Prune rollup day-buckets for days that have fully aged out of the
    // 24-month retention window, so cve_rollup_daily can't grow without
    // bound either.
    await env.DB.prepare(`DELETE FROM cve_rollup_daily WHERE day < ?`)
      .bind(dateToInt(new Date(cutoffMs)))
      .run();

    // Invalidate the dashboard metrics cache. The app worker caches
    // getMetrics() output under `dash:metrics:<window>` (see
    // apps/app/src/routes/api/metrics/[window]/+server.ts and the homepage
    // +page.server.ts — both share these exact keys). A previous version of
    // this sweep deleted `dash:kpi:total|severity|kev|epss` instead, which
    // are keys NOTHING ever writes — so the real metrics cache was never
    // event-invalidated and relied solely on its 300s TTL, and the four
    // deletes were pure waste against the 1,000/day KV write+delete cap.
    // Only invalidate when the sweep actually changed the corpus (deleted
    // aged-out CVEs); a no-op run must not burn KV deletes 4x/day for
    // nothing — same skip-if-unchanged discipline the rest of ingest uses.
    //
    // No longer gated on `agedOut > 0`: as of migration 0014 this run also
    // REBUILDS the rollups the dashboard reads, so every run changes the
    // numbers behind those keys whether or not anything aged out. Five
    // deletes once a day is negligible against the 1,000/day KV cap — the
    // original problem was four deletes 4x/day against keys nothing wrote.
    ctx.waitUntil(
      Promise.all(
        (['1h', '24h', '7d', '30d', '90d'] as const).map((w) =>
          env.CACHE.delete(`dash:metrics:${w}`),
        ),
      ),
    );
  } catch (err) {
    lastError = String(err);
  }

  await markIngestFinished(env, 'AGING', lastError ? 'FAILED' : 'OK', agedOut, 0, lastError);

  ctx.waitUntil(
    Promise.resolve(
      env.ANALYTICS.writeDataPoint({
        blobs: ['AGING_SWEEP', lastError ? 'FAILED' : 'OK', 'AGING', '', '', '', ''],
        doubles: [
          startedAt,
          Date.now(),
          agedOut,
          // How many days of vendor rollup this run rebuilt. 0 means the
          // rollup step never completed, which is the signal that the
          // dashboard is serving stale aggregates.
          rollups?.vendorDays ?? 0,
          Date.now() - startedAt,
        ],
        indexes: ['ingest_run'],
      }),
    ),
  );
}

function dateToInt(d: Date): number {
  return d.getUTCFullYear() * 10000 + (d.getUTCMonth() + 1) * 100 + d.getUTCDate();
}

function isoDay(d: Date): string {
  return d.toISOString().slice(0, 10);
}
