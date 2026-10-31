import { markIngestFinished, markIngestStarted } from '../lib/server/ingestRun';
import type { Env } from '../types';

const RETENTION_MONTHS = 24;
const QUOTA_RETENTION_DAYS = 7;
const AUDIT_RETENTION_DAYS = 90;
const DELETE_BATCH_SIZE = 500;
const MAX_DELETE_BATCHES = 50; // caps a single run at 25,000 rows

/**
 * Aging sweep (cron: 30 2 * * *).
 *
 * Hard-deletes CVE records published more than 24 months ago UNLESS the CVE
 * is KEV-listed. CASCADE foreign keys clean up all child rows automatically.
 * After deletion, rebuilds the cpe_search FTS index and writes daily metrics.
 * Also runs tail-purge of quota ledgers, audit_log, and cve_quarantine tables
 * (folded here to stay within the 5-trigger Workers cap).
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

  try {
    // Delete expired CVEs in bounded batches (CASCADE handles child rows).
    // The inner SELECT...LIMIT is standard SQLite (works without the
    // SQLITE_ENABLE_UPDATE_DELETE_LIMIT compile flag D1 doesn't guarantee);
    // a bare `DELETE ... LIMIT` would not be portable.
    for (let i = 0; i < MAX_DELETE_BATCHES; i++) {
      const result = await env.DB.prepare(
        `DELETE FROM cve WHERE cve_id IN (
           SELECT cve_id FROM cve
           WHERE published_at < ?
             AND cve_id NOT IN (SELECT cve_id FROM cve_state WHERE kev_listed = 1)
           LIMIT ?
         )`,
      )
        .bind(cutoffMs, DELETE_BATCH_SIZE)
        .run();

      const batchDeleted = result.meta.changes ?? 0;
      agedOut += batchDeleted;
      if (batchDeleted < DELETE_BATCH_SIZE) break; // fewer than a full batch — caught up
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

    // Write daily metrics snapshot.
    const metricDate = dateToInt(new Date(startedAt));
    const counts = await env.DB.prepare(
      `SELECT
         COUNT(*)                                              AS total_cves,
         SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) AS critical,
         SUM(CASE WHEN severity='HIGH'     THEN 1 ELSE 0 END) AS high,
         SUM(CASE WHEN severity='MEDIUM'   THEN 1 ELSE 0 END) AS medium,
         SUM(CASE WHEN severity='LOW'      THEN 1 ELSE 0 END) AS low,
         SUM(CASE WHEN severity='NONE'     THEN 1 ELSE 0 END) AS none_sev,
         (SELECT COUNT(*) FROM cve_state WHERE kev_listed = 1) AS kev_listed
       FROM cve`,
    ).first<{
      total_cves: number;
      critical: number;
      high: number;
      medium: number;
      low: number;
      none_sev: number;
      kev_listed: number;
    }>();

    if (counts) {
      const metrics: Array<[string, number]> = [
        ['total_cves', counts.total_cves ?? 0],
        ['severity_critical', counts.critical ?? 0],
        ['severity_high', counts.high ?? 0],
        ['severity_medium', counts.medium ?? 0],
        ['severity_low', counts.low ?? 0],
        ['severity_none', counts.none_sev ?? 0],
        ['kev_listed', counts.kev_listed ?? 0],
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
    if (agedOut > 0) {
      ctx.waitUntil(
        Promise.all(
          (['1h', '24h', '7d', '30d', '90d'] as const).map((w) =>
            env.CACHE.delete(`dash:metrics:${w}`),
          ),
        ),
      );
    }
  } catch (err) {
    lastError = String(err);
  }

  await markIngestFinished(env, 'AGING', lastError ? 'FAILED' : 'OK', agedOut, 0, lastError);

  ctx.waitUntil(
    Promise.resolve(
      env.ANALYTICS.writeDataPoint({
        blobs: ['AGING_SWEEP', lastError ? 'FAILED' : 'OK', 'AGING', '', '', '', ''],
        doubles: [startedAt, Date.now(), agedOut, 0, Date.now() - startedAt],
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
