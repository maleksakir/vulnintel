import { markIngestFinished, markIngestStarted } from '../lib/server/ingestRun';
import type { Env } from '../types';

const RETENTION_MONTHS = 24;
const QUOTA_RETENTION_DAYS = 7;
const AUDIT_RETENTION_DAYS = 90;

/**
 * Aging sweep (cron: 30 2 * * *).
 *
 * Hard-deletes CVE records published more than 24 months ago UNLESS the CVE
 * is KEV-listed. CASCADE foreign keys clean up all child rows automatically.
 * After deletion, rebuilds the cpe_search FTS index and writes daily metrics.
 * Also runs tail-purge of quota ledgers, audit_log, and cve_quarantine tables
 * (folded here to stay within the 5-trigger Workers cap).
 */
export async function runAgingSweep(env: Env, ctx: ExecutionContext): Promise<void> {
  const startedAt = Date.now();
  const cutoffMs = startedAt - RETENTION_MONTHS * 30.44 * 24 * 60 * 60 * 1000;

  await markIngestStarted(env, 'AGING');

  let agedOut = 0;
  let lastError: string | undefined;

  try {
    // Delete expired CVEs (CASCADE handles child rows).
    const result = await env.DB.prepare(
      `DELETE FROM cve
       WHERE published_at < ?
         AND cve_id NOT IN (
           SELECT cve_id FROM cve_state WHERE kev_listed = 1
         )`,
    )
      .bind(cutoffMs)
      .run();

    agedOut = result.meta.changes ?? 0;

    // Tail-purge operational tables.
    const quotaCutoffDay = isoDay(new Date(startedAt - QUOTA_RETENTION_DAYS * 86400000));
    const auditCutoffMs = startedAt - AUDIT_RETENTION_DAYS * 86400000;

    await env.DB.batch([
      env.DB.prepare('DELETE FROM search_quota_ledger WHERE day < ?').bind(quotaCutoffDay),
      env.DB.prepare('DELETE FROM search_quota_ip_ledger WHERE bucket < ?').bind(quotaCutoffDay),
      env.DB.prepare('DELETE FROM audit_log WHERE occurred_at < ?').bind(auditCutoffMs),
      env.DB.prepare('DELETE FROM cve_quarantine WHERE quarantined_at < ?').bind(auditCutoffMs),
    ]);

    // Rebuild cpe_search FTS after bulk delete (one-shot cheaper than per-row trigger).
    await env.DB.batch([
      env.DB.prepare('DELETE FROM cpe_search'),
      env.DB.prepare(
        `INSERT INTO cpe_search (vendor, product)
         SELECT DISTINCT vendor, product FROM cpe`,
      ),
    ]);

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

    // Invalidate dashboard KPI cache keys.
    ctx.waitUntil(
      Promise.all([
        env.CACHE.delete('dash:kpi:total'),
        env.CACHE.delete('dash:kpi:severity'),
        env.CACHE.delete('dash:kpi:kev'),
        env.CACHE.delete('dash:kpi:epss'),
      ]),
    );
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
