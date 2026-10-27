import type { MetricsResponse, MetricsWindow, MetricsSeries, MetricsKpis } from '@threat-lens/contracts';

const WINDOW_DAYS: Record<MetricsWindow, number> = {
  '1h': 1,
  '24h': 1,
  '7d': 7,
  '30d': 30,
  '90d': 90,
};

interface SeverityRow { severity: string; count: number }
interface VelocityRow { date: string; count: number }
interface VendorRow { vendor: string; cve_count: number; kev_count: number }
interface KevInflowRow { date: string; count: number }
interface KpiRow {
  total_cves: number;
  critical_count: number;
  kev_count: number;
  mean_epss_7d: number | null;
}

export async function getMetrics(window: MetricsWindow, db: D1Database): Promise<MetricsResponse> {
  const now = Date.now();
  const days = WINDOW_DAYS[window];
  const cutoffMs = window === '1h'
    ? now - 60 * 60 * 1000
    : now - days * 86_400_000;
  const sevenDaysCutoffMs = now - 7 * 86_400_000;

  const [kpiResult, severityResult, velocityResult, vendorResult, kevInflowResult] =
    await Promise.all([
      db.prepare(
        `SELECT
           COUNT(*)                                                     AS total_cves,
           SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END)      AS critical_count,
           (SELECT COUNT(*) FROM cve_state WHERE kev_listed = 1)        AS kev_count,
           (SELECT AVG(epss_percentile) FROM cve_state
            WHERE epss_percentile IS NOT NULL
              AND epss_updated_at > ?)                                  AS mean_epss_7d
         FROM cve`,
      ).bind(sevenDaysCutoffMs).first<KpiRow>(),

      db.prepare(
        `SELECT severity, COUNT(*) AS count
         FROM cve
         WHERE published_at > ?
         GROUP BY severity ORDER BY count DESC`,
      ).bind(cutoffMs).all<SeverityRow>(),

      db.prepare(
        `SELECT DATE(published_at / 1000, 'unixepoch') AS date, COUNT(*) AS count
         FROM cve
         WHERE published_at > ?
         GROUP BY date ORDER BY date DESC
         LIMIT ?`,
      ).bind(cutoffMs, days + 1).all<VelocityRow>(),

      db.prepare(
        `SELECT p.vendor,
                COUNT(DISTINCT p.cve_id)                                          AS cve_count,
                SUM(CASE WHEN s.kev_listed = 1 THEN 1 ELSE 0 END)                AS kev_count
         FROM cpe p
         JOIN cve c USING (cve_id)
         LEFT JOIN cve_state s USING (cve_id)
         WHERE c.published_at > ?
         GROUP BY p.vendor
         ORDER BY cve_count DESC
         LIMIT 10`,
      ).bind(cutoffMs).all<VendorRow>(),

      db.prepare(
        `SELECT DATE(s.kev_date_added / 1000, 'unixepoch') AS date, COUNT(*) AS count
         FROM cve_state s
         WHERE s.kev_listed = 1 AND s.kev_date_added > ?
         GROUP BY date ORDER BY date DESC
         LIMIT ?`,
      ).bind(cutoffMs, days + 1).all<KevInflowRow>(),
    ]);

  const kpis: MetricsKpis = {
    totalCves: kpiResult?.total_cves ?? 0,
    criticalCount: kpiResult?.critical_count ?? 0,
    kevCount: kpiResult?.kev_count ?? 0,
    meanEpssPercentile7d: kpiResult?.mean_epss_7d ?? 0,
  };

  const series: MetricsSeries = {
    severityDistribution: (severityResult.results ?? []).map(r => ({
      severity: r.severity as MetricsSeries['severityDistribution'][0]['severity'],
      count: r.count,
    })),
    publicationVelocity: velocityResult.results ?? [],
    topVendors: (vendorResult.results ?? []).map(r => ({
      vendor: r.vendor,
      cveCount: r.cve_count,
      kevCount: r.kev_count,
    })),
    kevInflow: kevInflowResult.results ?? [],
  };

  return {
    window,
    generatedAt: new Date(now).toISOString(),
    kpis,
    series,
  };
}
