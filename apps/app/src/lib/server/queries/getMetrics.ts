import type {
  MetricsKpis,
  MetricsResponse,
  MetricsSeries,
  MetricsWindow,
} from '@threat-lens/contracts';

/**
 * Dashboard metrics.
 *
 * This used to compute five aggregates straight off the base tables on every
 * cache miss. Measured on production 2026-10-31 (`wrangler d1 insights`):
 * 236k rows for top-vendors, 116k for the KPI panel, 56k for the severity
 * donut — about 10M rows/day at the ~25 cache misses a day the site actually
 * got, against a 5M/day free-tier cap. The cost also scaled with the CORPUS
 * rather than with traffic, so it got worse every month on its own.
 *
 * Now:
 *   - KPI panel reads the daily snapshot in `cve_metrics_daily` (migration
 *     0005) that the aging sweep has always written. The dashboard was
 *     full-scanning `cve` to recompute numbers that were already sitting in a
 *     ten-row table.
 *   - Windows of 7d and up read the day-grain rollups from migration 0014
 *     (hundreds of rows instead of tens of thousands).
 *   - The 1h and 24h windows keep querying the base tables, because at that
 *     size `idx_cve_published_at` bounds them to a few hundred rows — cheaper
 *     than a rollup scan, and exact to the minute.
 *
 * Semantics note: windows of 7d and up are now DAY-ALIGNED (UTC). "7d" means
 * "since the start of the day 7 days ago", not "since this time 7 days ago".
 * That is the grain the rollups store, and for a trend chart it's the better
 * defined window anyway. 1h and 24h are unchanged and exact.
 *
 * Every rollup read falls back to the old base-table query when the rollup is
 * empty, so a deploy that lands before the first post-migration aging sweep
 * shows correct numbers rather than zeros.
 */

const WINDOW_DAYS: Record<MetricsWindow, number> = {
  '1h': 1,
  '24h': 1,
  '7d': 7,
  '30d': 30,
  '90d': 90,
};

/** Windows small enough that the base tables are cheaper than the rollups. */
const EXACT_WINDOWS: ReadonlySet<MetricsWindow> = new Set<MetricsWindow>(['1h', '24h']);

const TOP_VENDOR_LIMIT = 10;

interface SeverityRow {
  severity: string;
  count: number;
}
interface VelocityRow {
  date: string;
  count: number;
}
interface VendorRow {
  vendor: string;
  cve_count: number;
  kev_count: number;
}
interface KevInflowRow {
  date: string;
  count: number;
}

/** unix ms → INTEGER yyyymmdd (UTC). Mirrors rollups.ts's dayKey in ingest. */
function dayKey(ms: number): number {
  const d = new Date(ms);
  return d.getUTCFullYear() * 10000 + (d.getUTCMonth() + 1) * 100 + d.getUTCDate();
}

/** INTEGER yyyymmdd → 'YYYY-MM-DD', the shape the chart series expect. */
function dayKeyToIso(day: number): string {
  const y = Math.floor(day / 10000);
  const m = Math.floor((day % 10000) / 100);
  const d = day % 100;
  return `${y}-${String(m).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
}

export async function getMetrics(window: MetricsWindow, db: D1Database): Promise<MetricsResponse> {
  const now = Date.now();
  const days = WINDOW_DAYS[window];
  const cutoffMs = window === '1h' ? now - 60 * 60 * 1000 : now - days * 86_400_000;
  const useRollups = !EXACT_WINDOWS.has(window);

  const [kpis, severityDistribution, publicationVelocity, topVendors, kevInflow] =
    await Promise.all([
      loadKpis(db, now),
      useRollups ? severityFromRollup(db, cutoffMs) : severityFromBase(db, cutoffMs),
      useRollups ? velocityFromRollup(db, cutoffMs, days) : velocityFromBase(db, cutoffMs, days),
      useRollups ? vendorsFromRollup(db, cutoffMs) : vendorsFromBase(db, cutoffMs),
      useRollups ? kevInflowFromRollup(db, cutoffMs, days) : kevInflowFromBase(db, cutoffMs, days),
    ]);

  const series: MetricsSeries = {
    severityDistribution,
    publicationVelocity,
    topVendors,
    kevInflow,
  };

  return { window, generatedAt: new Date(now).toISOString(), kpis, series };
}

/**
 * Corpus-wide KPI numbers from the aging sweep's daily snapshot. These were
 * never windowed, so a once-a-day snapshot is exactly as accurate as the
 * full-scan version was — the corpus only changes when ingest runs.
 */
async function loadKpis(db: D1Database, now: number): Promise<MetricsKpis> {
  const snapshot = await db
    .prepare(
      `SELECT metric_key, value FROM cve_metrics_daily
       WHERE metric_date = (SELECT MAX(metric_date) FROM cve_metrics_daily)`,
    )
    .all<{ metric_key: string; value: number }>();

  if (snapshot.results.length > 0) {
    const m = new Map(snapshot.results.map((r) => [r.metric_key, r.value]));
    return {
      totalCves: m.get('total_cves') ?? 0,
      criticalCount: m.get('severity_critical') ?? 0,
      kevCount: m.get('kev_listed') ?? 0,
      meanEpssPercentile7d: m.get('mean_epss_percentile_7d') ?? 0,
    };
  }

  // No snapshot yet (fresh database, or deployed before the first sweep).
  // Pay the full scan once rather than render zeros.
  const row = await db
    .prepare(
      `SELECT COUNT(*)                                               AS total_cves,
              SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) AS critical_count,
              (SELECT COUNT(*) FROM cve_state WHERE kev_listed = 1)  AS kev_count,
              (SELECT AVG(epss_percentile) FROM cve_state
               WHERE epss_percentile IS NOT NULL
                 AND epss_updated_at > ?)                            AS mean_epss_7d
       FROM cve`,
    )
    .bind(now - 7 * 86_400_000)
    .first<{
      total_cves: number;
      critical_count: number;
      kev_count: number;
      mean_epss_7d: number | null;
    }>();

  return {
    totalCves: row?.total_cves ?? 0,
    criticalCount: row?.critical_count ?? 0,
    kevCount: row?.kev_count ?? 0,
    meanEpssPercentile7d: row?.mean_epss_7d ?? 0,
  };
}

// ── Severity distribution ────────────────────────────────────────────────────

async function severityFromRollup(
  db: D1Database,
  cutoffMs: number,
): Promise<MetricsSeries['severityDistribution']> {
  const res = await db
    .prepare(
      `SELECT severity, SUM(cve_count) AS count
       FROM cve_rollup_daily WHERE day >= ?
       GROUP BY severity ORDER BY count DESC`,
    )
    .bind(dayKey(cutoffMs))
    .all<SeverityRow>();
  if (res.results.length === 0) return severityFromBase(db, cutoffMs);
  return mapSeverity(res.results);
}

async function severityFromBase(
  db: D1Database,
  cutoffMs: number,
): Promise<MetricsSeries['severityDistribution']> {
  const res = await db
    .prepare(
      `SELECT severity, COUNT(*) AS count
       FROM cve WHERE published_at > ?
       GROUP BY severity ORDER BY count DESC`,
    )
    .bind(cutoffMs)
    .all<SeverityRow>();
  return mapSeverity(res.results ?? []);
}

function mapSeverity(rows: SeverityRow[]): MetricsSeries['severityDistribution'] {
  return rows.map((r) => ({
    severity: r.severity as MetricsSeries['severityDistribution'][0]['severity'],
    count: r.count,
  }));
}

// ── Publication velocity ─────────────────────────────────────────────────────

async function velocityFromRollup(
  db: D1Database,
  cutoffMs: number,
  days: number,
): Promise<VelocityRow[]> {
  const res = await db
    .prepare(
      `SELECT day, SUM(cve_count) AS count
       FROM cve_rollup_daily WHERE day >= ?
       GROUP BY day ORDER BY day DESC LIMIT ?`,
    )
    .bind(dayKey(cutoffMs), days + 1)
    .all<{ day: number; count: number }>();
  if (res.results.length === 0) return velocityFromBase(db, cutoffMs, days);
  return res.results.map((r) => ({ date: dayKeyToIso(r.day), count: r.count }));
}

async function velocityFromBase(
  db: D1Database,
  cutoffMs: number,
  days: number,
): Promise<VelocityRow[]> {
  const res = await db
    .prepare(
      `SELECT DATE(published_at / 1000, 'unixepoch') AS date, COUNT(*) AS count
       FROM cve WHERE published_at > ?
       GROUP BY date ORDER BY date DESC LIMIT ?`,
    )
    .bind(cutoffMs, days + 1)
    .all<VelocityRow>();
  return res.results ?? [];
}

// ── Top vendors ──────────────────────────────────────────────────────────────

async function vendorsFromRollup(
  db: D1Database,
  cutoffMs: number,
): Promise<MetricsSeries['topVendors']> {
  const res = await db
    .prepare(
      `SELECT vendor, SUM(cve_count) AS cve_count, SUM(kev_count) AS kev_count
       FROM cve_rollup_vendor_daily WHERE day >= ?
       GROUP BY vendor ORDER BY cve_count DESC LIMIT ?`,
    )
    .bind(dayKey(cutoffMs), TOP_VENDOR_LIMIT)
    .all<VendorRow>();
  if (res.results.length === 0) return vendorsFromBase(db, cutoffMs);
  return mapVendors(res.results);
}

async function vendorsFromBase(
  db: D1Database,
  cutoffMs: number,
): Promise<MetricsSeries['topVendors']> {
  // Driven from `cve` (not `cpe`) so the published_at index bounds the scan to
  // the window; this only ever runs for 1h/24h, or as the empty-rollup
  // fallback.
  const res = await db
    .prepare(
      `SELECT p.vendor,
              COUNT(DISTINCT p.cve_id)                                        AS cve_count,
              COUNT(DISTINCT CASE WHEN s.kev_listed = 1 THEN p.cve_id END)    AS kev_count
       FROM cve c
       JOIN cpe p ON p.cve_id = c.cve_id
       LEFT JOIN cve_state s ON s.cve_id = c.cve_id
       WHERE c.published_at > ?
       GROUP BY p.vendor
       ORDER BY cve_count DESC
       LIMIT ?`,
    )
    .bind(cutoffMs, TOP_VENDOR_LIMIT)
    .all<VendorRow>();
  return mapVendors(res.results ?? []);
}

function mapVendors(rows: VendorRow[]): MetricsSeries['topVendors'] {
  return rows.map((r) => ({
    vendor: r.vendor,
    cveCount: r.cve_count,
    kevCount: r.kev_count,
  }));
}

// ── KEV inflow ───────────────────────────────────────────────────────────────

async function kevInflowFromRollup(
  db: D1Database,
  cutoffMs: number,
  days: number,
): Promise<KevInflowRow[]> {
  const res = await db
    .prepare(
      `SELECT day, kev_count AS count
       FROM cve_rollup_kev_daily WHERE day >= ?
       ORDER BY day DESC LIMIT ?`,
    )
    .bind(dayKey(cutoffMs), days + 1)
    .all<{ day: number; count: number }>();
  if (res.results.length === 0) return kevInflowFromBase(db, cutoffMs, days);
  return res.results.map((r) => ({ date: dayKeyToIso(r.day), count: r.count }));
}

async function kevInflowFromBase(
  db: D1Database,
  cutoffMs: number,
  days: number,
): Promise<KevInflowRow[]> {
  // idx_state_kev_partial covers this (partial index on kev_date_added WHERE
  // kev_listed = 1), so it reads only KEV rows.
  const res = await db
    .prepare(
      `SELECT DATE(s.kev_date_added / 1000, 'unixepoch') AS date, COUNT(*) AS count
       FROM cve_state s
       WHERE s.kev_listed = 1 AND s.kev_date_added > ?
       GROUP BY date ORDER BY date DESC LIMIT ?`,
    )
    .bind(cutoffMs, days + 1)
    .all<KevInflowRow>();
  return res.results ?? [];
}
