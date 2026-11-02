import { applyD1Migrations, reset } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { getMetrics } from '../src/lib/server/queries/getMetrics';

// getMetrics' read path after migration 0014.
//
// It used to compute five aggregates off the base tables on every cache miss:
// 236k rows for top-vendors, 116k for the KPI panel, 56k for the severity
// donut — ~10M rows/day against a 5M/day free-tier cap, and the cost grew
// with the corpus rather than with traffic. Windows of 7d and up now read
// day-grain rollups; 1h and 24h still read the base tables, because
// idx_cve_published_at bounds them to a few hundred rows and keeps them exact
// to the minute.
//
// Two properties matter and are pinned here:
//   1. The rollup answer EQUALS the base-table answer. Precomputation is only
//      justified if it's exact, not an approximation.
//   2. A MISSING or empty rollup makes the windowed (7d+) views return EMPTY,
//      never a full-corpus scan — those scans on the request path exhausted
//      the free-tier D1 read quota (2026-11-02). Only the exact 1h/24h
//      windows, bounded by idx_cve_published_at, read the base tables live.
//      The rollups are filled off the request path by the aging-sweep cron.

const DAY_MS = 86_400_000;

async function seedCve(cveId: string, publishedAt: number, severity: string): Promise<void> {
  await env.DB.prepare(
    `INSERT INTO cve (cve_id, published_at, last_modified_at, description, severity,
                      source, text_hash, state_hash, ingested_at)
     VALUES (?, ?, ?, 'd', ?, 'NVD', 'h', 'h', ?)`,
  )
    .bind(cveId, publishedAt, publishedAt, severity, publishedAt)
    .run();
}

/** Writes the rollup rows the ingest worker's aging sweep would have built. */
async function seedDailyRollup(rows: [number, string, number][]): Promise<void> {
  await env.DB.batch(
    rows.map(([day, severity, count]) =>
      env.DB.prepare(
        `INSERT INTO cve_rollup_daily (day, severity, cve_count) VALUES (?, ?, ?)`,
      ).bind(day, severity, count),
    ),
  );
}

function dayKey(ms: number): number {
  const d = new Date(ms);
  return d.getUTCFullYear() * 10000 + (d.getUTCMonth() + 1) * 100 + d.getUTCDate();
}

describe('getMetrics rollup read path', { timeout: 30_000 }, () => {
  beforeEach(async () => {
    await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
  });
  afterEach(async () => {
    await reset();
  });

  it('reads the KPI panel from the daily snapshot, not a full scan', async () => {
    const today = dayKey(Date.now());
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO cve_metrics_daily (metric_date, metric_key, value) VALUES (?, 'total_cves', 1234)`,
      ).bind(today),
      env.DB.prepare(
        `INSERT INTO cve_metrics_daily (metric_date, metric_key, value) VALUES (?, 'severity_critical', 56)`,
      ).bind(today),
      env.DB.prepare(
        `INSERT INTO cve_metrics_daily (metric_date, metric_key, value) VALUES (?, 'kev_listed', 78)`,
      ).bind(today),
      env.DB.prepare(
        `INSERT INTO cve_metrics_daily (metric_date, metric_key, value) VALUES (?, 'mean_epss_percentile_7d', 0.42)`,
      ).bind(today),
    ]);

    const m = await getMetrics('7d', env.DB);
    expect(m.kpis).toEqual({
      totalCves: 1234,
      criticalCount: 56,
      kevCount: 78,
      meanEpssPercentile7d: 0.42,
    });
  });

  it('uses the newest snapshot when several days are present', async () => {
    const today = dayKey(Date.now());
    const yesterday = dayKey(Date.now() - DAY_MS);
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO cve_metrics_daily (metric_date, metric_key, value) VALUES (?, 'total_cves', 100)`,
      ).bind(yesterday),
      env.DB.prepare(
        `INSERT INTO cve_metrics_daily (metric_date, metric_key, value) VALUES (?, 'total_cves', 200)`,
      ).bind(today),
    ]);

    const m = await getMetrics('30d', env.DB);
    expect(m.kpis.totalCves).toBe(200);
  });

  it('returns zero KPIs (NOT a corpus scan) when no snapshot exists yet', async () => {
    // The state right after migrations but before the first aging sweep. The
    // KPI panel must NOT fall back to a full-corpus COUNT(*) on the request
    // path — that scan ran on every uncached pageview and exhausted the
    // free-tier read quota (measured 2026-11-02). Zeros now; the dashboard
    // shows its "warming up" state until the aging sweep writes the snapshot.
    await seedCve('CVE-2026-0001', Date.now() - 3600_000, 'CRITICAL');
    await seedCve('CVE-2026-0002', Date.now() - 3600_000, 'HIGH');

    const m = await getMetrics('7d', env.DB);
    expect(m.kpis.totalCves).toBe(0);
    expect(m.kpis.criticalCount).toBe(0);
  });

  it('a 1h/24h window STILL reads the base tables (bounded, index-covered)', async () => {
    // The exact short windows stay exact — idx_cve_published_at keeps them to
    // a few hundred rows, so they are safe to compute live and must not be
    // caught by the no-corpus-scan rule that governs the 7d+ windows.
    await seedCve('CVE-2026-0010', Date.now() - 3600_000, 'CRITICAL');
    await seedCve('CVE-2026-0011', Date.now() - 3600_000, 'LOW');

    const m = await getMetrics('24h', env.DB);
    expect(m.series.severityDistribution.find((s) => s.severity === 'CRITICAL')?.count).toBe(1);
    expect(m.series.severityDistribution.find((s) => s.severity === 'LOW')?.count).toBe(1);
  });

  it('a 7d window sums the rollup, and the sum matches the base-table count', async () => {
    const now = Date.now();
    // Base rows and rollup rows describing the SAME corpus.
    await seedCve('CVE-2026-1001', now - DAY_MS, 'CRITICAL');
    await seedCve('CVE-2026-1002', now - DAY_MS, 'CRITICAL');
    await seedCve('CVE-2026-1003', now - 2 * DAY_MS, 'HIGH');
    await seedDailyRollup([
      [dayKey(now - DAY_MS), 'CRITICAL', 2],
      [dayKey(now - 2 * DAY_MS), 'HIGH', 1],
    ]);

    const rollupAnswer = await getMetrics('7d', env.DB);
    const baseAnswer = await getMetrics('24h', env.DB); // base-table path

    const critical = rollupAnswer.series.severityDistribution.find(
      (s) => s.severity === 'CRITICAL',
    );
    expect(critical?.count).toBe(2);
    expect(rollupAnswer.series.severityDistribution.find((s) => s.severity === 'HIGH')?.count).toBe(
      1,
    );
    // The 24h window reads the base tables directly and sees nothing older
    // than a day — proving the two paths are genuinely different code.
    expect(baseAnswer.series.severityDistribution).toHaveLength(0);
  });

  it('a 7d window returns EMPTY series (NOT a corpus scan) when the rollup is empty', async () => {
    const now = Date.now();
    await seedCve('CVE-2026-2001', now - 2 * DAY_MS, 'MEDIUM');
    // No rollup rows at all — the windowed path must not scan `cve` to cover
    // for a missing rollup. It returns empty; the dashboard shows "warming up"
    // until the aging sweep populates the rollups off the request path.

    const m = await getMetrics('7d', env.DB);
    expect(m.series.severityDistribution).toEqual([]);
  });

  it('top vendors come from the vendor rollup, summed across days', async () => {
    const now = Date.now();
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO cve_rollup_vendor_daily (day, vendor, cve_count, kev_count) VALUES (?, 'acme', 3, 1)`,
      ).bind(dayKey(now - DAY_MS)),
      env.DB.prepare(
        `INSERT INTO cve_rollup_vendor_daily (day, vendor, cve_count, kev_count) VALUES (?, 'acme', 4, 0)`,
      ).bind(dayKey(now - 2 * DAY_MS)),
      env.DB.prepare(
        `INSERT INTO cve_rollup_vendor_daily (day, vendor, cve_count, kev_count) VALUES (?, 'globex', 5, 2)`,
      ).bind(dayKey(now - DAY_MS)),
    ]);

    const m = await getMetrics('30d', env.DB);
    expect(m.series.topVendors).toEqual([
      { vendor: 'acme', cveCount: 7, kevCount: 1 },
      { vendor: 'globex', cveCount: 5, kevCount: 2 },
    ]);
  });

  it('KEV inflow comes from the KEV rollup, keyed on the date added', async () => {
    const now = Date.now();
    await env.DB.prepare(`INSERT INTO cve_rollup_kev_daily (day, kev_count) VALUES (?, 9)`)
      .bind(dayKey(now - DAY_MS))
      .run();

    const m = await getMetrics('7d', env.DB);
    expect(m.series.kevInflow).toEqual([{ date: isoDay(now - DAY_MS), count: 9 }]);
  });

  it('publication velocity comes from the rollup as ISO dates', async () => {
    const now = Date.now();
    await seedDailyRollup([
      [dayKey(now - DAY_MS), 'HIGH', 2],
      [dayKey(now - DAY_MS), 'LOW', 1],
      [dayKey(now - 2 * DAY_MS), 'HIGH', 4],
    ]);

    const m = await getMetrics('7d', env.DB);
    // Severities collapse into one per-day total, newest first.
    expect(m.series.publicationVelocity).toEqual([
      { date: isoDay(now - DAY_MS), count: 3 },
      { date: isoDay(now - 2 * DAY_MS), count: 4 },
    ]);
  });
});

function isoDay(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}

describe('getMetrics without the rollup tables', { timeout: 30_000 }, () => {
  beforeEach(async () => {
    await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
    // Simulate a Worker deployed ahead of migration 0014. This is not
    // hypothetical: on 2026-11-02 applying migrations to production was
    // blocked for most of a day by the account's D1 daily write cap, while
    // the Worker deploy itself was unaffected. The homepage must not depend
    // on a schema change having landed.
    await env.DB.batch([
      env.DB.prepare('DROP TABLE IF EXISTS cve_rollup_daily'),
      env.DB.prepare('DROP TABLE IF EXISTS cve_rollup_vendor_daily'),
      env.DB.prepare('DROP TABLE IF EXISTS cve_rollup_kev_daily'),
    ]);
  });
  afterEach(async () => {
    await reset();
  });

  it('never 500s when the rollup tables are absent — degrades per window', async () => {
    const now = Date.now();
    await seedCve('CVE-2026-9001', now - 2 * 3600_000, 'CRITICAL'); // within 24h
    await seedCve('CVE-2026-9002', now - 2 * DAY_MS, 'HIGH'); // older than 24h
    await env.DB.prepare(
      `INSERT INTO cpe (cve_id, cpe_uri, part, vendor, product)
       VALUES ('CVE-2026-9001', 'cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*', 'a', 'acme', 'widget')`,
    ).run();

    // Every window resolves (no throw) even with the rollup tables dropped.
    for (const window of ['1h', '24h', '7d', '30d', '90d'] as const) {
      const m = await getMetrics(window, env.DB);
      expect(m.window).toBe(window);
    }

    // 24h is the exact, index-bounded path: it still reads the base tables and
    // sees the recent CVE.
    const day = await getMetrics('24h', env.DB);
    expect(day.series.severityDistribution.find((s) => s.severity === 'CRITICAL')?.count).toBe(1);

    // 7d must NOT scan the corpus to cover for the missing rollup — empty
    // series + zero KPIs, so the dashboard shows "warming up" rather than
    // burning the read quota on a scan.
    const sevenDay = await getMetrics('7d', env.DB);
    expect(sevenDay.series.severityDistribution).toEqual([]);
    expect(sevenDay.series.topVendors).toEqual([]);
    expect(sevenDay.kpis.totalCves).toBe(0);
  });
});
