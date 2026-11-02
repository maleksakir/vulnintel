import { applyD1Migrations, reset, SELF } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

// Real server-side render of the dashboard, through the built worker
// (wrangler.toml `main` = .svelte-kit/cloudflare/_worker.js — CI builds
// apps/app before this suite) running in workerd, against real local D1.
//
// Guards two production failure modes a passing `vite build` can't catch:
//  1. Browser-only code (window/document/ResizeObserver, including inside a
//     charting library's internals) executing during SSR and 500ing every
//     request — the 2026-10-28 /search outage.
//  2. LayerChart rendering during SSR at all: measured at ~30–400 ms CPU per
//     request for these charts, against Workers Free's 10 ms limit. The
//     charts must stay client-only islands (ChartIsland.svelte), so the
//     server HTML must contain no LayerChart markup.

const DAY_MS = 86_400_000;
const SEVERITIES = ['CRITICAL', 'HIGH', 'HIGH', 'MEDIUM', 'MEDIUM', 'MEDIUM', 'LOW', null] as const;

async function seedSyntheticCves(count: number): Promise<void> {
  const now = Date.now();
  const statements: D1PreparedStatement[] = [];
  for (let i = 0; i < count; i++) {
    const cveId = `CVE-2026-${90000 + i}`;
    // Spread across ~90 days with gaps, so the zero-fill path runs.
    const publishedAt = now - (i % 30) * 3 * DAY_MS - 3_600_000;
    const kev = i % 5 === 0;
    statements.push(
      env.DB.prepare(
        `INSERT INTO cve (cve_id, published_at, last_modified_at, description, severity,
                          source, text_hash, state_hash, ingested_at)
         VALUES (?, ?, ?, ?, ?, 'NVD', 'synthetic', 'synthetic', ?)`,
      ).bind(
        cveId,
        publishedAt,
        publishedAt,
        `Synthetic test record ${i}`,
        SEVERITIES[i % SEVERITIES.length] ?? null,
        now,
      ),
      env.DB.prepare(
        `INSERT INTO cpe (cve_id, cpe_uri, part, vendor, product)
         VALUES (?, ?, 'a', ?, 'product')`,
      ).bind(cveId, `cpe:2.3:a:vendor${i % 3}:product:*:*:*:*:*:*:*:*`, `vendor${i % 3}`),
      env.DB.prepare(
        `INSERT INTO cve_state (cve_id, kev_listed, kev_date_added, state_updated_at)
         VALUES (?, ?, ?, ?)`,
      ).bind(cveId, kev ? 1 : 0, kev ? publishedAt : null, now),
    );
  }
  await env.DB.batch(statements);
}

/**
 * Populate the dashboard's read sources (day-grain rollups + daily snapshot)
 * FROM the seeded base rows, exactly as the ingest aging-sweep does — same
 * INSERT…SELECT the rollup builder runs (apps/ingest/lib/server/rollups.ts).
 * The dashboard reads only these, never a live corpus scan, so this is the
 * realistic state under test.
 */
async function seedDashboardRollups(): Promise<void> {
  const day = `CAST(strftime('%Y%m%d', published_at / 1000, 'unixepoch') AS INTEGER)`;
  const kevDay = `CAST(strftime('%Y%m%d', kev_date_added / 1000, 'unixepoch') AS INTEGER)`;
  await env.DB.batch([
    env.DB.prepare(
      // COALESCE to 'NONE': production's writeD1 stores a missing severity as
      // 'NONE', never NULL, so the rollup's NOT NULL column never sees null.
      // This synthetic seeder inserts raw NULL severities, so normalize here
      // to match how the real pipeline would have written them.
      `INSERT INTO cve_rollup_daily (day, severity, cve_count)
       SELECT ${day} AS day, COALESCE(severity, 'NONE') AS severity, COUNT(*)
       FROM cve GROUP BY day, COALESCE(severity, 'NONE')`,
    ),
    env.DB.prepare(
      `INSERT INTO cve_rollup_kev_daily (day, kev_count)
       SELECT ${kevDay} AS day, COUNT(*) FROM cve_state
       WHERE kev_listed = 1 AND kev_date_added IS NOT NULL GROUP BY day`,
    ),
    env.DB.prepare(
      `INSERT INTO cve_rollup_vendor_daily (day, vendor, cve_count, kev_count)
       SELECT ${day.replace('published_at', 'c.published_at')} AS day, p.vendor,
              COUNT(DISTINCT p.cve_id),
              COUNT(DISTINCT CASE WHEN s.kev_listed = 1 THEN p.cve_id END)
       FROM cve c JOIN cpe p ON p.cve_id = c.cve_id
       LEFT JOIN cve_state s ON s.cve_id = c.cve_id
       GROUP BY day, p.vendor`,
    ),
  ]);
  // Daily KPI snapshot (the aging sweep writes these keys).
  const today = Number(new Date().toISOString().slice(0, 10).replace(/-/g, ''));
  const counts = await env.DB.prepare(
    `SELECT COUNT(*) AS total,
            SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) AS crit,
            (SELECT COUNT(*) FROM cve_state WHERE kev_listed=1) AS kev
     FROM cve`,
  ).first<{ total: number; crit: number; kev: number }>();
  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO cve_metrics_daily (metric_date, metric_key, value) VALUES (?, 'total_cves', ?)`,
    ).bind(today, counts?.total ?? 0),
    env.DB.prepare(
      `INSERT INTO cve_metrics_daily (metric_date, metric_key, value) VALUES (?, 'severity_critical', ?)`,
    ).bind(today, counts?.crit ?? 0),
    env.DB.prepare(
      `INSERT INTO cve_metrics_daily (metric_date, metric_key, value) VALUES (?, 'kev_listed', ?)`,
    ).bind(today, counts?.kev ?? 0),
  ]);
}

function countMatches(html: string, re: RegExp): number {
  return html.match(re)?.length ?? 0;
}

// The first request in a fresh workerd loads and transforms the whole SSR
// bundle (~2 s locally); the render itself is milliseconds once warm.
describe('dashboard SSR (GET /)', { timeout: 30_000 }, () => {
  beforeEach(async () => {
    await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
  });

  afterEach(async () => {
    await reset();
  });

  it('renders chart placeholders and data tables, but no LayerChart markup', async () => {
    await seedSyntheticCves(40);
    // The dashboard reads the day-grain rollups + the daily snapshot (both
    // written off the request path by the aging sweep), NOT a live corpus
    // scan — so seed those, which is the real state the dashboard renders
    // from. Without them the 90d view correctly shows "warming up".
    await seedDashboardRollups();

    const res = await SELF.fetch('http://localhost/');
    const html = await res.text();

    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toMatch(/text\/html/);
    // Severity, publication velocity, KEV additions: one island each,
    // server-rendered as a skeleton until the client loads the chart.
    expect(countMatches(html, /class="chart-island(\s|")/g)).toBe(3);
    expect(countMatches(html, /class="skeleton chart-island__skeleton/g)).toBe(3);
    // No LayerChart component rendered server-side (CPU budget + SSR safety).
    expect(html).not.toMatch(/\blc-[a-z]/);
    // The accessible tables carry the real numbers in the server HTML,
    // including the NULL-severity row folded into "None".
    expect(html).toContain('<caption>CVEs by severity, last 90 days</caption>');
    for (const label of ['Critical', 'High', 'Medium', 'Low', 'None']) {
      expect(html).toContain(`<th scope="row">${label}</th>`);
    }
    expect(countMatches(html, /<th scope="row">[A-Z][a-z]{2} \d{1,2}, \d{4}<\/th>/g)).toBe(2 * 91);
  });

  it('renders empty states, not islands or a 500, when D1 has no rows', async () => {
    const res = await SELF.fetch('http://localhost/');
    const html = await res.text();

    expect(res.status).toBe(200);
    expect(countMatches(html, /class="chart-island(\s|")/g)).toBe(0);
    expect(html).toContain('No KEV additions in this window.');
  });
});
