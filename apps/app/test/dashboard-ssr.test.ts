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
