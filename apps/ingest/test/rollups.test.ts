import { describe, expect, it } from 'vitest';
import { dayKey, rebuildAllRollups, refreshRecentRollups } from '../src/lib/server/rollups';
import { spyOnBindings, testEnv, useCleanBindings } from './helpers';

// Day-grain dashboard rollups (migration 0014 / lib/server/rollups.ts).
//
// These exist because getMetrics() was computing the same five aggregates off
// the base tables on every cache miss — 236k rows for top-vendors, 116k for
// the KPI panel, 56k for the severity donut, ~10M rows/day in total against a
// 5M/day free-tier cap. The rollups must be EXACT, not approximate: the whole
// argument for precomputing is that a sum over day buckets equals the same
// count taken from the base rows. That exactness is what's pinned here.

const DAY_MS = 86_400_000;

async function seedCve(cveId: string, publishedAt: number, severity = 'HIGH'): Promise<void> {
  await testEnv.DB.prepare(
    `INSERT INTO cve
       (cve_id, published_at, last_modified_at, description, severity, source,
        text_hash, state_hash, ingested_at)
     VALUES (?, ?, ?, 'd', ?, 'NVD', 'h', 'h', ?)`,
  )
    .bind(cveId, publishedAt, publishedAt, severity, publishedAt)
    .run();
}

async function seedCpe(cveId: string, vendor: string, product: string): Promise<void> {
  await testEnv.DB.prepare(
    `INSERT INTO cpe (cve_id, cpe_uri, part, vendor, product) VALUES (?, ?, 'a', ?, ?)`,
  )
    .bind(cveId, `cpe:2.3:a:${vendor}:${product}:*:*:*:*:*:*:*:*`, vendor, product)
    .run();
}

async function seedKev(cveId: string, kevDateAdded: number): Promise<void> {
  await testEnv.DB.prepare(
    `INSERT INTO cve_state (cve_id, kev_listed, kev_date_added, state_updated_at)
     VALUES (?, 1, ?, ?)
     ON CONFLICT (cve_id) DO UPDATE SET kev_listed = 1, kev_date_added = excluded.kev_date_added`,
  )
    .bind(cveId, kevDateAdded, kevDateAdded)
    .run();
}

describe('dashboard rollups', () => {
  useCleanBindings();

  it('counts published CVEs by day and severity, exactly', async () => {
    const now = Date.UTC(2026, 9, 31, 12, 0, 0); // 2026-10-31
    const yesterday = now - DAY_MS;

    await seedCve('CVE-2026-0001', now, 'CRITICAL');
    await seedCve('CVE-2026-0002', now, 'CRITICAL');
    await seedCve('CVE-2026-0003', now, 'LOW');
    await seedCve('CVE-2026-0004', yesterday, 'CRITICAL');

    await rebuildAllRollups(testEnv, now);

    const rows = await testEnv.DB.prepare(
      `SELECT day, severity, cve_count FROM cve_rollup_daily ORDER BY day, severity`,
    ).all<{ day: number; severity: string; cve_count: number }>();

    expect(rows.results).toEqual([
      { day: 20261030, severity: 'CRITICAL', cve_count: 1 },
      { day: 20261031, severity: 'CRITICAL', cve_count: 2 },
      { day: 20261031, severity: 'LOW', cve_count: 1 },
    ]);
  });

  it('a full rebuild SHRINKS a bucket when a severity moves — not just grows it', async () => {
    // The reason the builders delete-then-insert instead of upserting alone.
    // An upsert-only pass would leave 'HIGH': 1 behind forever.
    const now = Date.UTC(2026, 9, 31, 12, 0, 0);
    await seedCve('CVE-2026-1001', now, 'HIGH');
    await rebuildAllRollups(testEnv, now);

    await testEnv.DB.prepare(`UPDATE cve SET severity = 'CRITICAL' WHERE cve_id = ?`)
      .bind('CVE-2026-1001')
      .run();
    await rebuildAllRollups(testEnv, now);

    const rows = await testEnv.DB.prepare(
      `SELECT severity, cve_count FROM cve_rollup_daily ORDER BY severity`,
    ).all<{ severity: string; cve_count: number }>();
    expect(rows.results).toEqual([{ severity: 'CRITICAL', cve_count: 1 }]);
  });

  it('a full rebuild drops days whose CVEs are gone', async () => {
    const now = Date.UTC(2026, 9, 31, 12, 0, 0);
    await seedCve('CVE-2026-1101', now - DAY_MS);
    await rebuildAllRollups(testEnv, now);
    expect(
      (
        await testEnv.DB.prepare(`SELECT COUNT(*) AS n FROM cve_rollup_daily`).first<{
          n: number;
        }>()
      )?.n,
    ).toBe(1);

    await testEnv.DB.prepare(`DELETE FROM cve WHERE cve_id = ?`).bind('CVE-2026-1101').run();
    await rebuildAllRollups(testEnv, now);

    expect(
      (
        await testEnv.DB.prepare(`SELECT COUNT(*) AS n FROM cve_rollup_daily`).first<{
          n: number;
        }>()
      )?.n,
    ).toBe(0);
  });

  it('counts vendor exposure per day, deduping a vendor with several CPE rows on one CVE', async () => {
    const now = Date.UTC(2026, 9, 31, 12, 0, 0);
    await seedCve('CVE-2026-2001', now);
    // Same vendor twice on one CVE — must count as ONE affected CVE, which is
    // why the builder uses COUNT(DISTINCT cve_id).
    await seedCpe('CVE-2026-2001', 'acme', 'widget');
    await seedCpe('CVE-2026-2001', 'acme', 'gadget');
    await seedCve('CVE-2026-2002', now);
    await seedCpe('CVE-2026-2002', 'acme', 'widget');
    await seedCve('CVE-2026-2003', now);
    await seedCpe('CVE-2026-2003', 'globex', 'router');
    await seedKev('CVE-2026-2003', now);

    await rebuildAllRollups(testEnv, now);

    const rows = await testEnv.DB.prepare(
      `SELECT vendor, cve_count, kev_count FROM cve_rollup_vendor_daily ORDER BY vendor`,
    ).all<{ vendor: string; cve_count: number; kev_count: number }>();
    expect(rows.results).toEqual([
      { vendor: 'acme', cve_count: 2, kev_count: 0 },
      { vendor: 'globex', cve_count: 1, kev_count: 1 },
    ]);
  });

  it('buckets KEV inflow by kev_date_added, not by published_at', async () => {
    // The distinction the chart exists for: an old CVE entering the KEV
    // catalogue today is today's news.
    const now = Date.UTC(2026, 9, 31, 12, 0, 0);
    await seedCve('CVE-2019-5001', Date.UTC(2019, 0, 15));
    await seedKev('CVE-2019-5001', now);

    await rebuildAllRollups(testEnv, now);

    const rows = await testEnv.DB.prepare(`SELECT day, kev_count FROM cve_rollup_kev_daily`).all<{
      day: number;
      kev_count: number;
    }>();
    expect(rows.results).toEqual([{ day: 20261031, kev_count: 1 }]);
  });

  it('prunes vendor rows outside the 90-day window', async () => {
    const now = Date.UTC(2026, 9, 31, 12, 0, 0);
    // Plant a stale row directly, as a previous run would have left it.
    await testEnv.DB.prepare(
      `INSERT INTO cve_rollup_vendor_daily (day, vendor, cve_count, kev_count)
       VALUES (?, 'ancient', 5, 0)`,
    )
      .bind(dayKey(now - 200 * DAY_MS))
      .run();

    await rebuildAllRollups(testEnv, now);

    const left = await testEnv.DB.prepare(
      `SELECT COUNT(*) AS n FROM cve_rollup_vendor_daily WHERE vendor = 'ancient'`,
    ).first<{ n: number }>();
    expect(left?.n).toBe(0);
  });

  it('a trailing refresh updates recent days and leaves older buckets alone', async () => {
    const now = Date.UTC(2026, 9, 31, 12, 0, 0);
    const old = now - 30 * DAY_MS;

    await seedCve('CVE-2026-3001', old, 'LOW');
    await rebuildAllRollups(testEnv, now);

    // New CVE today; refresh only looks at the trailing 7 days.
    await seedCve('CVE-2026-3002', now, 'CRITICAL');
    await refreshRecentRollups(testEnv, now);

    const rows = await testEnv.DB.prepare(
      `SELECT day, severity, cve_count FROM cve_rollup_daily ORDER BY day`,
    ).all<{ day: number; severity: string; cve_count: number }>();
    expect(rows.results).toEqual([
      { day: dayKey(old), severity: 'LOW', cve_count: 1 }, // untouched
      { day: 20261031, severity: 'CRITICAL', cve_count: 1 }, // picked up
    ]);
  });

  it('records build bookkeeping so a stale dashboard is visible', async () => {
    const now = Date.UTC(2026, 9, 31, 12, 0, 0);
    await seedCve('CVE-2026-4001', now);
    await rebuildAllRollups(testEnv, now);

    const state = await testEnv.DB.prepare(
      `SELECT rollup_key, last_full_at, last_status FROM rollup_state ORDER BY rollup_key`,
    ).all<{ rollup_key: string; last_full_at: number; last_status: string }>();
    expect(state.results.map((r) => r.rollup_key)).toEqual(['daily', 'kev_daily', 'vendor_daily']);
    for (const r of state.results) {
      expect(r.last_status).toBe('OK');
      expect(r.last_full_at).toBe(now);
    }
  });
});

describe('rollup D1 query budget', () => {
  useCleanBindings();

  /**
   * A Worker invocation is killed at its 51st D1 query on the Free plan, and
   * the aging sweep has to fit the rollups alongside its deletes and metrics
   * snapshot. The first version of these builders read rows into JS and wrote
   * them back one statement at a time: the ~27k-row vendor rollup needed ~54
   * batched writes on its own and would have died partway through, leaving a
   * half-built rollup. Aggregating in SQL makes each rollup exactly one query
   * regardless of how many buckets it produces — this pins that.
   */
  it('rebuilds every rollup in a handful of queries, independent of bucket count', async () => {
    const now = Date.UTC(2026, 9, 31, 12, 0, 0);

    // 60 CVEs spread over 30 days across 12 vendors: enough buckets that a
    // per-row implementation would be obvious in the count.
    const stmts: D1PreparedStatement[] = [];
    for (let i = 0; i < 60; i++) {
      const cveId = `CVE-2026-${7000 + i}`;
      const published = now - (i % 30) * DAY_MS;
      stmts.push(
        testEnv.DB.prepare(
          `INSERT INTO cve (cve_id, published_at, last_modified_at, description, severity,
                            source, text_hash, state_hash, ingested_at)
           VALUES (?, ?, ?, 'd', ?, 'NVD', 'h', 'h', ?)`,
        ).bind(cveId, published, published, i % 2 === 0 ? 'HIGH' : 'LOW', published),
        testEnv.DB.prepare(
          `INSERT INTO cpe (cve_id, cpe_uri, part, vendor, product) VALUES (?, ?, 'a', ?, 'p')`,
        ).bind(cveId, `cpe:2.3:a:v${i % 12}:p:*:*:*:*:*:*:*:*`, `v${i % 12}`),
      );
    }
    await testEnv.DB.batch(stmts);

    const spies = spyOnBindings();
    spies.clearAll();

    await rebuildAllRollups(testEnv, now);

    // queryCalls (standalone first/run/all) + dbBatch calls = real D1 round
    // trips; see helpers.ts.
    const queries = spies.queryCalls.length + spies.dbBatch.mock.calls.length;
    expect(queries).toBeLessThanOrEqual(10);

    // And it actually produced the buckets, so the low count isn't a no-op.
    const buckets = await testEnv.DB.prepare(
      `SELECT (SELECT COUNT(*) FROM cve_rollup_daily)        AS daily,
              (SELECT COUNT(*) FROM cve_rollup_vendor_daily) AS vendor`,
    ).first<{ daily: number; vendor: number }>();
    // Each day gets CVEs i and i+30, whose indices share a parity, so both
    // land on the same severity: 30 days x 1 severity bucket. Their vendors
    // (i%12 and (i+30)%12) differ, so vendors are 30 days x 2.
    expect(buckets?.daily).toBe(30);
    expect(buckets?.vendor).toBe(60);

    // No bound statement may exceed D1's 100-parameter cap either.
    for (const call of spies.boundCalls) {
      expect(call.paramCount).toBeLessThanOrEqual(100);
    }
  });

  it('rebuilds the vendor rollup over 30 days on an ordinary run, 90 when stale', async () => {
    const now = Date.UTC(2026, 9, 31, 12, 0, 0);

    // No prior state → must do the full 90-day pass to establish the window.
    const first = await rebuildAllRollups(testEnv, now);
    expect(first.vendorFullRebuild).toBe(true);
    expect(first.vendorDays).toBe(90);

    // Next day: a full pass would rewrite ~27k unchanged rows, a quarter of
    // the 100k/day write allowance, so it narrows to the trailing 30 days.
    const second = await rebuildAllRollups(testEnv, now + DAY_MS);
    expect(second.vendorFullRebuild).toBe(false);
    expect(second.vendorDays).toBe(30);

    // A week on, kev_count can have moved for any day in the window, so the
    // full pass is forced again.
    const later = await rebuildAllRollups(testEnv, now + 8 * DAY_MS);
    expect(later.vendorFullRebuild).toBe(true);
    expect(later.vendorDays).toBe(90);
  });
});
