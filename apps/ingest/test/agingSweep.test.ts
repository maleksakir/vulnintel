import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { runAgingSweep } from '../src/pipelines/aging';
import { spyOnBindings, testEnv, useCleanBindings } from './helpers';

// Aging sweep — dashboard cache-key invalidation, FTS cleanup, rollups.
//
// The sweep used to delete `dash:kpi:total|severity|kev|epss` after pruning
// aged-out CVEs. Nothing in the app ever writes those keys — the dashboard
// metrics are cached under `dash:metrics:<window>` (see the app's
// /api/metrics route and homepage loader). So the real metrics cache was
// NEVER event-invalidated (it relied solely on its 300s TTL) and the four
// deletes were pure waste against the 1,000/day KV write+delete cap. These
// guard the corrected keys.
//
// The invalidation is no longer conditional on `agedOut > 0`. It was, back
// when the only thing a sweep changed was which CVEs existed. As of migration
// 0014 this run also REBUILDS the day-grain rollups that getMetrics reads, so
// every run changes the numbers behind those keys — a run that aged nothing
// out still picks up whatever ingest landed that day. Five deletes once a day
// is nothing against the 1,000/day KV cap; the original bug was four deletes
// 4x/day against keys no writer ever used.

const TWENTY_SIX_MONTHS_MS = 26 * 30.44 * 24 * 60 * 60 * 1000;
const METRICS_KEYS = [
  'dash:metrics:1h',
  'dash:metrics:24h',
  'dash:metrics:7d',
  'dash:metrics:30d',
  'dash:metrics:90d',
];

/** Inserts a cve row with an explicit published_at (seedCveRow hardcodes now). */
async function seedAgedCve(cveId: string, publishedAt: number): Promise<void> {
  await testEnv.DB.prepare(
    `INSERT INTO cve
       (cve_id, published_at, last_modified_at, description, severity, source,
        text_hash, state_hash, ingested_at)
     VALUES (?, ?, ?, 'old record', 'HIGH', 'NVD', 'h', 'h', ?)`,
  )
    .bind(cveId, publishedAt, publishedAt, Date.now())
    .run();
}

describe('runAgingSweep cache invalidation', () => {
  useCleanBindings();

  it('a run that deletes aged-out CVEs invalidates the real dash:metrics:* keys and never the dead dash:kpi:* keys', async () => {
    const oldPublished = Date.now() - TWENTY_SIX_MONTHS_MS;
    await seedAgedCve('CVE-2023-0001', oldPublished);
    await seedAgedCve('CVE-2023-0002', oldPublished);

    const spies = spyOnBindings();
    const ctx = createExecutionContext();
    await runAgingSweep(testEnv, ctx);
    await waitOnExecutionContext(ctx);

    const deletedKeys = spies.cacheDelete.mock.calls.map(([k]) => k);

    // Every real metrics key is invalidated.
    for (const key of METRICS_KEYS) {
      expect(deletedKeys).toContain(key);
    }
    // None of the dead dash:kpi:* keys are touched anymore.
    expect(deletedKeys.some((k) => k.startsWith('dash:kpi:'))).toBe(false);

    // The aged-out rows are actually gone.
    const remaining = await testEnv.DB.prepare('SELECT COUNT(*) AS n FROM cve').first<{
      n: number;
    }>();
    expect(remaining?.n).toBe(0);
  });

  it('a run that ages nothing out still invalidates, because it rebuilt the rollups', async () => {
    // A fresh, in-window CVE: not eligible for deletion, but it IS new data
    // the rollups (and therefore the dashboard) must reflect.
    await seedAgedCve('CVE-2026-0001', Date.now());

    const spies = spyOnBindings();
    const ctx = createExecutionContext();
    await runAgingSweep(testEnv, ctx);
    await waitOnExecutionContext(ctx);

    const deletedKeys = spies.cacheDelete.mock.calls.map(([k]) => k);
    for (const key of METRICS_KEYS) {
      expect(deletedKeys).toContain(key);
    }
    // Exactly the five metrics keys — no stray deletes burning the KV cap.
    expect(deletedKeys).toHaveLength(METRICS_KEYS.length);

    const remaining = await testEnv.DB.prepare('SELECT COUNT(*) AS n FROM cve').first<{
      n: number;
    }>();
    expect(remaining?.n).toBe(1);

    // And the rollup actually describes that CVE.
    const rollup = await testEnv.DB.prepare(
      `SELECT severity, cve_count FROM cve_rollup_daily`,
    ).all<{ severity: string; cve_count: number }>();
    expect(rollup.results).toEqual([{ severity: 'HIGH', cve_count: 1 }]);
  });

  it('a KEV-listed aged CVE is exempt from deletion (and so triggers no invalidation)', async () => {
    const oldPublished = Date.now() - TWENTY_SIX_MONTHS_MS;
    await seedAgedCve('CVE-2023-9999', oldPublished);
    await testEnv.DB.prepare(
      `INSERT INTO cve_state (cve_id, kev_listed, kev_date_added, kev_required_action, state_updated_at)
       VALUES (?, 1, ?, 'Patch', ?)`,
    )
      .bind('CVE-2023-9999', oldPublished, Date.now())
      .run();

    const spies = spyOnBindings();
    const ctx = createExecutionContext();
    await runAgingSweep(testEnv, ctx);
    await waitOnExecutionContext(ctx);

    const remaining = await testEnv.DB.prepare('SELECT COUNT(*) AS n FROM cve').first<{
      n: number;
    }>();
    expect(remaining?.n).toBe(1); // KEV-exempt, retained

    // Invalidation still happens (the rollups were rebuilt), and the KEV
    // inflow rollup picked the CVE up by its kev_date_added day.
    expect(spies.cacheDelete.mock.calls.map(([k]) => k)).toEqual(
      expect.arrayContaining(METRICS_KEYS),
    );
    const kevRollup = await testEnv.DB.prepare(
      `SELECT SUM(kev_count) AS n FROM cve_rollup_kev_daily`,
    ).first<{ n: number | null }>();
    expect(kevRollup?.n).toBe(1);
  });
});

describe('runAgingSweep orphaned match sweep', () => {
  useCleanBindings();

  /**
   * watchlist_match.cve_id and asset_component_match.cve_id are deliberately
   * NOT foreign keys (migrations 0009/0011), so the CVE hard-delete at the top
   * of the sweep leaves them behind. Both migrations say this tail sweeps
   * them; it didn't, so they accumulated against a 500MB D1 cap that a DELETE
   * cannot reclaim.
   */
  it('prunes orphaned watchlist_match rows, except ones an analyst is mid-triage on', async () => {
    const oldPublished = Date.now() - TWENTY_SIX_MONTHS_MS;
    const now = Date.now();
    await seedAgedCve('CVE-2023-7001', oldPublished);
    await testEnv.DB.prepare(
      `INSERT INTO watchlist (watchlist_id, name, created_at, updated_at) VALUES (1, 'w', ?, ?)`,
    )
      .bind(now, now)
      .run();

    // Four matches on the same (about to be deleted) CVE-less state: one per
    // status that matters. Statuses live on separate CVEs so each is distinct.
    for (const [cveId, status] of [
      ['CVE-2019-0001', 'NEW'],
      ['CVE-2019-0002', 'RESOLVED'],
      ['CVE-2019-0003', 'IGNORED'],
      ['CVE-2019-0004', 'TRIAGING'],
      ['CVE-2019-0005', 'ACKNOWLEDGED'],
    ] as const) {
      await testEnv.DB.prepare(
        `INSERT INTO watchlist_match (watchlist_id, cve_id, status, first_matched_at, status_updated_at)
         VALUES (1, ?, ?, ?, ?)`,
      )
        .bind(cveId, status, now, now)
        .run();
    }

    const ctx = createExecutionContext();
    await runAgingSweep(testEnv, ctx);
    await waitOnExecutionContext(ctx);

    const left = await testEnv.DB.prepare(
      `SELECT cve_id FROM watchlist_match ORDER BY cve_id`,
    ).all<{ cve_id: string }>();
    // NEW (nobody looked) and the terminal statuses go; in-flight triage
    // survives, which is the entire reason cve_id isn't a foreign key.
    expect(left.results.map((r) => r.cve_id)).toEqual(['CVE-2019-0004', 'CVE-2019-0005']);
  });

  it('prunes orphaned asset_component_match rows', async () => {
    const now = Date.now();
    await seedAgedCve('CVE-2026-8001', now); // in-window, stays
    await testEnv.DB.batch([
      testEnv.DB.prepare(
        `INSERT INTO asset (asset_id, name, created_at, updated_at, last_component_count)
         VALUES (1, 'app', ?, ?, 1)`,
      ).bind(now, now),
      testEnv.DB.prepare(
        `INSERT INTO asset_component (component_id, asset_id, name, created_at)
         VALUES (1, 1, 'lib', ?)`,
      ).bind(now),
      // One match to a live CVE, one to a CVE that no longer exists.
      testEnv.DB.prepare(
        `INSERT INTO asset_component_match (component_id, cve_id, match_via, first_matched_at)
         VALUES (1, 'CVE-2026-8001', 'PURL', ?)`,
      ).bind(now),
      testEnv.DB.prepare(
        `INSERT INTO asset_component_match (component_id, cve_id, match_via, first_matched_at)
         VALUES (1, 'CVE-2018-9999', 'PURL', ?)`,
      ).bind(now),
    ]);

    const ctx = createExecutionContext();
    await runAgingSweep(testEnv, ctx);
    await waitOnExecutionContext(ctx);

    const left = await testEnv.DB.prepare(
      `SELECT cve_id FROM asset_component_match ORDER BY cve_id`,
    ).all<{ cve_id: string }>();
    expect(left.results.map((r) => r.cve_id)).toEqual(['CVE-2026-8001']);
  });
});

describe('runAgingSweep D1 query budget', () => {
  useCleanBindings();

  /**
   * The Free plan kills a Worker invocation at its 51st D1 query. This sweep
   * previously allowed 50 delete batches on its own, before the tail purge,
   * the FTS rebuild and the metrics snapshot — so on any run with a real
   * backlog everything after the deletes was unreachable, which (together
   * with the per-row FTS delete trigger that migration 0013 removed) is why
   * this job never completed for ~2 months while `ingest_run` kept reporting
   * a stale OK.
   */
  it('stays under the 50-query invocation cap with a full delete backlog', async () => {
    const oldPublished = Date.now() - TWENTY_SIX_MONTHS_MS;
    // More aged CVEs than one run's delete allowance, to force every batch.
    const stmts: D1PreparedStatement[] = [];
    for (let i = 0; i < 40; i++) {
      stmts.push(
        testEnv.DB.prepare(
          `INSERT INTO cve (cve_id, published_at, last_modified_at, description, severity,
                            source, text_hash, state_hash, ingested_at)
           VALUES (?, ?, ?, 'old', 'HIGH', 'NVD', 'h', 'h', ?)`,
        ).bind(`CVE-2023-${8000 + i}`, oldPublished, oldPublished, Date.now()),
      );
    }
    await testEnv.DB.batch(stmts);

    const spies = spyOnBindings();
    spies.clearAll();

    const ctx = createExecutionContext();
    await runAgingSweep(testEnv, ctx);
    await waitOnExecutionContext(ctx);

    const queries = spies.queryCalls.length + spies.dbBatch.mock.calls.length;
    expect(queries).toBeLessThan(50);

    // The run reached completion: deletes AND the rollup rebuild AND the
    // metrics snapshot all happened, which is the whole point of the budget.
    const remaining = await testEnv.DB.prepare('SELECT COUNT(*) AS n FROM cve').first<{
      n: number;
    }>();
    expect(remaining?.n).toBe(0);

    const rollupState = await testEnv.DB.prepare(
      `SELECT COUNT(*) AS n FROM rollup_state WHERE last_status = 'OK'`,
    ).first<{ n: number }>();
    expect(rollupState?.n).toBe(3);

    const snapshot = await testEnv.DB.prepare(`SELECT COUNT(*) AS n FROM cve_metrics_daily`).first<{
      n: number;
    }>();
    expect(snapshot?.n).toBeGreaterThan(0);

    const run = await testEnv.DB.prepare(
      `SELECT last_status FROM ingest_run WHERE source = 'AGING'`,
    ).first<{ last_status: string }>();
    expect(run?.last_status).toBe('OK');
  });
});
