import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { runAgingSweep } from '../src/pipelines/aging';
import { spyOnBindings, testEnv, useCleanBindings } from './helpers';

// Aging sweep — focused on the dashboard cache-key invalidation fix.
//
// The sweep used to delete `dash:kpi:total|severity|kev|epss` after pruning
// aged-out CVEs. Nothing in the app ever writes those keys — the dashboard
// metrics are cached under `dash:metrics:<window>` (see the app's
// /api/metrics route and homepage loader). So the real metrics cache was
// NEVER event-invalidated (it relied solely on its 300s TTL) and the four
// deletes were pure waste against the 1,000/day KV write+delete cap. This
// guards the corrected behavior: invalidate the real keys, only on a run that
// actually changed the corpus.

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

  it('a no-op run (nothing aged out) invalidates nothing — no wasted KV deletes', async () => {
    // A fresh, in-window CVE: not eligible for deletion.
    await seedAgedCve('CVE-2026-0001', Date.now());

    const spies = spyOnBindings();
    const ctx = createExecutionContext();
    await runAgingSweep(testEnv, ctx);
    await waitOnExecutionContext(ctx);

    // Skip-if-unchanged: a run that deleted nothing must not burn any KV
    // delete (this fires 4x/day via the cron — unconditional deletes would
    // waste the 1,000/day KV cap).
    expect(spies.cacheDelete).not.toHaveBeenCalled();

    const remaining = await testEnv.DB.prepare('SELECT COUNT(*) AS n FROM cve').first<{
      n: number;
    }>();
    expect(remaining?.n).toBe(1);
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
    expect(spies.cacheDelete).not.toHaveBeenCalled(); // nothing deleted → nothing invalidated
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
