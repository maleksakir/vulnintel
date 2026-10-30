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
