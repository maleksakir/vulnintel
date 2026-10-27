import { fetchKevCatalog } from '../adapters/kev';
import { markIngestFinished, markIngestStarted } from '../lib/server/ingestRun';
import { applyKevPatch } from '../lib/server/processRecord';
import type { Env } from '../types';

// KEV fast-lane (cron: 0 */6 * * *).
// Downloads the full CISA KEV catalog snapshot and applies every entry.
// applyKevPatch uses INSERT … ON CONFLICT DO UPDATE, so re-running is idempotent.
export async function runKevFastLane(env: Env, ctx: ExecutionContext): Promise<void> {
  const startedAt = Date.now();
  await markIngestStarted(env, 'KEV');

  let processed = 0;
  let failed = 0;
  let lastError: string | undefined;

  try {
    const patches = await fetchKevCatalog();

    for (const patch of patches) {
      try {
        await applyKevPatch(patch, env, ctx);
        processed++;
      } catch (err) {
        failed++;
        lastError = String(err);
      }
    }
  } catch (err) {
    lastError = String(err);
    failed++;
  }

  await markIngestFinished(
    env,
    'KEV',
    lastError && processed === 0 ? 'FAILED' : failed > 0 ? 'PARTIAL' : 'OK',
    processed,
    failed,
    lastError,
  );

  ctx.waitUntil(
    Promise.all([
      env.CACHE.delete('threat:kev:list'),
      env.ANALYTICS.writeDataPoint({
        blobs: ['KEV_FAST_LANE', lastError ? 'PARTIAL' : 'OK', 'KEV', '', '', '', ''],
        doubles: [startedAt, Date.now(), processed, failed, Date.now() - startedAt],
        indexes: ['ingest_run'],
      }),
    ]),
  );
}
