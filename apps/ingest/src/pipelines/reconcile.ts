import { fetchNvdDelta } from '../adapters/nvd';
import { markIngestFinished, markIngestStarted } from '../lib/server/ingestRun';
import { processRecord } from '../lib/server/processRecord';
import type { Env } from '../types';

const RECONCILE_WINDOW_DAYS = 30;

/**
 * Weekly 30-day reconciliation sweep (cron: 0 3 * * 0).
 *
 * Re-fetches all CVEs modified in the last 30 days from NVD and runs
 * processRecord on each. The two-hash strategy means unchanged records are
 * skipped cheaply; only genuine discrepancies trigger D1/Vectorize writes.
 *
 * Purpose: catch any CVEs that were missed or corrupted during daily ingests.
 */
export async function runWeeklyReconciliation(env: Env, ctx: ExecutionContext): Promise<void> {
  const startedAt = Date.now();
  const endDate = new Date(startedAt);
  const startDate = new Date(startedAt - RECONCILE_WINDOW_DAYS * 24 * 60 * 60 * 1000);

  await markIngestStarted(env, 'RECONCILE');

  let processed = 0;
  let failed = 0;
  let lastError: string | undefined;

  try {
    for await (const record of fetchNvdDelta(env.NVD_API_KEY, startDate, endDate)) {
      try {
        await processRecord(record, env, ctx);
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
    'RECONCILE',
    lastError && processed === 0 ? 'FAILED' : failed > 0 ? 'PARTIAL' : 'OK',
    processed,
    failed,
    lastError,
  );

  ctx.waitUntil(
    Promise.resolve(
      env.ANALYTICS.writeDataPoint({
        blobs: ['WEEKLY_RECONCILE', lastError ? 'PARTIAL' : 'OK', 'NVD', '', '', '', ''],
        doubles: [startedAt, Date.now(), processed, failed, Date.now() - startedAt],
        indexes: ['ingest_run'],
      }),
    ),
  );
}
