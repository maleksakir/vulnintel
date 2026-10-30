import { fetchNvdDelta } from '../adapters/nvd';
import { markIngestFinished, markIngestStarted } from '../lib/server/ingestRun';
import type { Env } from '../types';
import { enqueueNvdRecords } from './nvdProducer';

const RECONCILE_WINDOW_DAYS = 30;

/**
 * Weekly 30-day reconciliation sweep (cron: 0 3 * * 0) — PRODUCER ONLY.
 *
 * Re-fetches all CVEs modified in the last 30 days from NVD and enqueues them
 * onto the EXISTING nvd-ingest queue (the same one pipelines/daily.ts's NVD
 * section feeds) — it does NOT call processRecord() inline itself.
 *
 * Why the split: this had the identical inline-per-record D1 bug as the daily
 * NVD delta (see docs/EXECUTION_PLAN.md's reconcile row and CLAUDE.md's
 * D1-caps bullet) — it called processRecord() once per record inside a single
 * cron invocation, over a 30-day window (far larger than the daily 48h one),
 * so it blew the Free plan's 50-D1-query-per-invocation cap and got killed
 * mid-run. Because it runs weekly and its purpose is catching late
 * edits/corrections, the failure mode was silent: discrepancies simply never
 * got reconciled, with ingest_run showing the last run that DID finish.
 *
 * It reuses the nvd-ingest queue rather than provisioning its own: the
 * consumer (pipelines/nvdQueue.ts) is identical work — run processRecord() per
 * record with a fresh per-invocation D1 budget — and the two-hash gate in
 * processRecord makes an unchanged record (the overwhelming majority of a
 * reconciliation window) a cheap no-op SELECT. No new queue, no new
 * wrangler.toml provisioning, no extra share of the account-wide
 * 10,000-Queue-ops/day pool beyond the messages themselves.
 *
 * Because of the split, processed/failed and the status passed to
 * markIngestFinished describe the ENQUEUE outcome, not the D1-write outcome —
 * per-record write success/failure happens later in the consumer, outside
 * this cron run's visibility (see nvd_consumer_processed analytics).
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
    const result = await enqueueNvdRecords(
      fetchNvdDelta(env.NVD_API_KEY, startDate, endDate),
      env,
      'RECONCILE_PRODUCER',
    );
    processed = result.processed;
    failed = result.failed;
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
