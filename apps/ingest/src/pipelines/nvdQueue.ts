import type { NormalizedCveRecord, NvdQueueMessage } from '@threat-lens/contracts';
import { processRecord } from '../lib/server/processRecord';
import type { Env } from '../types';

function isPlausibleCveRecord(r: unknown): r is NormalizedCveRecord {
  if (typeof r !== 'object' || r === null) return false;
  const rec = r as Record<string, unknown>;
  return (
    typeof rec.cveId === 'string' &&
    typeof rec.description === 'string' &&
    Array.isArray(rec.cwes) &&
    Array.isArray(rec.cpes) &&
    Array.isArray(rec.references)
  );
}

function isValidNvdQueueMessage(m: unknown): m is NvdQueueMessage {
  if (typeof m !== 'object' || m === null) return false;
  const msg = m as Record<string, unknown>;
  return Array.isArray(msg.records) && msg.records.every(isPlausibleCveRecord);
}

/**
 * NVD queue consumer (queue: `nvd-ingest` / `nvd-ingest-staging`).
 *
 * `pipelines/daily.ts`'s NVD section only fetches + size-aware-batches +
 * enqueues NormalizedCveRecords; this is where processRecord() — unchanged —
 * actually runs, one small bounded batch (see NVD_QUEUE_MAX_RECORDS /
 * NVD_QUEUE_MAX_BYTES in daily.ts) per invocation. Each invocation gets its
 * own fresh 50-D1-query budget — the whole point of moving this off the
 * cron path, same reasoning as pipelines/epssQueue.ts.
 *
 * Unlike epssQueue.ts's runEpssConsumer (which rethrows on failure so the
 * queue's own max_retries/DLQ mechanism handles a failed batch),
 * processRecord() ALREADY has its own per-call retry path: on D1/AI/
 * Vectorize failure it enqueues onto cve-ingest-retry (UPSERT_ALL /
 * VECTORIZE_ONLY) before rethrowing — see processRecord.ts. Letting one
 * record's processRecord() failure fail the WHOLE message here (and trigger
 * nvd-ingest's own retry) would redundantly re-run every OTHER record in the
 * batch too (harmless — processRecord's two-hash gate makes an unchanged
 * re-run a cheap no-op SELECT — but still unnecessary D1 traffic) and would
 * duplicate work the existing retry-queue mechanism already owns. So, same
 * as the original inline per-record loop this replaces (pipelines/daily.ts,
 * pre-fix), each record's error is caught and counted here, never rethrown
 * for an individual processRecord() failure.
 */
export async function runNvdConsumer(
  message: NvdQueueMessage,
  env: Env,
  ctx: ExecutionContext,
): Promise<void> {
  const t0 = Date.now();

  // Defensive runtime check on the dequeued body, same reasoning as
  // epssQueue.ts's isValidPatch check: a malformed/corrupted redelivery can
  // never succeed no matter how many times it's retried. Ack (drop) it
  // immediately instead of throwing, and log distinctly so this failure
  // mode isn't invisible to nvd_consumer_processed telemetry.
  if (!isValidNvdQueueMessage(message)) {
    env.ANALYTICS.writeDataPoint({
      blobs: ['NVD_QUEUE', 'MALFORMED_MESSAGE', '', '', '', '', ''],
      doubles: [Date.now() - t0, 0, 0, 0, 0],
      indexes: ['nvd_consumer_processed'],
    });
    return;
  }

  let processed = 0;
  let failed = 0;

  for (const record of message.records) {
    try {
      await processRecord(record, env, ctx);
      processed++;
    } catch {
      // processRecord() already enqueued its own RetryMessage before
      // rethrowing (see processRecord.ts) — this catch exists only to keep
      // one record's failure from aborting the rest of this batch, not to
      // duplicate that retry logic.
      failed++;
    }
  }

  env.ANALYTICS.writeDataPoint({
    blobs: ['NVD_QUEUE', failed > 0 ? 'PARTIAL' : 'OK', '', '', '', '', ''],
    doubles: [Date.now() - t0, processed, failed, 0, 0],
    indexes: ['nvd_consumer_processed'],
  });
}
