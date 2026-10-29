import type { EpssPatch, EpssQueueMessage } from '@threat-lens/contracts';
import { applyEpssPatchBatch } from '../lib/server/processRecord';
import type { Env } from '../types';

function isValidPatch(p: unknown): p is EpssPatch {
  if (typeof p !== 'object' || p === null) return false;
  const patch = p as Record<string, unknown>;
  return (
    typeof patch.cveId === 'string' &&
    typeof patch.epssScore === 'number' &&
    typeof patch.epssPercentile === 'number' &&
    typeof patch.epssUpdatedAt === 'number'
  );
}

/**
 * EPSS queue consumer (queue: `epss-ingest` / `epss-ingest-staging`).
 *
 * `pipelines/daily.ts` only fetches + chunks + enqueues EPSS patches; this is
 * where the actual D1 change-detection + write work happens, one message
 * (~EPSS_MESSAGE_CHUNK_SIZE patches) per invocation. Each invocation gets its
 * own fresh 50-D1-query budget — distinct from the daily cron's single
 * NVD+MITRE+EPSS-producer invocation — which is the whole point of moving
 * this off the cron path (see `wrangler.toml`'s `epss-ingest` consumer,
 * `max_batch_size = 1`, for how that one-message-per-invocation guarantee is
 * enforced).
 */
export async function runEpssConsumer(
  message: EpssQueueMessage,
  env: Env,
  ctx: ExecutionContext,
): Promise<void> {
  const t0 = Date.now();

  // Defensive runtime check on the dequeued body: today only this Worker's
  // own producer (daily.ts) sends to this queue, but a malformed/corrupted
  // redelivery can never succeed no matter how many times it's retried —
  // retrying it would just burn through max_retries until the DLQ anyway.
  // Ack (drop) it immediately instead, and log distinctly so this failure
  // mode isn't invisible to epss_consumer_processed telemetry, the same
  // "silently broken, nobody noticed" shape CLAUDE.md's aging-sweep
  // incident warns about.
  if (!Array.isArray(message?.patches) || !message.patches.every(isValidPatch)) {
    env.ANALYTICS.writeDataPoint({
      blobs: ['EPSS_QUEUE', 'MALFORMED_MESSAGE', '', '', '', '', ''],
      doubles: [Date.now() - t0, 0, 0, 0, 0],
      indexes: ['epss_consumer_processed'],
    });
    return;
  }

  const total = message.patches.length;

  try {
    await applyEpssPatchBatch(message.patches, env, ctx);
    env.ANALYTICS.writeDataPoint({
      blobs: ['EPSS_QUEUE', 'OK', '', '', '', '', ''],
      doubles: [Date.now() - t0, total, 0, 0, 0],
      indexes: ['epss_consumer_processed'],
    });
  } catch (err) {
    env.ANALYTICS.writeDataPoint({
      blobs: ['EPSS_QUEUE', 'FAILED', String(err), '', '', '', ''],
      doubles: [Date.now() - t0, 0, total, 0, 0],
      indexes: ['epss_consumer_processed'],
    });
    // Rethrow so the caller (the queue() handler in index.ts) calls
    // msg.retry() instead of msg.ack() — the queue's own retry mechanism
    // (max_retries, then dead_letter_queue "epss-ingest-dlq") handles it
    // from there, same pattern as the existing RETRY_QUEUE consumer path.
    throw err;
  }
}
