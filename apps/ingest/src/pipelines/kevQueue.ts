import type { KevPatch, KevQueueMessage } from '@threat-lens/contracts';
import { applyKevPatchBatch } from '../lib/server/processRecord';
import type { Env } from '../types';

function isValidPatch(p: unknown): p is KevPatch {
  if (typeof p !== 'object' || p === null) return false;
  const patch = p as Record<string, unknown>;
  return (
    typeof patch.cveId === 'string' &&
    typeof patch.kevDateAdded === 'number' &&
    (patch.kevDueDate === null || typeof patch.kevDueDate === 'number') &&
    typeof patch.kevRequiredAction === 'string'
  );
}

/**
 * KEV queue consumer (queue: `kev-ingest` / `kev-ingest-staging`).
 *
 * `pipelines/kev.ts` only fetches + chunks + enqueues the CISA KEV catalog;
 * this is where the actual D1 change-detection + write work happens, one
 * message (~KEV_MESSAGE_CHUNK_SIZE patches) per invocation. Each invocation
 * gets its own fresh 50-D1-query budget — distinct from the 6-hourly cron's
 * single producer invocation — which is the whole point of moving this off
 * the cron path (see `wrangler.toml`'s `kev-ingest` consumer,
 * `max_batch_size = 1`). Same shape as pipelines/epssQueue.ts.
 */
export async function runKevConsumer(
  message: KevQueueMessage,
  env: Env,
  ctx: ExecutionContext,
): Promise<void> {
  const t0 = Date.now();

  // Defensive runtime check on the dequeued body, same reasoning as
  // epssQueue.ts's isValidPatch check: a malformed/corrupted redelivery can
  // never succeed no matter how many times it's retried — retrying it would
  // just burn through max_retries until the DLQ anyway. Ack (drop) it
  // immediately instead, and log distinctly so this failure mode isn't
  // invisible to kev_consumer_processed telemetry.
  if (!Array.isArray(message?.patches) || !message.patches.every(isValidPatch)) {
    env.ANALYTICS.writeDataPoint({
      blobs: ['KEV_QUEUE', 'MALFORMED_MESSAGE', '', '', '', '', ''],
      doubles: [Date.now() - t0, 0, 0, 0, 0],
      indexes: ['kev_consumer_processed'],
    });
    return;
  }

  try {
    const { processed, changed } = await applyKevPatchBatch(message.patches, env, ctx);
    env.ANALYTICS.writeDataPoint({
      blobs: ['KEV_QUEUE', 'OK', '', '', '', '', ''],
      doubles: [Date.now() - t0, processed, changed, 0, 0],
      indexes: ['kev_consumer_processed'],
    });
  } catch (err) {
    env.ANALYTICS.writeDataPoint({
      blobs: ['KEV_QUEUE', 'FAILED', String(err), '', '', '', ''],
      doubles: [Date.now() - t0, 0, message.patches.length, 0, 0],
      indexes: ['kev_consumer_processed'],
    });
    // Rethrow so index.ts's queue() handler calls msg.retry() — the queue's
    // own retry mechanism (max_retries, then kev-ingest-dlq) handles it from
    // there, same pattern as the EPSS consumer path.
    throw err;
  }
}
