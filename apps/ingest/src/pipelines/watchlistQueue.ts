import type { WatchlistQueueMessage } from '@threat-lens/contracts';
import { markIngestFinished, markIngestStarted } from '../lib/server/ingestRun';
import { dispatchWatchlistNotifications } from '../lib/server/watchlistNotify';
import { reconcileWatchlistMatches } from '../lib/server/watchlistReconcile';
import type { Env } from '../types';

function isValidMessage(m: unknown): m is WatchlistQueueMessage {
  return (
    typeof m === 'object' &&
    m !== null &&
    (m as Record<string, unknown>).kind === 'WATCHLIST_RECONCILE'
  );
}

/**
 * Watchlist reconciliation consumer (queue: `watchlist-ingest` /
 * `watchlist-ingest-staging`).
 *
 * `pipelines/daily.ts` sends a single lightweight WATCHLIST_RECONCILE kick-off
 * on the daily cron (watchlists have no cron slot of their own — all 5 are
 * used); this consumer does the actual incremental match materialization with
 * its own fresh 50-D1-query budget (`max_batch_size = 1` in wrangler.toml),
 * same isolation reasoning as every other ingest queue.
 */
export async function runWatchlistConsumer(
  message: WatchlistQueueMessage,
  env: Env,
  _ctx: ExecutionContext,
): Promise<void> {
  const t0 = Date.now();

  // Malformed/corrupted redelivery can never succeed — ack (drop) it, don't
  // retry into the DLQ, and log distinctly. Same pattern as the other
  // consumers' shape checks.
  if (!isValidMessage(message)) {
    env.ANALYTICS.writeDataPoint({
      blobs: ['WATCHLIST_QUEUE', 'MALFORMED_MESSAGE', '', '', '', '', ''],
      doubles: [Date.now() - t0, 0, 0, 0, 0],
      indexes: ['watchlist_consumer_processed'],
    });
    return;
  }

  try {
    // markIngestStarted is INSIDE the try (not before it) so that a D1
    // outage during the start-marker write still lands in the catch below and
    // emits FAILED telemetry, rather than throwing uncaught past all of it.
    await markIngestStarted(env, 'WATCHLIST');
    const result = await reconcileWatchlistMatches(env);
    // Fire new-match digests to any enabled webhooks. Runs in the same
    // invocation after reconciliation — it's bounded (capped webhooks ×
    // capped digest size) and best-effort, so wrap it so a notification
    // failure can't fail the whole reconciliation (which already committed
    // its matches). A webhook that fails leaves notified_at NULL and is
    // retried next run (see watchlistNotify.ts).
    let notified = { webhooksDispatched: 0, matchesNotified: 0 };
    try {
      notified = await dispatchWatchlistNotifications(env);
    } catch (notifyErr) {
      env.ANALYTICS.writeDataPoint({
        blobs: ['WATCHLIST_NOTIFY', 'ERROR', String(notifyErr), '', '', '', ''],
        doubles: [Date.now() - t0, 0, 0, 0, 0],
        indexes: ['watchlist_consumer_processed'],
      });
    }
    await markIngestFinished(env, 'WATCHLIST', 'OK', result.matchesWritten, 0, undefined);
    env.ANALYTICS.writeDataPoint({
      blobs: ['WATCHLIST_QUEUE', 'OK', '', '', '', '', ''],
      doubles: [
        Date.now() - t0,
        result.cvesScanned,
        result.matchesWritten,
        notified.webhooksDispatched,
        notified.matchesNotified,
      ],
      indexes: ['watchlist_consumer_processed'],
    });
  } catch (err) {
    // Emit the FAILED analytics point FIRST and unconditionally — Analytics
    // Engine is a separate binding from D1, so this telemetry survives even a
    // total D1 outage (the exact case where markIngestFinished below would
    // also throw). Without this ordering, a D1-down failure would be silent
    // in `watchlist_consumer_processed` — the "nobody noticed" shape CLAUDE.md
    // warns about.
    env.ANALYTICS.writeDataPoint({
      blobs: ['WATCHLIST_QUEUE', 'FAILED', String(err), '', '', '', ''],
      doubles: [Date.now() - t0, 0, 1, 0, 0],
      indexes: ['watchlist_consumer_processed'],
    });
    // Best-effort FAILED bookkeeping — must not mask the original error (or
    // the analytics point above) if D1 is the thing that's down.
    try {
      await markIngestFinished(env, 'WATCHLIST', 'FAILED', 0, 1, String(err));
    } catch {
      /* D1 unavailable — the analytics point above is the durable signal */
    }
    // Rethrow so index.ts's queue() handler calls msg.retry() — the queue's
    // own max_retries/DLQ mechanism handles it, same as the EPSS/KEV path.
    throw err;
  }
}
