import type { EpssQueueMessage, NvdQueueMessage, RetryMessage } from '@threat-lens/contracts';
import { processRecord } from './lib/server/processRecord';
import { runAgingSweep } from './pipelines/aging';
import { runDailyFullDelta } from './pipelines/daily';
import { runEpssConsumer } from './pipelines/epssQueue';
import { runIpListPrune } from './pipelines/iplist';
import { runKevFastLane } from './pipelines/kev';
import { runNvdConsumer } from './pipelines/nvdQueue';
import { isValidOsvQueueMessage, runOsvDiscovery, runOsvFetchBatch } from './pipelines/osv';
import { runWeeklyReconciliation } from './pipelines/reconcile';
import type { Env } from './types';

export default {
  /**
   * Cron dispatch (§5.1.1).
   * HTTP fetch handler is intentionally absent — workers_dev = false in wrangler.toml.
   */
  async scheduled(controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    switch (controller.cron) {
      case '0 1 * * *':
        await runDailyFullDelta(env, ctx);
        break;

      case '0 */6 * * *':
        await runKevFastLane(env, ctx);
        break;

      case '0 3 * * 7':
        await runWeeklyReconciliation(env, ctx);
        break;

      case '30 2 * * *':
        await runAgingSweep(env, ctx);
        break;

      case '0 4 * * *':
        await runIpListPrune(env, ctx);
        break;

      default:
        env.ANALYTICS.writeDataPoint({
          blobs: ['UNKNOWN_CRON', controller.cron, '', '', '', '', ''],
          doubles: [Date.now(), 0, 0, 0, 0],
          indexes: ['ingest_warn'],
        });
    }
  },

  /**
   * Queue consumer — dispatches by queue name since this Worker now
   * subscribes to three distinct queues.
   *
   * `epss-ingest` (+ `epss-ingest-staging`): one message = one chunk of a
   *   day's EPSS CSV snapshot, produced by pipelines/daily.ts. Routed by
   *   `startsWith` rather than exact match so the `-staging` suffixed queue
   *   matches too, same reasoning the retry queue would need if staging ever
   *   got its own traffic (see wrangler.toml's staging section).
   *   max_retries=3 → exhausted messages land in epss-ingest-dlq.
   *
   * `nvd-ingest` (+ `nvd-ingest-staging`): one message = one small bounded
   *   batch of NormalizedCveRecords from a day's NVD delta, produced by
   *   pipelines/daily.ts. A malformed body is acked (dropped), not retried —
   *   same reasoning as the epss-ingest malformed-message branch below.
   *   max_retries=3 → exhausted messages land in nvd-ingest-dlq.
   *
   * `osv-ingest` (+ `osv-ingest-staging`): carries both the daily
   *   OSV_DISCOVER kick-off (from pipelines/daily.ts) and the per-record
   *   OSV_FETCH work items it produces (from pipelines/osv.ts's own
   *   runOsvDiscovery, a queue consumer invocation in its own right). A
   *   malformed body is acked (dropped), not retried — same reasoning as
   *   the epss-ingest malformed-message branch below.
   *   max_retries=3 → exhausted messages land in osv-ingest-dlq.
   *
   * Everything else falls through to the existing retry-queue handling
   * (§5.1.7): cve-ingest-retry → max_retries=5 → cve-ingest-dlq.
   *   UPSERT_ALL: D1 write failed on a previous attempt — retry full pipeline.
   *   VECTORIZE_ONLY: D1 succeeded but Vectorize/AI failed — skip D1, re-run Vectorize.
   *     If message.vector is present, pass it through to avoid a second AI call.
   */
  async queue(batch: MessageBatch, env: Env, ctx: ExecutionContext): Promise<void> {
    if (batch.queue.startsWith('epss-ingest')) {
      for (const msg of batch.messages) {
        try {
          await runEpssConsumer(msg.body as EpssQueueMessage, env, ctx);
          msg.ack();
        } catch {
          msg.retry();
        }
      }
      return;
    }

    if (batch.queue.startsWith('nvd-ingest')) {
      for (const msg of batch.messages) {
        try {
          await runNvdConsumer(msg.body as NvdQueueMessage, env, ctx);
          msg.ack();
        } catch {
          msg.retry();
        }
      }
      return;
    }

    if (batch.queue.startsWith('osv-ingest')) {
      for (const msg of batch.messages) {
        if (!isValidOsvQueueMessage(msg.body)) {
          env.ANALYTICS.writeDataPoint({
            blobs: ['OSV_QUEUE', 'MALFORMED_MESSAGE', '', '', '', '', ''],
            doubles: [Date.now(), 0, 0, 0, 0],
            indexes: ['osv_consumer_processed'],
          });
          msg.ack();
          continue;
        }
        try {
          if (msg.body.kind === 'OSV_DISCOVER') {
            await runOsvDiscovery(env, ctx);
          } else {
            await runOsvFetchBatch(msg.body.items, env, ctx);
          }
          msg.ack();
        } catch {
          msg.retry();
        }
      }
      return;
    }

    for (const msg of batch.messages) {
      try {
        const body = msg.body as RetryMessage;

        await processRecord(body.normalizedRecord, env, ctx, {
          opType: body.opType,
          ...(body.vector !== undefined && { vector: body.vector }),
        });

        msg.ack();
      } catch {
        msg.retry();
      }
    }
  },
} satisfies ExportedHandler<Env>;
