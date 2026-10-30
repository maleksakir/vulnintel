import type { NormalizedCveRecord } from '@threat-lens/contracts';
import type { Env } from '../types';

// NVD_QUEUE batch sizing — shared by both NVD producers (the daily 48h delta
// in pipelines/daily.ts and the weekly 30-day reconciliation in
// pipelines/reconcile.ts). Both feed the SAME nvd-ingest queue and the SAME
// consumer (pipelines/nvdQueue.ts), so their batch bounds MUST match the
// consumer's per-invocation budget — hence sharing one implementation rather
// than duplicating (and risking drift in) the sizing constants.
//
// Why bytes AND a record count, not a flat record count like EPSS: a single
// NormalizedCveRecord's size varies enormously — processRecord.ts's writeD1
// caps one record at 500 CPEs / 200 references, and a record actually built
// at that cap measures ~200KB on its own, already over Cloudflare Queues'
// 128KB (131,072-byte) per-message cap BY ITSELF. A record-count-only chunk
// size can't safely bound that.
//
// NVD_QUEUE_MAX_RECORDS caps the OTHER constraint: each CHANGED record's
// processRecord() call costs up to ~5 D1 queries in the consumer (1 SELECT +
// up to 4 db.batch() calls in writeD1, each db.batch() counting as ONE query
// toward the 50-per-invocation cap). A worst-case all-changed batch of 8
// records costs at most 8 × 5 = 40 D1 queries — under the 50 cap with
// headroom.
export const NVD_QUEUE_MAX_RECORDS = 8;
export const NVD_QUEUE_MAX_BYTES = 100_000;
// `{"records":[...]}`'s own wrapper + per-element comma overhead; a small
// fixed allowance rather than exact structural accounting.
const NVD_MESSAGE_WRAPPER_OVERHEAD_BYTES = 16;

export interface NvdEnqueueResult {
  processed: number;
  failed: number;
}

/**
 * Drains an async iterable of NormalizedCveRecords, size-aware-batches them,
 * and enqueues each batch onto NVD_QUEUE — doing ZERO D1/Vectorize/AI work of
 * its own (that happens in pipelines/nvdQueue.ts's consumer, one batch per
 * invocation with its own fresh 50-D1-query budget).
 *
 * `producerTag` is used only in the RECORD_TOO_LARGE analytics blob so the
 * two callers (daily NVD delta vs. weekly reconciliation) are
 * distinguishable in telemetry.
 *
 * A record whose own serialized size alone exceeds NVD_QUEUE_MAX_BYTES can't
 * be enqueued even in a batch of one — sending it would exceed Cloudflare
 * Queues' 128KB cap and be rejected — so it is flagged (RECORD_TOO_LARGE) and
 * skipped rather than silently truncated here ahead of writeD1's own 500/200
 * caps. Rare, but a real gap (see docs/EXECUTION_PLAN.md's NVD row).
 *
 * `processed`/`failed` describe the ENQUEUE outcome, not the D1-write
 * outcome — per-record write success/failure happens later in the consumer.
 */
export async function enqueueNvdRecords(
  records: AsyncIterable<NormalizedCveRecord>,
  env: Env,
  producerTag: string,
): Promise<NvdEnqueueResult> {
  let processed = 0;
  let failed = 0;

  let batch: NormalizedCveRecord[] = [];
  let batchBytes = 0;
  const flush = async () => {
    if (batch.length === 0) return;
    const chunk = batch;
    batch = [];
    batchBytes = 0;
    try {
      // Sequential, not concurrent: Queue send/sendBatch calls share a
      // 6-simultaneous-connection cap per invocation; awaiting one flush at
      // a time (as the for-await loop below does) never approaches it.
      await env.NVD_QUEUE.send({ records: chunk });
      processed += chunk.length;
    } catch {
      failed += chunk.length;
    }
  };

  for await (const record of records) {
    const recordBytes = new TextEncoder().encode(JSON.stringify(record)).length;

    if (recordBytes + NVD_MESSAGE_WRAPPER_OVERHEAD_BYTES > NVD_QUEUE_MAX_BYTES) {
      failed++;
      env.ANALYTICS.writeDataPoint({
        blobs: [producerTag, 'RECORD_TOO_LARGE', record.cveId, '', '', '', ''],
        doubles: [recordBytes, 0, 0, 0, 0],
        indexes: ['ingest_warn'],
      });
      continue;
    }

    if (
      batch.length >= NVD_QUEUE_MAX_RECORDS ||
      batchBytes + recordBytes + NVD_MESSAGE_WRAPPER_OVERHEAD_BYTES > NVD_QUEUE_MAX_BYTES
    ) {
      await flush();
    }

    batch.push(record);
    batchBytes += recordBytes;
  }
  await flush();

  return { processed, failed };
}
