import type { EpssPatch, NormalizedCveRecord } from '@threat-lens/contracts';
import { fetchEpssCsv } from '../adapters/epss';
import { fetchMitreDelta } from '../adapters/mitre';
import { fetchNvdDelta } from '../adapters/nvd';
import { markIngestFinished, markIngestStarted } from '../lib/server/ingestRun';
import { processRecord } from '../lib/server/processRecord';
import type { Env } from '../types';

const DELTA_WINDOW_MS = 48 * 60 * 60 * 1000; // 48-hour lookback for safety overlap
// EPSS_QUEUE message chunk size. Cloudflare Queues caps a message at 128KB
// (131,072 bytes) of JSON. Measured `JSON.stringify({ patches: [...] })`
// size for real-shaped EpssPatch records: ~102 bytes/patch, so 1,000 patches
// serializes to ~103KB — a ~28KB (≈21%) margin under the cap for the
// occasional longer cveId/epssUpdatedAt. (1,500 patches, the number
// originally proposed for this constant, measured at ~154KB — over the cap —
// so don't raise this without re-measuring actual serialized size.)
const EPSS_MESSAGE_CHUNK_SIZE = 1000;

// NVD_QUEUE batch sizing. Unlike EPSS's flat, small EpssPatch shape, a
// NormalizedCveRecord's size varies enormously: processRecord.ts's writeD1
// caps a single record at 500 CPEs / 200 references, and a record actually
// built at that cap measures ~200KB on its own — already over Cloudflare
// Queues' 128KB (131,072-byte) per-message cap BY ITSELF, before any
// batching. A fixed record-count-only chunk size (EPSS's approach) can't
// safely bound this, so batching here tracks actual serialized bytes per
// batch, not just a count.
//
// NVD_QUEUE_MAX_RECORDS caps the OTHER constraint: each CHANGED record's
// processRecord() call costs up to ~5 D1 queries in the consumer (1 SELECT
// + up to 4 more db.batch() calls in writeD1 — main row+state+provenance,
// CWEs, CPEs, references — each db.batch() call counts as ONE query
// regardless of statement count, per the D1-query-budget comment on
// WRITE_SUB_BATCH_SIZE in processRecord.ts). A worst-case ALL-CHANGED batch
// of 8 records costs at most 8 × 5 = 40 D1 queries — comfortably under the
// 50-per-invocation Free-tier cap with headroom to spare, unlike EPSS's
// equivalent (~1,000 patches/message) which can use a much larger count
// because applyEpssPatchBatch's D1 cost is O(1 batch per ~500 patches), not
// O(5) per record.
//
// NVD_QUEUE_MAX_BYTES leaves a ~24% margin under the 131,072-byte cap for
// the enclosing `{"records":[...]}` wrapper and any single large record
// already queued in the batch (measured: 10 typical-shaped records — 4
// CPEs/5 references each — serialize to ~25KB, so in the common case
// NVD_QUEUE_MAX_RECORDS is the binding constraint and NVD_QUEUE_MAX_BYTES
// only matters for unusually CPE/reference-heavy CVEs).
const NVD_QUEUE_MAX_RECORDS = 8;
const NVD_QUEUE_MAX_BYTES = 100_000;
// `{"records":[...]}`'s own wrapper + per-element comma overhead; a small
// fixed allowance rather than exact structural accounting.
const NVD_MESSAGE_WRAPPER_OVERHEAD_BYTES = 16;

/**
 * Daily full delta (cron: 0 1 * * *).
 * 1. NVD CVE 2.0 — all CVEs modified in last 48 h
 * 2. MITRE CVE List v5 — supplement CWEs for MITRE-sourced CVEs
 * 3. FIRST EPSS daily CSV — update exploitability scores for all CVEs
 */
export async function runDailyFullDelta(env: Env, ctx: ExecutionContext): Promise<void> {
  const startedAt = Date.now();
  const endDate = new Date(startedAt);
  const startDate = new Date(startedAt - DELTA_WINDOW_MS);

  // OSV (GHSA) discovery piggybacks on this cron slot — all 5 Workers Free
  // cron triggers are already used (see wrangler.toml), so OSV can't get its
  // own. This is just the kick-off: the real discovery work (GCS CSV scans +
  // D1 reads) happens in pipelines/osv.ts's runOsvDiscovery, run as its own
  // `osv-ingest` queue-consumer invocation with a fresh 50-D1-query budget —
  // same producer/consumer split as EPSS below. Best-effort: OSV is
  // additive and must never block NVD/MITRE/EPSS.
  try {
    await env.OSV_QUEUE.send({ kind: 'OSV_DISCOVER' });
  } catch {
    /* best-effort enqueue — see comment above */
  }

  await Promise.all([
    markIngestStarted(env, 'NVD'),
    markIngestStarted(env, 'MITRE'),
    markIngestStarted(env, 'EPSS'),
  ]);

  // ── NVD ──────────────────────────────────────────────────────────────────
  // This pipeline only fetches, size-aware-batches, and enqueues
  // NormalizedCveRecords onto NVD_QUEUE — it does NOT call processRecord()
  // (and therefore does no D1/Vectorize/AI work) itself. NVD's 48h delta is
  // variable — hundreds to low-thousands of modified records is typical, but
  // it is NOT a fixed daily snapshot size the way EPSS's 250k-row CSV is —
  // and each CHANGED record's processRecord() call costs up to ~5 D1 queries
  // (see processRecord.ts's writeD1). Even a few dozen changed records would
  // exhaust this single cron invocation's 50-D1-query budget if processed
  // inline alongside MITRE+EPSS — the exact failure class EPSS had (see the
  // EPSS section below and pipelines/epssQueue.ts). The actual
  // processRecord() work now happens in pipelines/nvdQueue.ts, run as
  // separate queue-consumer invocations, each with its own fresh 50-query
  // budget (see NVD_QUEUE in wrangler.toml).
  //
  // Because of that split, nvdProcessed/nvdFailed/the status passed to
  // markIngestFinished below describe the ENQUEUE outcome (did every fetched
  // record make it onto NVD_QUEUE), not the D1-write outcome — per-record
  // write success/failure now happens later, outside this cron run's
  // visibility (see nvd_consumer_processed analytics in nvdQueue.ts).
  let nvdProcessed = 0;
  let nvdFailed = 0;
  let nvdError: string | undefined;

  let nvdBatch: NormalizedCveRecord[] = [];
  let nvdBatchBytes = 0;
  const flushNvdBatch = async () => {
    if (nvdBatch.length === 0) return;
    const chunk = nvdBatch;
    nvdBatch = [];
    nvdBatchBytes = 0;
    try {
      // Sequential, not concurrent — same reasoning as flushEpssBatch below:
      // Queue send/sendBatch calls share a 6-simultaneous-connection cap per
      // invocation, and this for-await loop already awaits one flush at a
      // time.
      await env.NVD_QUEUE.send({ records: chunk });
      nvdProcessed += chunk.length;
    } catch {
      nvdFailed += chunk.length;
    }
  };

  try {
    for await (const record of fetchNvdDelta(env.NVD_API_KEY, startDate, endDate)) {
      const recordBytes = new TextEncoder().encode(JSON.stringify(record)).length;

      if (recordBytes + NVD_MESSAGE_WRAPPER_OVERHEAD_BYTES > NVD_QUEUE_MAX_BYTES) {
        // A single record this large can't be safely enqueued even alone —
        // sending it would exceed Cloudflare Queues' 128KB cap outright and
        // the send() call would be rejected outright. Flag and skip rather
        // than attempting (and failing) to send it, or silently truncating
        // cpes/references here ahead of writeD1's own, documented 500/200
        // caps. This is a real, if rare, gap: see this task's report.
        nvdFailed++;
        env.ANALYTICS.writeDataPoint({
          blobs: ['NVD_PRODUCER', 'RECORD_TOO_LARGE', record.cveId, '', '', '', ''],
          doubles: [recordBytes, 0, 0, 0, 0],
          indexes: ['ingest_warn'],
        });
        continue;
      }

      if (
        nvdBatch.length >= NVD_QUEUE_MAX_RECORDS ||
        nvdBatchBytes + recordBytes + NVD_MESSAGE_WRAPPER_OVERHEAD_BYTES > NVD_QUEUE_MAX_BYTES
      ) {
        await flushNvdBatch();
      }

      nvdBatch.push(record);
      nvdBatchBytes += recordBytes;
    }
    await flushNvdBatch();
  } catch (err) {
    nvdError = String(err);
    nvdFailed += nvdBatch.length;
  }

  await markIngestFinished(
    env,
    'NVD',
    nvdError ? 'FAILED' : nvdFailed > 0 ? 'PARTIAL' : 'OK',
    nvdProcessed,
    nvdFailed,
    nvdError,
  );

  // ── MITRE ─────────────────────────────────────────────────────────────────
  let mitreProcessed = 0;
  let mitreFailed = 0;
  let mitreError: string | undefined;

  try {
    for await (const record of fetchMitreDelta(startDate, endDate)) {
      try {
        await processRecord(record, env, ctx);
        mitreProcessed++;
      } catch {
        mitreFailed++;
      }
    }
  } catch (err) {
    mitreError = String(err);
    mitreFailed++;
  }

  await markIngestFinished(
    env,
    'MITRE',
    mitreError ? 'FAILED' : mitreFailed > 0 ? 'PARTIAL' : 'OK',
    mitreProcessed,
    mitreFailed,
    mitreError,
  );

  // ── EPSS ──────────────────────────────────────────────────────────────────
  // This pipeline only fetches, chunks, and enqueues EPSS patches — it does
  // NOT write them to D1 itself. FIRST.org's 250k+-row full daily snapshot
  // can't be change-detected and written within this single cron invocation
  // alongside NVD+MITRE: D1 caps queries per Worker invocation at 50, and
  // even chunking SELECTs at the 100-bound-param max would need ~2,500 of
  // them just to scan the file. The actual D1 work now happens in
  // pipelines/epssQueue.ts, run as separate queue-consumer invocations, each
  // with its own fresh 50-query budget (see EPSS_QUEUE in wrangler.toml).
  //
  // Because of that split, `epssProcessed`/`epssFailed`/the status passed to
  // markIngestFinished below describe the ENQUEUE outcome (did every patch
  // make it onto the queue), not the D1-write outcome — per-row write
  // success/failure now happens later, outside this cron run's visibility.
  let epssProcessed = 0;
  let epssFailed = 0;
  let epssError: string | undefined;

  let epssBatch: EpssPatch[] = [];
  const flushEpssBatch = async () => {
    if (epssBatch.length === 0) return;
    const chunk = epssBatch;
    epssBatch = [];
    try {
      // Sequential, not concurrent: Queue send/sendBatch calls share a
      // 6-simultaneous-connection cap per invocation, and a plain sequence
      // of awaits (one chunk at a time, as the for-await loop below already
      // does) never approaches that.
      await env.EPSS_QUEUE.send({ patches: chunk });
      epssProcessed += chunk.length;
    } catch {
      epssFailed += chunk.length;
    }
  };

  try {
    for await (const patch of fetchEpssCsv()) {
      epssBatch.push(patch);
      if (epssBatch.length >= EPSS_MESSAGE_CHUNK_SIZE) {
        await flushEpssBatch();
      }
    }
    await flushEpssBatch();
  } catch (err) {
    epssError = String(err);
    epssFailed += epssBatch.length;
  }

  await markIngestFinished(
    env,
    'EPSS',
    epssError ? 'FAILED' : epssFailed > 0 ? 'PARTIAL' : 'OK',
    epssProcessed,
    epssFailed,
    epssError,
  );

  ctx.waitUntil(
    Promise.resolve(
      env.ANALYTICS.writeDataPoint({
        blobs: [
          'DAILY_DELTA',
          nvdError ?? mitreError ?? epssError ?? 'OK',
          'NVD+MITRE+EPSS',
          '',
          '',
          '',
          '',
        ],
        doubles: [
          startedAt,
          Date.now(),
          nvdProcessed + mitreProcessed + epssProcessed,
          nvdFailed + mitreFailed + epssFailed,
          Date.now() - startedAt,
        ],
        indexes: ['ingest_run'],
      }),
    ),
  );
}
