import type { EpssPatch, MitreCweQueueMessage, NormalizedCveRecord } from '@threat-lens/contracts';
import { fetchEpssCsv } from '../adapters/epss';
import { CVE_ID_SHAPE } from '../adapters/mitre';
import { fetchNvdDelta } from '../adapters/nvd';
import { markIngestFinished, markIngestStarted } from '../lib/server/ingestRun';
import type { Env } from '../types';
import { NVD_QUEUE_MAX_BYTES, NVD_QUEUE_MAX_RECORDS } from './nvdProducer';

const DELTA_WINDOW_MS = 48 * 60 * 60 * 1000; // 48-hour lookback for safety overlap
// EPSS_QUEUE message chunk size. Cloudflare Queues caps a message at 128KB
// (131,072 bytes) of JSON. Measured `JSON.stringify({ patches: [...] })`
// size for real-shaped EpssPatch records: ~102 bytes/patch, so 1,000 patches
// serializes to ~103KB — a ~28KB (≈21%) margin under the cap for the
// occasional longer cveId/epssUpdatedAt. (1,500 patches, the number
// originally proposed for this constant, measured at ~154KB — over the cap —
// so don't raise this without re-measuring actual serialized size.)
const EPSS_MESSAGE_CHUNK_SIZE = 1000;

// NVD_QUEUE batch sizing (NVD_QUEUE_MAX_RECORDS / NVD_QUEUE_MAX_BYTES) is
// shared with pipelines/reconcile.ts via pipelines/nvdProducer.ts — both feed
// the SAME nvd-ingest queue + consumer, so their bounds must match the
// consumer's per-invocation budget and must not drift. See nvdProducer.ts for
// the full rationale (per-record size variance, the ~5-D1-query-per-record
// consumer cost, and why bytes AND a record count are both needed). This file
// keeps its own enqueue LOOP (rather than calling enqueueNvdRecords) only
// because it must also collect zero-CWE CVE IDs for the MITRE gap-fill inline
// in the same pass — a side effect the shared helper deliberately does not
// carry.
//
// `{"records":[...]}`'s own wrapper + per-element comma overhead; a small
// fixed allowance rather than exact structural accounting.
const NVD_MESSAGE_WRAPPER_OVERHEAD_BYTES = 16;

// MITRE CWE gap-fill lookup. The NVD loop below collects the CVE IDs of
// any record it saw with zero CWEs (`record.cwes.length === 0`) and hands
// them to a dedicated `mitre-ingest` queue (pipelines/mitreQueue.ts) to
// individually re-check against MITRE's public single-record endpoint —
// replacing the old, removed full MITRE delta re-ingest (adapters/mitre.ts
// used to call MITRE's Secretariat/Bulk-Download-only LIST endpoint, which
// returns HTTP 400 for public callers and was never actually working in
// production; its records, had they been written, would also have
// overwritten NVD's superior description/CVSS/CPE data — see
// adapters/mitre.ts's header comment).
//
// A live-verified planner investigation (2026-10-30, see
// docs/EXECUTION_PLAN.md) found NVD's own `weaknesses[]` parsing
// (adapters/nvd.ts) already surfaces essentially every CWE MITRE's CNA+ADP
// containers carry; the one genuine, recoverable gap is a CNA that wrote a
// CWE as free text in a description field with no structured `cweId` NVD
// could pick up — rare enough that a capped, narrow lookup (not a full
// re-ingest) is the right shape.
//
// MITRE_LOOKUP_MAX_PER_RUN caps a pathological 48h delta with an unusually
// large zero-CWE fraction (observed: mostly Linux kernel CNA submissions,
// which don't assign CWEs at all) from blowing past Cloudflare Queues'
// sendBatch limits or ballooning mitre-ingest consumer traffic. Anything
// over the cap is counted and logged (ANALYTICS 'LOOKUP_CAP_EXCEEDED'),
// never silently truncated.
const MITRE_LOOKUP_MAX_PER_RUN = 1000;
const MITRE_QUEUE_CHUNK_SIZE = 20;
// Cloudflare Queues' sendBatch() caps at 100 messages per call. At
// MITRE_LOOKUP_MAX_PER_RUN(1000)/MITRE_QUEUE_CHUNK_SIZE(20) = 50 messages
// max, one call always suffices today; this loop is purely defensive
// against either constant changing later (same reasoning as OSV's
// discovery sendBatch loop in pipelines/osv.ts).
const QUEUES_SENDBATCH_MAX_MESSAGES = 100;

/**
 * Daily full delta (cron: 0 1 * * *).
 * 1. NVD CVE 2.0 — all CVEs modified in last 48 h
 * 2. MITRE CWE gap-fill — re-check NVD records with zero CWEs against
 *    MITRE's public single-record endpoint for a free-text-only CWE NVD's
 *    own parsing can't recover (narrow supplement, not a record source)
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

  // Watchlist match reconciliation piggybacks on this cron slot too (same
  // reason as OSV: no free cron slots left). Lightweight kick-off only — the
  // actual D1 match materialization happens in pipelines/watchlistQueue.ts's
  // consumer with its own fresh 50-query budget. Best-effort: watchlists are
  // an additive read-side feature and must never block or fail NVD/MITRE/EPSS.
  try {
    await env.WATCHLIST_QUEUE.send({ kind: 'WATCHLIST_RECONCILE' });
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

  // MITRE CWE gap-fill collection — pure in-memory, filled inside the NVD
  // loop below, enqueued onto MITRE_QUEUE after the loop finishes. Adds
  // ZERO new D1 queries to this loop (see MITRE_LOOKUP_MAX_PER_RUN above).
  const cweGapCveIds: string[] = [];
  let cweGapOverCap = 0;

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
      // Defense in depth: mitreQueue.ts's consumer re-validates every id
      // before building a fetch URL (the gate that actually matters), but
      // filtering here too — before anything reaches the queue at all —
      // matches this codebase's own osv.ts precedent (OSV_ID_ALLOW is
      // checked before enqueueing, not just before fetching).
      if (record.cwes.length === 0 && CVE_ID_SHAPE.test(record.cveId)) {
        if (cweGapCveIds.length < MITRE_LOOKUP_MAX_PER_RUN) {
          cweGapCveIds.push(record.cveId);
        } else {
          cweGapOverCap++;
        }
      }

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

  // ── MITRE (CWE gap-fill) ─────────────────────────────────────────────────
  // Enqueue-only, same shape as NVD/EPSS above: this reports the ENQUEUE
  // outcome (did every collected CVE ID make it onto MITRE_QUEUE), not a
  // D1-write outcome — the actual D1 work happens later in
  // pipelines/mitreQueue.ts's consumer, outside this cron run's visibility.
  let mitreEnqueued = 0;
  let mitreFailed = 0;
  let mitreError: string | undefined;

  if (cweGapOverCap > 0) {
    env.ANALYTICS.writeDataPoint({
      blobs: ['MITRE_PRODUCER', 'LOOKUP_CAP_EXCEEDED', String(cweGapOverCap), '', '', '', ''],
      doubles: [cweGapOverCap, 0, 0, 0, 0],
      indexes: ['ingest_warn'],
    });
  }

  if (cweGapCveIds.length > 0) {
    const messages: { body: MitreCweQueueMessage }[] = [];
    for (let i = 0; i < cweGapCveIds.length; i += MITRE_QUEUE_CHUNK_SIZE) {
      messages.push({ body: { cveIds: cweGapCveIds.slice(i, i + MITRE_QUEUE_CHUNK_SIZE) } });
    }

    for (let i = 0; i < messages.length; i += QUEUES_SENDBATCH_MAX_MESSAGES) {
      const slice = messages.slice(i, i + QUEUES_SENDBATCH_MAX_MESSAGES);
      try {
        await env.MITRE_QUEUE.sendBatch(slice);
        mitreEnqueued += slice.reduce((n, m) => n + m.body.cveIds.length, 0);
      } catch (err) {
        mitreFailed += slice.reduce((n, m) => n + m.body.cveIds.length, 0);
        mitreError = String(err);
      }
    }
  }

  await markIngestFinished(
    env,
    'MITRE',
    mitreError ? (mitreEnqueued > 0 ? 'PARTIAL' : 'FAILED') : cweGapOverCap > 0 ? 'PARTIAL' : 'OK',
    mitreEnqueued,
    mitreFailed + cweGapOverCap,
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
          nvdProcessed + mitreEnqueued + epssProcessed,
          nvdFailed + mitreFailed + epssFailed,
          Date.now() - startedAt,
        ],
        indexes: ['ingest_run'],
      }),
    ),
  );
}
