import type { EpssPatch } from '@threat-lens/contracts';
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

  await Promise.all([
    markIngestStarted(env, 'NVD'),
    markIngestStarted(env, 'MITRE'),
    markIngestStarted(env, 'EPSS'),
  ]);

  // ── NVD ──────────────────────────────────────────────────────────────────
  let nvdProcessed = 0;
  let nvdFailed = 0;
  let nvdError: string | undefined;

  try {
    for await (const record of fetchNvdDelta(env.NVD_API_KEY, startDate, endDate)) {
      try {
        await processRecord(record, env, ctx);
        nvdProcessed++;
      } catch {
        nvdFailed++;
      }
    }
  } catch (err) {
    nvdError = String(err);
    nvdFailed++;
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
