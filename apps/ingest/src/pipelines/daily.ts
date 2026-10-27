import type { Env } from '../types';
import { fetchNvdDelta } from '../adapters/nvd';
import { fetchMitreDelta } from '../adapters/mitre';
import { fetchEpssCsv } from '../adapters/epss';
import type { EpssPatch } from '@threat-lens/contracts';
import { processRecord, applyEpssPatchBatch } from '../lib/server/processRecord';
import { markIngestStarted, markIngestFinished } from '../lib/server/ingestRun';

const DELTA_WINDOW_MS = 48 * 60 * 60 * 1000; // 48-hour lookback for safety overlap
const EPSS_BATCH_SIZE = 200; // chunk size for the batched change-detection read

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
    env, 'NVD',
    nvdError ? 'FAILED' : nvdFailed > 0 ? 'PARTIAL' : 'OK',
    nvdProcessed, nvdFailed, nvdError,
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
    env, 'MITRE',
    mitreError ? 'FAILED' : mitreFailed > 0 ? 'PARTIAL' : 'OK',
    mitreProcessed, mitreFailed, mitreError,
  );

  // ── EPSS ──────────────────────────────────────────────────────────────────
  let epssProcessed = 0;
  let epssFailed = 0;
  let epssError: string | undefined;

  let epssBatch: EpssPatch[] = [];
  const flushEpssBatch = async () => {
    if (epssBatch.length === 0) return;
    const batch = epssBatch;
    epssBatch = [];
    try {
      await applyEpssPatchBatch(batch, env, ctx);
      epssProcessed += batch.length;
    } catch {
      epssFailed += batch.length;
    }
  };

  try {
    for await (const patch of fetchEpssCsv()) {
      epssBatch.push(patch);
      if (epssBatch.length >= EPSS_BATCH_SIZE) {
        await flushEpssBatch();
      }
    }
    await flushEpssBatch();
  } catch (err) {
    epssError = String(err);
    epssFailed += epssBatch.length;
  }

  await markIngestFinished(
    env, 'EPSS',
    epssError ? 'FAILED' : epssFailed > 0 ? 'PARTIAL' : 'OK',
    epssProcessed, epssFailed, epssError,
  );

  ctx.waitUntil(
    Promise.resolve(env.ANALYTICS.writeDataPoint({
      blobs: [
        'DAILY_DELTA',
        nvdError ?? mitreError ?? epssError ?? 'OK',
        'NVD+MITRE+EPSS', '', '', '', '',
      ],
      doubles: [
        startedAt, Date.now(),
        nvdProcessed + mitreProcessed + epssProcessed,
        nvdFailed + mitreFailed + epssFailed,
        Date.now() - startedAt,
      ],
      indexes: ['ingest_run'],
    })),
  );
}
