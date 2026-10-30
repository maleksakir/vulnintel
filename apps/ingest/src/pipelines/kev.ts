import type { KevPatch } from '@threat-lens/contracts';
import { fetchKevCatalog } from '../adapters/kev';
import { markIngestFinished, markIngestStarted } from '../lib/server/ingestRun';
import type { Env } from '../types';

// KEV_QUEUE message chunk size. CISA's KEV catalog is ~1,000+ entries total
// (a full snapshot on every run, not a delta). A KevPatch is a flat shape —
// cveId + two unix-ms numbers + the free-text kevRequiredAction string — so
// most patches serialize to ~120-180 bytes. kevRequiredAction has no hard
// upstream length bound, though (CISA sometimes writes a full remediation
// sentence), so a conservative 500/chunk keeps a worst-case message well
// under Cloudflare Queues' 128KB (131,072-byte) cap: even at a pessimistic
// ~250 bytes/patch, 500 patches ≈ 125KB — and realistic catalogs measure
// far smaller. (Don't raise this without re-measuring actual serialized
// size, the same caveat EPSS_MESSAGE_CHUNK_SIZE carries in daily.ts.)
const KEV_MESSAGE_CHUNK_SIZE = 500;
// Cloudflare Queues' sendBatch() caps at 100 messages per call. At
// ~1,000 catalog entries / KEV_MESSAGE_CHUNK_SIZE (500) = ~2 messages, one
// call always suffices today; this loop is purely defensive against the
// catalog growing or the chunk size shrinking later (same reasoning as the
// MITRE/OSV sendBatch loops elsewhere in this worker).
const QUEUES_SENDBATCH_MAX_MESSAGES = 100;

/**
 * KEV fast-lane (the every-6-hours cron slot) — PRODUCER ONLY.
 *
 * Downloads the full CISA KEV catalog snapshot, chunks it, and enqueues the
 * chunks onto KEV_QUEUE. It does NOT apply any patch to D1 itself — that work
 * moved to pipelines/kevQueue.ts's consumer, which runs as a separate
 * invocation with its own fresh 50-D1-query budget.
 *
 * Why the split: the old inline `applyKevPatch`-per-entry loop issued a
 * change-detect SELECT per catalog entry inside this single cron invocation,
 * so even a zero-change run spent ~1,000 D1 queries and got killed mid-run by
 * the platform after ~50 (the Free plan's per-invocation D1-query cap) — the
 * exact silent-failure class EPSS and NVD independently hit (see CLAUDE.md's
 * D1-caps bullet and docs/EXECUTION_PLAN.md's KEV row). Because KEV runs
 * every 6 hours and tracks actively-exploited vulnerabilities, a silently
 * truncated run is a safety-relevant gap, not just staleness — a real
 * KEV-listed CVE could go unflagged.
 *
 * `fetchKevCatalog()` is a single HTTP fetch + in-memory map — zero D1 — so
 * it is safe to run inline here. Because of the split, processed/failed and
 * the status passed to markIngestFinished describe the ENQUEUE outcome (did
 * every fetched entry make it onto KEV_QUEUE), not the D1-apply outcome —
 * per-entry apply success/failure happens later in the consumer, outside this
 * cron run's visibility (see kev_consumer_processed analytics in kevQueue.ts).
 */
export async function runKevFastLane(env: Env, ctx: ExecutionContext): Promise<void> {
  const startedAt = Date.now();
  await markIngestStarted(env, 'KEV');

  let enqueued = 0;
  let failed = 0;
  let lastError: string | undefined;

  try {
    const patches = await fetchKevCatalog();

    const messages: { body: { patches: KevPatch[] } }[] = [];
    for (let i = 0; i < patches.length; i += KEV_MESSAGE_CHUNK_SIZE) {
      messages.push({ body: { patches: patches.slice(i, i + KEV_MESSAGE_CHUNK_SIZE) } });
    }

    for (let i = 0; i < messages.length; i += QUEUES_SENDBATCH_MAX_MESSAGES) {
      const slice = messages.slice(i, i + QUEUES_SENDBATCH_MAX_MESSAGES);
      try {
        await env.KEV_QUEUE.sendBatch(slice);
        enqueued += slice.reduce((n, m) => n + m.body.patches.length, 0);
      } catch (err) {
        failed += slice.reduce((n, m) => n + m.body.patches.length, 0);
        lastError = String(err);
      }
    }
  } catch (err) {
    lastError = String(err);
    failed++;
  }

  await markIngestFinished(
    env,
    'KEV',
    lastError && enqueued === 0 ? 'FAILED' : failed > 0 ? 'PARTIAL' : 'OK',
    enqueued,
    failed,
    lastError,
  );

  // NOTE: the `threat:kev:list` KV key is now invalidated by the CONSUMER
  // (pipelines/kevQueue.ts, via applyKevPatchBatch) only when an entry
  // actually changes — not unconditionally here on every 6-hourly run. A
  // snapshot with zero changes should not burn a KV delete against the
  // 1,000/day write+delete cap, which the old unconditional delete here did
  // 4x/day regardless of whether anything changed.
  ctx.waitUntil(
    Promise.resolve(
      env.ANALYTICS.writeDataPoint({
        blobs: ['KEV_FAST_LANE', lastError ? 'PARTIAL' : 'OK', 'KEV', '', '', '', ''],
        doubles: [startedAt, Date.now(), enqueued, failed, Date.now() - startedAt],
        indexes: ['ingest_run'],
      }),
    ),
  );
}
