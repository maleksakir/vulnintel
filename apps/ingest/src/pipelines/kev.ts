import type { KevPatch } from '@threat-lens/contracts';
import { fetchKevCatalog } from '../adapters/kev';
import { markIngestFinished, markIngestStarted } from '../lib/server/ingestRun';
import type { Env } from '../types';

// KEV_QUEUE message bounds.
//
// This used to chunk by COUNT alone, at 500 patches per message, justified by
// an estimate of "~250 bytes/patch pessimistic". Production disagreed: every
// KEV run since that code shipped failed with
//
//   message in batch has length 187596 bytes which exceeds single message limit
//
// 187,596 / 500 = 375 bytes per patch, because CISA's kevRequiredAction is
// routinely a full remediation sentence and has no upstream length bound. The
// catalog is the actively-exploited-vulnerability feed, so a failing KEV run
// means real KEV-listed CVEs go unflagged — the exact safety-relevant gap the
// producer/consumer split was introduced to prevent, reintroduced by a
// guessed constant.
//
// Chunking is now driven by MEASURED serialized size, the same way the NVD
// producer does it (pipelines/nvdProducer.ts), with the count cap kept only as
// a secondary bound. Guessing bytes per record is what failed; measuring them
// cannot.
const KEV_QUEUE_MAX_BYTES = 100_000;
const KEV_QUEUE_MAX_PATCHES = 500;
// `{"patches":[...]}`'s own wrapper plus per-element comma overhead — a small
// fixed allowance rather than exact structural accounting, matching
// NVD_MESSAGE_WRAPPER_OVERHEAD_BYTES.
const KEV_MESSAGE_WRAPPER_OVERHEAD_BYTES = 256;

function byteLength(s: string): number {
  return new TextEncoder().encode(s).length;
}

/**
 * Split patches into messages that each serialize to under
 * KEV_QUEUE_MAX_BYTES. A single patch whose own serialized size exceeds the
 * budget is dropped rather than enqueued: it could not be sent even alone,
 * and silently retrying it forever would stall the catalog.
 */
export function chunkKevPatches(patches: KevPatch[]): {
  messages: KevPatch[][];
  oversized: KevPatch[];
} {
  const messages: KevPatch[][] = [];
  const oversized: KevPatch[] = [];
  let current: KevPatch[] = [];
  let currentBytes = 0;

  for (const patch of patches) {
    const patchBytes = byteLength(JSON.stringify(patch));
    if (patchBytes + KEV_MESSAGE_WRAPPER_OVERHEAD_BYTES > KEV_QUEUE_MAX_BYTES) {
      oversized.push(patch);
      continue;
    }
    if (
      current.length >= KEV_QUEUE_MAX_PATCHES ||
      currentBytes + patchBytes + KEV_MESSAGE_WRAPPER_OVERHEAD_BYTES > KEV_QUEUE_MAX_BYTES
    ) {
      if (current.length > 0) messages.push(current);
      current = [];
      currentBytes = 0;
    }
    current.push(patch);
    currentBytes += patchBytes + 1; // +1 inter-element comma
  }
  if (current.length > 0) messages.push(current);

  return { messages, oversized };
}
// Cloudflare Queues' sendBatch() caps at 100 messages per call. At ~1,800
// catalog entries and ~375 bytes each, size-aware chunking yields ~7 messages,
// so one call suffices today; this loop is defensive against the catalog
// growing (same reasoning as the MITRE/OSV sendBatch loops elsewhere in this
// worker).
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

    const { messages: chunks, oversized } = chunkKevPatches(patches);
    if (oversized.length > 0) {
      // Visible, not silent: a patch too large to ever enqueue is a data
      // problem upstream, and KEV data going missing must be noticeable.
      failed += oversized.length;
      lastError = `${oversized.length} KEV patch(es) exceeded the per-message byte budget (first: ${oversized[0]?.cveId})`;
    }
    const messages = chunks.map((patches) => ({ body: { patches } }));

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
