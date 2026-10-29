import type { OsvFetchItem, OsvQueueMessage } from '@threat-lens/contracts';
import {
  fetchOsvModifiedSince,
  fetchOsvRecord,
  normalizeOsvRecord,
  OSV_ECOSYSTEM_DIRS,
  OSV_ID_ALLOW,
} from '../adapters/osv';
import { markIngestFinished, markIngestStarted } from '../lib/server/ingestRun';
import { applyOsvPatchBatch, type OsvFetchResult } from '../lib/server/osvPatch';
import type { Env } from '../types';

// ── Discovery (producer) tuning ─────────────────────────────────────────────

/** First-ever run: no osv_record_state rows yet to derive a cursor from.
 *  Per the agreed scope: forward-only, starting 72h before go-live. */
const FIRST_RUN_LOOKBACK_MS = 72 * 60 * 60 * 1000;

/**
 * Cursor safety overlap. The cursor is `MAX(modified_at)` across everything
 * this path has ever written, minus this overlap — NOT a tight watermark.
 * Reason: an item that hits FETCH_FAILED (transient network error) in
 * runOsvFetchBatch is deliberately left unwritten (see osvPatch.ts), so it
 * never updates osv_record_state and can't bump the cursor itself. If some
 * OTHER, newer item from the same discovery run DID get written, the raw
 * MAX(modified_at) would jump past the failed item's timestamp, and the
 * next run's newest-first CSV scan would stop before ever reaching it again
 * — a silent, permanent gap. A full daily-cron-interval overlap guarantees
 * every item gets at least one full extra run to be reconsidered. This is
 * cheap to do: the CSV re-scan it causes is bounded by MAX_LINES_PER_DIR
 * regardless, and re-seen ids that genuinely haven't changed are dropped by
 * the modified_at-equality check in filterUnchangedOsvIds before any OSV API
 * call happens.
 */
const CURSOR_SAFETY_OVERLAP_MS = 24 * 60 * 60 * 1000;

/** Defensive backstop per ecosystem dir's CSV stream — in steady state the
 *  sinceMs cutoff is hit within the first handful of lines. */
const MAX_LINES_PER_DIR = 2000;

/** D1's bound-parameter cap is 100 per query on every plan. */
const STATE_SELECT_CHUNK_SIZE = 100;

/**
 * Hard cap on the COMBINED raw candidate count (deduped across all 8
 * ecosystem dirs) allowed into filterUnchangedOsvIds — applied BEFORE that
 * function issues a single SELECT, not just before the final enqueue step.
 *
 * MAX_LINES_PER_DIR (2000) only bounds a single directory's CSV scan;
 * combined across all 8 dirs that allows up to 16,000 unique candidates in
 * one run (realistically reachable after an extended backlog, which this
 * project has repeatedly experienced, or even a busy first run). At
 * STATE_SELECT_CHUNK_SIZE(100)-per-query, filtering all of them would need
 * up to 160 SELECTs — over 3x the ~50-query Free-tier budget this whole
 * architecture is built around (same budget epssQueue.ts/daily.ts's EPSS
 * section were built to respect).
 *
 * 2000 = 4x MAX_NEW_WORK_PER_RUN: generous headroom for change-detection to
 * filter out unchanged ids and still surface up to MAX_NEW_WORK_PER_RUN
 * genuinely new/changed ones, while capping filterUnchangedOsvIds at 20
 * SELECTs (2000/100) — comfortable room under the 50-query budget alongside
 * this invocation's other couple of D1 queries (the cursor MAX query, the
 * re-link SELECT).
 */
const MAX_DISCOVERY_CANDIDATES = 2000;

/** Bounded re-link pass: recent CVE_NOT_INGESTED rows only (idx_osv_state_relink
 *  covers this), oldest-first, capped. */
const RELINK_WINDOW_MS = 14 * 24 * 60 * 60 * 1000;
const RELINK_LIMIT = 90;

/** Total new/re-link work enqueued per discovery run. */
const MAX_NEW_WORK_PER_RUN = 500;

/**
 * OSV_FETCH message chunk size.
 *
 * Measured (not estimated) 2026-10-29 via `JSON.stringify` on a realistic
 * sample OsvFetchItem ({osvId: 'GHSA-jf75-q64q-g65r', ecosystemDir:
 * 'crates.io', modified: a 30-char ns-precision ISO string}): ~103
 * bytes/item once wrapped in the `{kind:'OSV_FETCH', items:[...]}` envelope
 * (500 items measured at 51,530 bytes total). At 20 items/message that's
 * ~2.1KB — about 1.6% of Cloudflare Queues' 128KB per-message cap, i.e. byte
 * size is nowhere near the binding constraint here (contrast EPSS, where it
 * was: 1,500 EpssPatch/message measured at ~154KB, over the cap).
 *
 * The actual constraint for THIS chunk size is the external HTTP subrequest
 * budget: runOsvFetchBatch does one `fetch()` to api.osv.dev per item, all
 * within a single queue-consumer invocation. Keeping this at 20 leaves
 * comfortable headroom under Cloudflare's per-invocation subrequest cap
 * alongside this same invocation's handful of D1 queries, with margin for
 * the bounded-concurrency fetch loop's overhead.
 */
const OSV_FETCH_CHUNK_SIZE = 20;

/** Raw OSV JSON truncated to this many bytes before being written to
 *  cve_quarantine.payload (task-specified). */
const QUARANTINE_PAYLOAD_MAX_BYTES = 4096;

/** Bounded fetch concurrency for runOsvFetchBatch — stays well under the
 *  ~6-simultaneous-connection-per-invocation ceiling noted in daily.ts's
 *  EPSS section. */
const FETCH_CONCURRENCY = 5;

/**
 * OSV discovery (queue consumer: osv-ingest, message kind OSV_DISCOVER).
 *
 * Runs as its own queue-consumer invocation — NOT inline in the shared
 * daily cron invocation — specifically so it gets its own fresh 50-D1-query
 * budget separate from NVD/MITRE/EPSS's (see pipelines/daily.ts, which only
 * sends the lightweight OSV_DISCOVER kick-off message).
 *
 * 1. Derive a cursor from the newest `modified_at` this path has ever
 *    written (or a 72h-before-go-live default on the very first run).
 * 2. Stream all 8 ecosystem directories' modified_id.csv newer than that
 *    cursor, deduping ids across directories.
 * 3. Cap the combined candidate count across all 8 dirs at
 *    MAX_DISCOVERY_CANDIDATES (oldest-first), THEN drop candidates whose
 *    modified_at hasn't actually changed from what's already stored (cheap
 *    batched read, no OSV API calls yet) — the cap is applied before this
 *    read, not just before the final enqueue step, so a 16,000-candidate
 *    worst case can't blow the per-invocation D1 query budget.
 * 4. Run a bounded re-link pass over recent CVE_NOT_INGESTED rows — treated
 *    identically to newly-discovered candidates from here on, so promoting
 *    them to LINKED once NVD/MITRE has since ingested their CVE needs no
 *    separate code path.
 * 5. Cap combined work at MAX_NEW_WORK_PER_RUN, oldest-first, chunk into
 *    OSV_FETCH messages, and sendBatch them.
 */
export async function runOsvDiscovery(env: Env, ctx: ExecutionContext): Promise<void> {
  const startedAt = Date.now();
  await markIngestStarted(env, 'OSV');

  let enqueued = 0;
  let failed = 0;
  let lastError: string | undefined;

  try {
    const cursorRow = await env.DB.prepare(
      `SELECT MAX(modified_at) AS max_modified FROM osv_record_state`,
    ).first<{ max_modified: string | null }>();
    const maxModifiedMs = cursorRow?.max_modified ? Date.parse(cursorRow.max_modified) : Number.NaN;
    const sinceMs = Number.isFinite(maxModifiedMs)
      ? maxModifiedMs - CURSOR_SAFETY_OVERLAP_MS
      : startedAt - FIRST_RUN_LOOKBACK_MS;

    const seen = new Map<string, OsvFetchItem>();
    for (const dir of OSV_ECOSYSTEM_DIRS) {
      try {
        for await (const entry of fetchOsvModifiedSince(dir, sinceMs, MAX_LINES_PER_DIR)) {
          if (!OSV_ID_ALLOW.test(entry.osvId)) continue;
          const prior = seen.get(entry.osvId);
          if (!prior || entry.modifiedMs > Date.parse(prior.modified)) {
            seen.set(entry.osvId, {
              osvId: entry.osvId,
              ecosystemDir: dir,
              modified: entry.modified,
            });
          }
        }
      } catch (err) {
        // One ecosystem dir's GCS fetch failing shouldn't block the other 7.
        failed++;
        lastError = String(err);
      }
    }

    // Cap the COMBINED candidate set (across all 8 dirs) BEFORE issuing any
    // change-detection SELECT — see MAX_DISCOVERY_CANDIDATES. Sorted
    // oldest-first, same priority order as newWork's own final
    // MAX_NEW_WORK_PER_RUN cap below, so this pre-filter cap never discards
    // a candidate that would otherwise have survived that later cap.
    const candidates = new Map(
      [...seen.values()]
        .sort((a, b) => Date.parse(a.modified) - Date.parse(b.modified))
        .slice(0, MAX_DISCOVERY_CANDIDATES)
        .map((item) => [item.osvId, item]),
    );

    const unchangedIds = await filterUnchangedOsvIds(env, [...candidates.keys()], candidates);
    for (const id of unchangedIds) candidates.delete(id);

    const newWork = [...candidates.values()];

    const relink = await env.DB.prepare(
      `SELECT osv_id, ecosystem_dir, modified_at FROM osv_record_state
       WHERE status = 'CVE_NOT_INGESTED' AND first_seen_at >= ?
       ORDER BY first_seen_at ASC LIMIT ?`,
    )
      .bind(startedAt - RELINK_WINDOW_MS, RELINK_LIMIT)
      .all<{ osv_id: string; ecosystem_dir: string; modified_at: string }>();

    for (const row of relink.results) {
      if (!newWork.some((w) => w.osvId === row.osv_id)) {
        newWork.push({
          osvId: row.osv_id,
          ecosystemDir: row.ecosystem_dir,
          modified: row.modified_at,
        });
      }
    }

    newWork.sort((a, b) => Date.parse(a.modified) - Date.parse(b.modified));
    const capped = newWork.slice(0, MAX_NEW_WORK_PER_RUN);

    const messages: { body: OsvQueueMessage }[] = [];
    for (let i = 0; i < capped.length; i += OSV_FETCH_CHUNK_SIZE) {
      messages.push({
        body: { kind: 'OSV_FETCH', items: capped.slice(i, i + OSV_FETCH_CHUNK_SIZE) },
      });
    }

    if (messages.length > 0) {
      try {
        // sendBatch caps at 100 messages/256KB per call. With
        // MAX_NEW_WORK_PER_RUN=500 and OSV_FETCH_CHUNK_SIZE=20 this is at
        // most 25 messages (~25 * 2.1KB ≈ 52.5KB) — one call, comfortably
        // under both limits.
        await env.OSV_QUEUE.sendBatch(messages);
        enqueued = capped.length;
      } catch (err) {
        failed += capped.length;
        lastError = String(err);
      }
    }
  } catch (err) {
    lastError = String(err);
    failed++;
  }

  await markIngestFinished(
    env,
    'OSV',
    lastError && enqueued === 0 ? 'FAILED' : failed > 0 ? 'PARTIAL' : 'OK',
    enqueued,
    failed,
    lastError,
  );

  ctx.waitUntil(
    Promise.resolve(
      env.ANALYTICS.writeDataPoint({
        blobs: ['OSV_DISCOVER', lastError ?? 'OK', 'OSV', '', '', '', ''],
        doubles: [startedAt, Date.now(), enqueued, failed, Date.now() - startedAt],
        indexes: ['ingest_run'],
      }),
    ),
  );
}

async function filterUnchangedOsvIds(
  env: Env,
  candidateIds: string[],
  seen: Map<string, OsvFetchItem>,
): Promise<string[]> {
  const unchanged: string[] = [];
  for (let i = 0; i < candidateIds.length; i += STATE_SELECT_CHUNK_SIZE) {
    const chunk = candidateIds.slice(i, i + STATE_SELECT_CHUNK_SIZE);
    if (chunk.length === 0) continue;
    const placeholders = chunk.map(() => '?').join(',');
    const { results } = await env.DB.prepare(
      `SELECT osv_id, modified_at FROM osv_record_state WHERE osv_id IN (${placeholders})`,
    )
      .bind(...chunk)
      .all<{ osv_id: string; modified_at: string }>();
    for (const row of results) {
      const item = seen.get(row.osv_id);
      if (item && item.modified === row.modified_at) unchanged.push(row.osv_id);
    }
  }
  return unchanged;
}

/**
 * OSV fetch-batch (queue consumer: osv-ingest, message kind OSV_FETCH).
 *
 * One message = one invocation (max_batch_size = 1 in wrangler.toml), so
 * this gets its own fresh 50-D1-query budget same as epssQueue.ts's
 * consumer. Fetches each item from the OSV API (bounded concurrency),
 * normalizes it, and hands the whole batch to applyOsvPatchBatch for the
 * actual D1 write (a single db.batch() call there).
 */
export async function runOsvFetchBatch(
  items: OsvFetchItem[],
  env: Env,
  ctx: ExecutionContext,
): Promise<void> {
  const t0 = Date.now();
  if (items.length === 0) return;

  const results: OsvFetchResult[] = new Array(items.length);

  for (let i = 0; i < items.length; i += FETCH_CONCURRENCY) {
    const slice = items.slice(i, i + FETCH_CONCURRENCY);
    const settled = await Promise.all(slice.map((item) => fetchAndNormalize(item)));
    settled.forEach((r, idx) => {
      results[i + idx] = r;
    });
  }

  const applyResult = await applyOsvPatchBatch(results, env, ctx);

  env.ANALYTICS.writeDataPoint({
    blobs: ['OSV_FETCH', 'OK', '', '', '', '', ''],
    doubles: [
      Date.now() - t0,
      items.length,
      applyResult.written,
      applyResult.skipped,
      applyResult.unlinked,
      applyResult.quarantined,
    ],
    indexes: ['osv_consumer_processed'],
  });
}

async function fetchAndNormalize(item: OsvFetchItem): Promise<OsvFetchResult> {
  if (!OSV_ID_ALLOW.test(item.osvId)) {
    return {
      item,
      outcome: 'MALFORMED',
      rawPayloadForQuarantine: '',
      errorMessage: `invalid OSV id shape: ${JSON.stringify(item.osvId)}`,
    };
  }

  try {
    const raw = await fetchOsvRecord(item.osvId);
    if (raw === null) {
      return { item, outcome: 'NOT_FOUND' };
    }

    const patch = normalizeOsvRecord(raw);
    if (!patch) {
      return {
        item,
        outcome: 'MALFORMED',
        rawPayloadForQuarantine: truncateForQuarantine(raw),
        errorMessage: 'normalizeOsvRecord returned null (unexpected record shape)',
      };
    }

    return { item, outcome: 'OK', patch };
  } catch (err) {
    return { item, outcome: 'FETCH_FAILED', errorMessage: String(err) };
  }
}

function truncateForQuarantine(raw: unknown): string {
  let s: string;
  try {
    s = JSON.stringify(raw);
  } catch {
    s = String(raw);
  }
  const bytes = new TextEncoder().encode(s);
  if (bytes.length <= QUARANTINE_PAYLOAD_MAX_BYTES) return s;
  return new TextDecoder('utf-8').decode(bytes.slice(0, QUARANTINE_PAYLOAD_MAX_BYTES));
}

function isValidOsvFetchItem(x: unknown): x is OsvFetchItem {
  if (typeof x !== 'object' || x === null) return false;
  const i = x as Record<string, unknown>;
  return (
    typeof i.osvId === 'string' &&
    typeof i.ecosystemDir === 'string' &&
    typeof i.modified === 'string'
  );
}

/** Defensive runtime check on a dequeued osv-ingest message body — mirrors
 *  epssQueue.ts's isValidPatch: a malformed body can never succeed no
 *  matter how many times it's retried, so index.ts's queue() handler acks
 *  (drops) it immediately instead of retrying into the DLQ. */
export function isValidOsvQueueMessage(m: unknown): m is OsvQueueMessage {
  if (typeof m !== 'object' || m === null) return false;
  const msg = m as Record<string, unknown>;
  if (msg.kind === 'OSV_DISCOVER') return true;
  if (msg.kind === 'OSV_FETCH')
    return Array.isArray(msg.items) && msg.items.every(isValidOsvFetchItem);
  return false;
}
