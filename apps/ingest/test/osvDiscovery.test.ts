import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import type { OsvFetchItem, OsvQueueMessage } from '@threat-lens/contracts';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { OSV_ECOSYSTEM_DIRS } from '../src/adapters/osv';
import { runOsvDiscovery } from '../src/pipelines/osv';
import { seedOsvState, spyOnBindings, testEnv, useCleanBindings } from './helpers';

// Coverage for runOsvDiscovery's producer-side logic itself (cursor
// derivation, cross-directory dedup, skip-unchanged filtering, the
// CVE_NOT_INGESTED re-link pass, and the MAX_NEW_WORK_PER_RUN cap) — distinct
// from osvQueueDispatch.test.ts, which only checks that index.ts routes
// OSV_DISCOVER to this function at all, and osvPatchBatch.test.ts, which
// covers the downstream D1-write path, not discovery.

type Dir = (typeof OSV_ECOSYSTEM_DIRS)[number];

function requestUrl(input: RequestInfo | URL): string {
  if (typeof input === 'string') return input;
  if (input instanceof URL) return input.href;
  return input.url;
}

/** Stubs the per-ecosystem-directory GCS `modified_id.csv` endpoints. Any
 *  directory not given an explicit body returns an empty (no-op) response —
 *  all 8 directories are scanned on every run, so every one needs *some*
 *  stubbed response or the adapter throws "unexpected fetch() call". */
function stubGcs(perDir: Partial<Record<Dir, string>>): void {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      const url = requestUrl(input);
      const dir = OSV_ECOSYSTEM_DIRS.find((d) =>
        url.includes(`/osv-vulnerabilities/${d}/modified_id.csv`),
      );
      if (dir) return new Response(perDir[dir] ?? '', { status: 200 });
      throw new Error(`unexpected fetch() call in test: ${url}`);
    }),
  );
}

function csvLine(modifiedIso: string, osvId: string): string {
  return `${modifiedIso},${osvId}`;
}

function isoAt(offsetMs: number): string {
  return new Date(Date.now() + offsetMs).toISOString();
}

async function runDiscovery(): Promise<{
  messages: OsvQueueMessage[];
  items: OsvFetchItem[];
}> {
  const sendBatchSpy = vi.spyOn(testEnv.OSV_QUEUE, 'sendBatch');
  const ctx = createExecutionContext();
  await runOsvDiscovery(testEnv, ctx);
  await waitOnExecutionContext(ctx);

  const messages = sendBatchSpy.mock.calls.flatMap(([batch]) =>
    (batch as { body: OsvQueueMessage }[]).map((m) => m.body),
  );
  const items = messages.flatMap((m) => (m.kind === 'OSV_FETCH' ? m.items : []));
  return { messages, items };
}

describe('runOsvDiscovery', () => {
  useCleanBindings();

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('first run (no stored state): uses the 72h-before-go-live lookback, enqueueing only entries inside that window', async () => {
    stubGcs({
      npm: [
        csvLine(isoAt(-1 * 60 * 60 * 1000), 'GHSA-aaaa-aaaa-aaaa'), // 1h ago — inside 72h window
        csvLine(isoAt(-100 * 60 * 60 * 1000), 'GHSA-bbbb-bbbb-bbbb'), // 100h ago — outside window
      ].join('\n'),
    });

    const { items } = await runDiscovery();
    expect(items.map((i) => i.osvId)).toEqual(['GHSA-aaaa-aaaa-aaaa']);
  }, 30_000);

  it('subsequent run: derives the cursor from MAX(stored modified_at) minus the 24h safety overlap, not just the most recent run', async () => {
    const cursorBase = isoAt(-5 * 24 * 60 * 60 * 1000); // 5 days ago
    await seedOsvState({
      osvId: 'GHSA-9999-9999-9999',
      modifiedAt: cursorBase,
      status: 'LINKED',
    });
    // sinceMs = (now - 5d) - 24h-overlap = now - 6d.

    stubGcs({
      npm: [
        csvLine(isoAt(-1 * 24 * 60 * 60 * 1000), 'GHSA-cccc-cccc-cccc'), // 1d ago — inside
        csvLine(isoAt(-10 * 24 * 60 * 60 * 1000), 'GHSA-dddd-dddd-dddd'), // 10d ago — before cursor, excluded
      ].join('\n'),
    });

    const { items } = await runDiscovery();
    expect(items.map((i) => i.osvId)).toEqual(['GHSA-cccc-cccc-cccc']);
  }, 30_000);

  it('dedupes an id appearing in multiple ecosystem directories, keeping the most-recently-modified sighting', async () => {
    const olderSeen = isoAt(-5 * 60 * 60 * 1000);
    const newerSeen = isoAt(-1 * 60 * 60 * 1000);
    stubGcs({
      npm: csvLine(olderSeen, 'GHSA-eeee-eeee-eeee'),
      Go: csvLine(newerSeen, 'GHSA-eeee-eeee-eeee'),
    });

    const { items } = await runDiscovery();
    const matches = items.filter((i) => i.osvId === 'GHSA-eeee-eeee-eeee');
    expect(matches).toHaveLength(1); // not enqueued twice
    expect(matches[0]?.modified).toBe(newerSeen);
    expect(matches[0]?.ecosystemDir).toBe('Go'); // the directory that carried the newer sighting
  }, 30_000);

  it('skips a candidate whose modified_at is unchanged vs. stored state (skip-if-unchanged), while still enqueueing a genuinely new one', async () => {
    const unchangedModified = isoAt(-2 * 60 * 60 * 1000);
    await seedOsvState({
      osvId: 'GHSA-ffff-ffff-ffff',
      ecosystemDir: 'npm',
      modifiedAt: unchangedModified,
      status: 'LINKED',
    });

    stubGcs({
      npm: [
        csvLine(unchangedModified, 'GHSA-ffff-ffff-ffff'), // same modified_at as stored — skip
        csvLine(isoAt(-1 * 60 * 60 * 1000), 'GHSA-1111-1111-1111'), // genuinely new
      ].join('\n'),
    });

    const { items } = await runDiscovery();
    expect(items.map((i) => i.osvId)).toEqual(['GHSA-1111-1111-1111']);
  }, 30_000);

  it('re-link pass: re-queues a CVE_NOT_INGESTED row inside the 14-day window, and leaves one outside the window alone', async () => {
    await seedOsvState({
      osvId: 'GHSA-2222-2222-2222',
      status: 'CVE_NOT_INGESTED',
      cveIds: 'CVE-2026-61000',
      modifiedAt: isoAt(-10 * 24 * 60 * 60 * 1000),
      firstSeenAt: Date.now() - 2 * 24 * 60 * 60 * 1000, // 2 days ago — inside RELINK_WINDOW_MS (14d)
    });
    await seedOsvState({
      osvId: 'GHSA-3333-3333-3333',
      status: 'CVE_NOT_INGESTED',
      cveIds: 'CVE-2026-61001',
      modifiedAt: isoAt(-20 * 24 * 60 * 60 * 1000),
      firstSeenAt: Date.now() - 20 * 24 * 60 * 60 * 1000, // 20 days ago — outside the window
    });
    // No new CSV work this run — isolates the re-link pass itself.
    stubGcs({});

    const { items } = await runDiscovery();
    expect(items.map((i) => i.osvId)).toEqual(['GHSA-2222-2222-2222']);
  }, 30_000);

  it('does not re-queue a LINKED or NO_CVE_ALIAS row via the re-link pass (only CVE_NOT_INGESTED is a re-link candidate)', async () => {
    await seedOsvState({
      osvId: 'GHSA-4444-4444-4444',
      status: 'LINKED',
      modifiedAt: isoAt(-1 * 24 * 60 * 60 * 1000),
      firstSeenAt: Date.now() - 1 * 24 * 60 * 60 * 1000,
    });
    stubGcs({});

    const { items } = await runDiscovery();
    expect(items).toHaveLength(0);
  }, 30_000);

  it('enforces the combined per-run work cap, keeping the oldest candidates (not the newest) when supply exceeds it', async () => {
    // 550 candidates, listed newest-first (real GCS CSV order), spaced 3
    // minutes apart so all 550 fit comfortably inside the 72h first-run
    // lookback. Index 0 = newest, index 549 = oldest.
    const TOTAL = 550;
    const lines: string[] = [];
    for (let i = 0; i < TOTAL; i++) {
      const id = `GHSA-${String(1000 + i).padStart(4, '0')}-aaaa-bbbb`;
      lines.push(csvLine(isoAt(-i * 3 * 60 * 1000), id));
    }
    stubGcs({ npm: lines.join('\n') });

    const { items } = await runDiscovery();

    expect(items.length).toBe(500); // MAX_NEW_WORK_PER_RUN

    // Oldest-first prioritization: the kept set must be the 500 OLDEST
    // candidates (highest indices, i.e. the last 500 lines in the
    // newest-first CSV), not the 500 newest.
    const keptIds = new Set(items.map((i) => i.osvId));
    for (let i = 0; i < TOTAL - 500; i++) {
      const droppedId = `GHSA-${String(1000 + i).padStart(4, '0')}-aaaa-bbbb`;
      expect(keptIds.has(droppedId)).toBe(false);
    }
    for (let i = TOTAL - 500; i < TOTAL; i++) {
      const keptId = `GHSA-${String(1000 + i).padStart(4, '0')}-aaaa-bbbb`;
      expect(keptIds.has(keptId)).toBe(true);
    }
  }, 60_000);

  it('D1 discipline: no IN(...) SELECT exceeds 100 bound params, and the whole invocation stays well under the 50-query Free-plan cap', async () => {
    const TOTAL = 550;
    const lines: string[] = [];
    for (let i = 0; i < TOTAL; i++) {
      lines.push(
        csvLine(isoAt(-i * 3 * 60 * 1000), `GHSA-${String(2000 + i).padStart(4, '0')}-cccc-dddd`),
      );
    }
    stubGcs({ npm: lines.join('\n') });

    const spies = spyOnBindings();
    const ctx = createExecutionContext();
    await runOsvDiscovery(testEnv, ctx);
    await waitOnExecutionContext(ctx);

    const selectCalls = spies.boundCalls.filter((c) => /WHERE osv_id IN/i.test(c.sql));
    expect(selectCalls.length).toBeGreaterThan(1); // actually chunked
    for (const call of selectCalls) {
      expect(call.paramCount).toBeLessThanOrEqual(100);
    }

    // Total D1 queries this invocation issues: 1 cursor SELECT + a handful
    // of filterUnchangedOsvIds chunks (ceil(550/100)=6) + 1 re-link SELECT +
    // markIngestStarted + markIngestFinished (2 UPDATEs) ≈ 10 — nowhere near
    // the 50-query Free-plan cap even at 550 candidates (far above
    // production's expected per-run volume).
    expect(spies.dbPrepare.mock.calls.length).toBeLessThan(50);
  }, 60_000);

  it('D1 discipline under the TRUE worst case (security finding 2): all 8 ecosystem dirs near MAX_LINES_PER_DIR, total D1 queries stays well under 50', async () => {
    // The previous "D1 discipline" test above only loads 550 candidates
    // into a single directory — under MAX_DISCOVERY_CANDIDATES (2000), so
    // it never actually exercises that cap. This test reproduces the
    // finding's literal worst case: all 8 ecosystem directories each near
    // their own MAX_LINES_PER_DIR (2000) cap, i.e. up to 16,000 unique
    // candidates combined — the scenario that, before the
    // MAX_DISCOVERY_CANDIDATES pre-filter cap existed, could have driven
    // filterUnchangedOsvIds to up to 160 SELECTs (16000/100).
    const PER_DIR = 2000;
    const dirTags: Record<Dir, string> = {
      npm: 'np01',
      PyPI: 'py01',
      Maven: 'mv01',
      Go: 'go01',
      'crates.io': 'cr01',
      Packagist: 'pk01',
      NuGet: 'nu01',
      RubyGems: 'rb01',
    };

    const perDir: Partial<Record<Dir, string>> = {};
    for (const dir of OSV_ECOSYSTEM_DIRS) {
      const tag = dirTags[dir];
      const lines: string[] = [];
      for (let i = 0; i < PER_DIR; i++) {
        // 1-minute spacing keeps every one of the 2000 entries per dir
        // comfortably inside the 72h first-run lookback window (max offset
        // ~33h), and the per-dir tag keeps all 16,000 ids globally unique
        // (no cross-dir dedup collapsing the candidate count).
        lines.push(
          csvLine(isoAt(-i * 60 * 1000), `GHSA-${String(i).padStart(4, '0')}-${tag}-aaaa`),
        );
      }
      perDir[dir] = lines.join('\n');
    }
    stubGcs(perDir);

    const spies = spyOnBindings();
    const ctx = createExecutionContext();
    await runOsvDiscovery(testEnv, ctx);
    await waitOnExecutionContext(ctx);

    const selectCalls = spies.boundCalls.filter((c) => /WHERE osv_id IN/i.test(c.sql));
    for (const call of selectCalls) {
      expect(call.paramCount).toBeLessThanOrEqual(100);
    }

    // MAX_DISCOVERY_CANDIDATES (2000) caps the combined, deduped candidate
    // set BEFORE filterUnchangedOsvIds runs, so chunked at
    // STATE_SELECT_CHUNK_SIZE (100) that's exactly ceil(2000/100) = 20
    // SELECTs — not the ceil(16000/100) = 160 it would have been without
    // that pre-filter cap.
    expect(selectCalls.length).toBe(20);

    // Total D1 queries this invocation issues: 1 cursor SELECT + 20
    // filterUnchangedOsvIds chunks + 1 re-link SELECT + markIngestStarted +
    // markIngestFinished (2 UPDATEs) ≈ 24 — comfortably under the 50-query
    // Free-plan budget even at this 16,000-candidate worst case.
    expect(spies.dbPrepare.mock.calls.length).toBeLessThan(50);
  }, 120_000);

  it('OSV_FETCH message size: realistic items stay comfortably under Cloudflare Queues 128KB cap (measured, not assumed)', async () => {
    // Realistic-shaped ids/dirs/timestamps, not short synthetic ones —
    // 'crates.io' is the longest ecosystem directory name, and a
    // nanosecond-precision ISO `modified` string is longer than a plain
    // millisecond one.
    const TOTAL = 200;
    const lines: string[] = [];
    for (let i = 0; i < TOTAL; i++) {
      const suffix = Math.random().toString(36).slice(2, 6);
      lines.push(
        csvLine(`${isoAt(-i * 60 * 1000).slice(0, -1)}123456789Z`, `GHSA-${suffix}-q64q-g65r`),
      );
    }
    stubGcs({ 'crates.io': lines.join('\n') });

    const { messages } = await runDiscovery();
    const fetchMessages = messages.filter(
      (m): m is Extract<OsvQueueMessage, { kind: 'OSV_FETCH' }> => m.kind === 'OSV_FETCH',
    );
    expect(fetchMessages.length).toBeGreaterThan(0);

    for (const msg of fetchMessages) {
      const bytes = new TextEncoder().encode(JSON.stringify(msg)).length;
      expect(bytes).toBeLessThanOrEqual(131_072); // Cloudflare Queues' per-message cap
      // Sanity: well under the cap, not just technically compliant — catches
      // a future chunk-size change that silently erodes the margin.
      expect(bytes).toBeLessThan(131_072 * 0.5);
    }

    const totalItems = fetchMessages.reduce((n, m) => n + m.items.length, 0);
    expect(totalItems).toBe(TOTAL);
  }, 30_000);

  it("filters a CSV-sourced id that fails the GHSA id shape BEFORE it can be enqueued (defense in depth, independent of fetchOsvRecord's own check)", async () => {
    stubGcs({
      npm: [
        csvLine(isoAt(-1 * 60 * 60 * 1000), 'GHSA-aaaa-aaaa-aaaa'), // well-formed
        csvLine(isoAt(-1 * 60 * 60 * 1000), 'GHSA-aaaa-bbbb-cccc/../../etc'), // malformed — path-traversal-shaped
        csvLine(isoAt(-1 * 60 * 60 * 1000), 'CVE-2026-12345'), // malformed — wrong id family entirely
      ].join('\n'),
    });

    const { items } = await runDiscovery();
    expect(items.map((i) => i.osvId)).toEqual(['GHSA-aaaa-aaaa-aaaa']);
  }, 30_000);
});
