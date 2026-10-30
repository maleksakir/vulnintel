import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import type { NvdQueueMessage } from '@threat-lens/contracts';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { runDailyFullDelta } from '../src/pipelines/daily';
import { spyOnBindings, testEnv, useCleanBindings } from './helpers';

// NVD queue PRODUCER coverage (pipelines/daily.ts's NVD section) — the other
// half of today's fix, same shape as test/epssProducer.test.ts: this stubs
// the global `fetch` rather than `vi.mock`-ing adapters/nvd.ts, because
// `@cloudflare/vitest-plugin` runs test files inside real workerd, where
// `vi.mock` on project-relative source paths does not reliably intercept the
// module graph the way it does under Vitest's Node pool (verified
// empirically while building the EPSS/OSV producer tests earlier today —
// mocked adapters were never invoked; the real ones ran and hit the network).
//
// This file also independently re-measures the implementer's byte-size
// claims for NVD_QUEUE_MAX_RECORDS / NVD_QUEUE_MAX_BYTES rather than trusting
// the comments in daily.ts — those constants aren't exported, so the
// expected values below are copied from daily.ts and will silently go stale
// if that file changes them without updating this file too; that drift is
// itself a meaningful regression signal (a test relying on a stale copy of a
// safety-margin constant should be revisited, not just updated blindly).
const NVD_QUEUE_MAX_RECORDS = 8;
const NVD_QUEUE_MAX_BYTES = 100_000;
const QUEUES_HARD_CAP_BYTES = 131_072;

function requestUrl(input: RequestInfo | URL): string {
  if (typeof input === 'string') return input;
  if (input instanceof URL) return input.href;
  return input.url;
}

async function gzip(text: string): Promise<Uint8Array> {
  const cs = new CompressionStream('gzip');
  const writer = cs.writable.getWriter();
  const done = writer.write(new TextEncoder().encode(text)).then(() => writer.close());
  const chunks: Uint8Array[] = [];
  const reader = cs.readable.getReader();
  for (;;) {
    const { done: readDone, value } = await reader.read();
    if (readDone) break;
    chunks.push(value);
  }
  await done;
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}

function emptyEpssCsv(): string {
  return '#model_version:v2023.03.01,score_date:2026-10-29T00:00:00+0000\ncve,epss,percentile\n';
}

/** One NVD API 2.0 `{cve: {...}}` vulnerability entry with `cpeCount` CPEs
 *  and `refCount` references — enough knobs to build "typical" (small),
 *  "medium" (byte-cap-binding), and "huge" (single-record-over-cap) shaped
 *  records from one function. */
function nvdVuln(opts: {
  id: string;
  cpeCount: number;
  refCount: number;
  descriptionChars?: number;
}) {
  return {
    cve: {
      id: opts.id,
      published: '2026-01-01T00:00:00.000',
      lastModified: '2026-01-02T00:00:00.000',
      vulnStatus: 'Analyzed',
      descriptions: [{ lang: 'en', value: 'D'.repeat(opts.descriptionChars ?? 60) }],
      weaknesses: [
        { source: 'nvd@nist.gov', type: 'Primary', description: [{ lang: 'en', value: 'CWE-79' }] },
      ],
      configurations: [
        {
          nodes: [
            {
              operator: 'OR',
              negate: false,
              cpeMatch: Array.from({ length: opts.cpeCount }, (_, i) => ({
                vulnerable: true,
                criteria: `cpe:2.3:a:vendor-name-${i}:product-name-${i}:1.2.${i}:*:*:*:*:*:*:*`,
              })),
            },
          ],
        },
      ],
      references: Array.from({ length: opts.refCount }, (_, i) => ({
        url: `https://example.com/advisory/reference-number-${i}`,
        tags: ['x_refsource_misc'],
      })),
    },
  };
}

function nvdDeltaResponse(vulns: ReturnType<typeof nvdVuln>[]) {
  return {
    resultsPerPage: vulns.length,
    startIndex: 0,
    totalResults: vulns.length,
    vulnerabilities: vulns,
  };
}

function stubFetch(nvdBody: unknown, gzippedEpssCsv: Uint8Array): void {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      const url = requestUrl(input);
      if (url.startsWith('https://services.nvd.nist.gov/')) {
        return new Response(JSON.stringify(nvdBody), { status: 200 });
      }
      if (url.startsWith('https://epss.cyentia.com/')) {
        return new Response(gzippedEpssCsv, {
          status: 200,
          headers: { 'Last-Modified': 'Thu, 29 Oct 2026 00:00:00 GMT' },
        });
      }
      throw new Error(`unexpected fetch() call in test: ${url}`);
    }),
  );
}

describe('NVD queue producer (daily.ts)', () => {
  useCleanBindings();

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('typical-sized records: makes zero D1 calls of its own and enqueues every fetched record exactly once, batched at NVD_QUEUE_MAX_RECORDS', async () => {
    const vulns = Array.from({ length: 20 }, (_, i) =>
      nvdVuln({ id: `CVE-2026-6${String(i).padStart(4, '0')}`, cpeCount: 4, refCount: 5 }),
    );
    stubFetch(nvdDeltaResponse(vulns), await gzip(emptyEpssCsv()));

    const spies = spyOnBindings();
    const sendSpy = vi.spyOn(testEnv.NVD_QUEUE, 'send');

    const ctx = createExecutionContext();
    await runDailyFullDelta(testEnv, ctx);
    await waitOnExecutionContext(ctx);

    const sent = sendSpy.mock.calls.map(([msg]) => msg as NvdQueueMessage);
    expect(sent.length).toBeGreaterThan(1); // 20 records / 8-per-batch actually splits across messages

    // (a) collectively cover every input record exactly once — no drops, no dupes.
    const sentIds = sent.flatMap((m) => m.records.map((r) => r.cveId));
    expect(sentIds).toHaveLength(20);
    expect(new Set(sentIds).size).toBe(20);
    const expectedIds = new Set(vulns.map((v) => v.cve.id));
    expect(new Set(sentIds)).toEqual(expectedIds);

    // (b) batch-size limit respected: record count is the binding constraint
    // for small records (8 typical records are far under the byte cap), so
    // every message except possibly the last has exactly 8 records.
    for (const msg of sent.slice(0, -1)) {
      expect(msg.records.length).toBe(NVD_QUEUE_MAX_RECORDS);
    }
    expect(sent.at(-1)?.records.length).toBeGreaterThan(0);
    expect(sent.at(-1)?.records.length).toBeLessThanOrEqual(NVD_QUEUE_MAX_RECORDS);

    // (c) message-size claim: every sent message's real serialized size is
    // under Cloudflare Queues' hard 131,072-byte cap, with real margin (not
    // just "doesn't throw").
    for (const msg of sent) {
      const bytes = new TextEncoder().encode(JSON.stringify(msg)).length;
      expect(bytes).toBeLessThanOrEqual(QUEUES_HARD_CAP_BYTES);
      expect(bytes).toBeLessThan(NVD_QUEUE_MAX_BYTES); // well under, since record-count binds here
    }

    // (d) zero direct D1 calls for NVD itself. markIngestStarted/Finished
    // bookkeeping writes to `ingest_run` for NVD/MITRE/EPSS are expected;
    // NVD's producer must make none beyond that.
    const nonBookkeepingSql = spies.preparedSql().filter((sql) => !/\bingest_run\b/i.test(sql));
    expect(nonBookkeepingSql).toEqual([]);
    expect(spies.dbBatch).not.toHaveBeenCalled();
  }, 30_000);

  it('medium-sized records (90 CPEs each): the byte cap binds before the record-count cap — batches come out smaller than NVD_QUEUE_MAX_RECORDS, and every message still stays under the 128KB hard cap', async () => {
    // Each record's NormalizedCveRecord JSON is big enough (many CPE
    // objects) that 8 of them together would exceed NVD_QUEUE_MAX_BYTES
    // (100,000) well before exceeding the per-message 131,072-byte hard cap
    // — this is what NVD_QUEUE_MAX_BYTES is FOR, and it's worth confirming
    // it actually fires rather than just trusting daily.ts's comment that it
    // does.
    const vulns = Array.from({ length: 16 }, (_, i) =>
      nvdVuln({ id: `CVE-2026-7${String(i).padStart(4, '0')}`, cpeCount: 90, refCount: 5 }),
    );
    stubFetch(nvdDeltaResponse(vulns), await gzip(emptyEpssCsv()));

    const sendSpy = vi.spyOn(testEnv.NVD_QUEUE, 'send');
    const ctx = createExecutionContext();
    await runDailyFullDelta(testEnv, ctx);
    await waitOnExecutionContext(ctx);

    const sent = sendSpy.mock.calls.map(([msg]) => msg as NvdQueueMessage);
    const sentIds = sent.flatMap((m) => m.records.map((r) => r.cveId));
    expect(new Set(sentIds)).toEqual(new Set(vulns.map((v) => v.cve.id))); // still no drops/dupes

    for (const msg of sent) {
      const bytes = new TextEncoder().encode(JSON.stringify(msg)).length;
      expect(bytes).toBeLessThanOrEqual(QUEUES_HARD_CAP_BYTES);
    }

    // The actual regression signal: at least one message was flushed with
    // FEWER than NVD_QUEUE_MAX_RECORDS records, proving the byte-size check
    // — not just the record-count check — triggered a flush.
    expect(sent.some((msg) => msg.records.length < NVD_QUEUE_MAX_RECORDS)).toBe(true);
  }, 30_000);

  it("a single record at writeD1-cap size (500 CPEs / 200 references / 3000-char description) measures over both NVD_QUEUE_MAX_BYTES and the 128KB hard cap by itself, and the producer skips it (flags RECORD_TOO_LARGE) instead of enqueueing — confirming, not assuming, the implementer's stated finding, and the resulting gap (no retry path for that one record) still applies", async () => {
    const hugeId = 'CVE-2026-90000';
    const vulns = [
      nvdVuln({ id: 'CVE-2026-80001', cpeCount: 4, refCount: 5 }),
      nvdVuln({ id: 'CVE-2026-80002', cpeCount: 4, refCount: 5 }),
      nvdVuln({ id: hugeId, cpeCount: 500, refCount: 200, descriptionChars: 3000 }),
      nvdVuln({ id: 'CVE-2026-80003', cpeCount: 4, refCount: 5 }),
    ];
    stubFetch(nvdDeltaResponse(vulns), await gzip(emptyEpssCsv()));

    const sendSpy = vi.spyOn(testEnv.NVD_QUEUE, 'send');
    const analyticsSpy = vi.spyOn(testEnv.ANALYTICS, 'writeDataPoint');

    const ctx = createExecutionContext();
    await runDailyFullDelta(testEnv, ctx);
    await waitOnExecutionContext(ctx);

    const sent = sendSpy.mock.calls.map(([msg]) => msg as NvdQueueMessage);
    const sentIds = sent.flatMap((m) => m.records.map((r) => r.cveId));

    // The oversized record never reaches the queue at all.
    expect(sentIds).not.toContain(hugeId);
    // The three normal-sized records around it are completely unaffected —
    // this is the thing most worth regression-testing here: one pathological
    // record must not take out its neighbours in the fetch stream.
    expect(new Set(sentIds)).toEqual(
      new Set(['CVE-2026-80001', 'CVE-2026-80002', 'CVE-2026-80003']),
    );

    // Every message that WAS sent still respects the hard cap.
    for (const msg of sent) {
      const bytes = new TextEncoder().encode(JSON.stringify(msg)).length;
      expect(bytes).toBeLessThanOrEqual(QUEUES_HARD_CAP_BYTES);
    }

    // The drop is flagged via analytics, not silent.
    const warnPoints = analyticsSpy.mock.calls
      .map(([p]) => p as { blobs: string[]; doubles: number[] })
      .filter((p) => p.blobs[0] === 'NVD_PRODUCER' && p.blobs[1] === 'RECORD_TOO_LARGE');
    expect(warnPoints).toHaveLength(1);
    expect(warnPoints[0]?.blobs[2]).toBe(hugeId);
    // The recorded byte count substantiates the "over 100KB" claim directly,
    // not just "we believe it would be".
    expect(warnPoints[0]?.doubles[0]).toBeGreaterThan(NVD_QUEUE_MAX_BYTES);
  }, 30_000);
});
