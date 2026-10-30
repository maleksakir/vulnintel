import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import type { EpssQueueMessage } from '@threat-lens/contracts';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { runDailyFullDelta } from '../src/pipelines/daily';
import { spyOnBindings, testEnv, useCleanBindings } from './helpers';

// EPSS queue PRODUCER coverage (pipelines/daily.ts's EPSS section).
//
// The whole point of the fix under test: `runDailyFullDelta` must fetch,
// chunk, and enqueue EPSS patches WITHOUT ever writing them to D1 itself —
// that work moved to pipelines/epssQueue.ts's consumer, which runs as a
// separate invocation with its own fresh 50-D1-query budget.
//
// This stubs the global `fetch` (via `vi.stubGlobal`) rather than
// `vi.mock`-ing the adapter modules: `@cloudflare/vitest-plugin` runs test
// files inside the real Workers runtime (workerd), where `vi.mock` on
// project-relative source paths does not reliably intercept the module
// graph the way it does under Vitest's Node pool — verified empirically
// (mocked adapters were never invoked; the real ones ran and hit the
// network, timing the test out). Overriding the actual `fetch` global that
// the adapters call is a lower-level seam that isn't affected by that
// limitation, and NVD is given a trivially-empty response so this test can
// isolate the EPSS path's D1 behavior. (MITRE no longer has a fetch of its
// own in this cron path — see pipelines/mitreQueue.ts — so no stub for it
// is needed here; any accidental call to cveawg.mitre.org would now hit
// this stub's `throw` branch below instead.)

const SYNTHETIC_PATCH_COUNT = 3247; // > 3 full EPSS_MESSAGE_CHUNK_SIZE (1000) chunks, deliberately not a round multiple

function syntheticCveId(i: number): string {
  return `CVE-2026-${String(40000 + i).padStart(5, '0')}`;
}

function buildEpssCsv(): string {
  const lines = [
    '#model_version:v2023.03.01,score_date:2026-10-29T00:00:00+0000',
    'cve,epss,percentile',
  ];
  for (let i = 0; i < SYNTHETIC_PATCH_COUNT; i++) {
    lines.push(`${syntheticCveId(i)},0.12345,0.67890`);
  }
  return `${lines.join('\n')}\n`;
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

function requestUrl(input: RequestInfo | URL): string {
  if (typeof input === 'string') return input;
  if (input instanceof URL) return input.href;
  return input.url;
}

describe('EPSS queue producer (daily.ts)', () => {
  useCleanBindings();

  beforeEach(async () => {
    const gzippedCsv = await gzip(buildEpssCsv());

    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const url = requestUrl(input);

        if (url.startsWith('https://epss.cyentia.com/')) {
          return new Response(gzippedCsv, {
            status: 200,
            headers: { 'Last-Modified': 'Thu, 29 Oct 2026 00:00:00 GMT' },
          });
        }
        if (url.startsWith('https://services.nvd.nist.gov/')) {
          return new Response(
            JSON.stringify({
              resultsPerPage: 0,
              startIndex: 0,
              totalResults: 0,
              vulnerabilities: [],
            }),
            { status: 200 },
          );
        }
        throw new Error(`unexpected fetch() call in test: ${url}`);
      }),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('enqueues every patch exactly once in sub-128KB messages, with zero direct D1 calls of its own', async () => {
    const spies = spyOnBindings();
    const sendSpy = vi.spyOn(testEnv.EPSS_QUEUE, 'send');

    const ctx = createExecutionContext();
    await runDailyFullDelta(testEnv, ctx);
    await waitOnExecutionContext(ctx);

    const sentMessages = sendSpy.mock.calls.map(([msg]) => msg as EpssQueueMessage);

    // (a) message size: never exceeds Cloudflare Queues' 128KB (131,072 byte) cap.
    expect(sentMessages.length).toBeGreaterThan(1); // actually chunked across multiple messages
    for (const msg of sentMessages) {
      const bytes = new TextEncoder().encode(JSON.stringify(msg)).length;
      expect(bytes).toBeLessThanOrEqual(131_072);
    }

    // (b) collectively cover every input patch exactly once.
    const sentIds = sentMessages.flatMap((m) => m.patches.map((p) => p.cveId));
    expect(sentIds).toHaveLength(SYNTHETIC_PATCH_COUNT);
    expect(new Set(sentIds).size).toBe(SYNTHETIC_PATCH_COUNT); // no duplicates
    const expectedIds = new Set(
      Array.from({ length: SYNTHETIC_PATCH_COUNT }, (_, i) => syntheticCveId(i)),
    );
    expect(new Set(sentIds)).toEqual(expectedIds);

    // (c) the producer makes no direct D1 calls for EPSS. markIngestStarted/
    // markIngestFinished bookkeeping writes to `ingest_run` (for NVD, MITRE,
    // AND EPSS — all three pipelines in this cron run) are expected and
    // unrelated to EPSS patch persistence; NVD/MITRE are stubbed to return
    // zero records, so no processRecord-driven CVE/cve_state writes happen
    // either. What must be absent is anything resembling the EPSS
    // patch-apply query shape (cve_state / cve_id IN / epss columns).
    const nonBookkeepingSql = spies.preparedSql().filter((sql) => !/\bingest_run\b/i.test(sql));
    expect(nonBookkeepingSql).toEqual([]);
    expect(spies.dbBatch).not.toHaveBeenCalled();
  }, 30_000);
});
