import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import type { MitreCweQueueMessage } from '@threat-lens/contracts';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { runDailyFullDelta } from '../src/pipelines/daily';
import { spyOnBindings, testEnv, useCleanBindings } from './helpers';

// MITRE queue PRODUCER coverage (pipelines/daily.ts's NVD-loop CWE-gap
// collection + enqueue section) — same stubbing approach as
// nvdProducer.test.ts/epssProducer.test.ts: this stubs the global `fetch`
// rather than `vi.mock`-ing adapters/nvd.ts (see those files' header
// comments for why `vi.mock` doesn't reliably work under
// `@cloudflare/vitest-plugin`'s real workerd runtime).
//
// MITRE_LOOKUP_MAX_PER_RUN/MITRE_QUEUE_CHUNK_SIZE aren't exported from
// daily.ts, so — same convention nvdProducer.test.ts documents for its own
// copied constants — the expected values below are copied from daily.ts and
// will go stale if that file changes them without updating this file too.
const MITRE_LOOKUP_MAX_PER_RUN = 1000;
const MITRE_QUEUE_CHUNK_SIZE = 20;

function requestUrl(input: RequestInfo | URL): string {
  if (typeof input === 'string') return input;
  if (input instanceof URL) return input.href;
  return input.url;
}

function emptyEpssCsv(): string {
  return '#model_version:v2023.03.01,score_date:2026-10-29T00:00:00+0000\ncve,epss,percentile\n';
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

/** One NVD API 2.0 `{cve: {...}}` entry. `hasCwe: false` omits `weaknesses`
 *  entirely — the exact shape adapters/nvd.ts's own parsing turns into
 *  `record.cwes: []`, which is what this feature watches for. */
function nvdVuln(opts: { id: string; hasCwe: boolean }) {
  return {
    cve: {
      id: opts.id,
      published: '2026-01-01T00:00:00.000',
      lastModified: '2026-01-02T00:00:00.000',
      vulnStatus: 'Analyzed',
      descriptions: [{ lang: 'en', value: 'Example vulnerability.' }],
      ...(opts.hasCwe
        ? {
            weaknesses: [
              {
                source: 'nvd@nist.gov',
                type: 'Primary',
                description: [{ lang: 'en', value: 'CWE-79' }],
              },
            ],
          }
        : {}),
      configurations: [],
      references: [],
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

describe('MITRE CWE gap-fill queue producer (daily.ts)', () => {
  useCleanBindings();

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('collects only the zero-CWE NVD records and enqueues them onto MITRE_QUEUE, chunked at MITRE_QUEUE_CHUNK_SIZE, leaving CWE-bearing records out entirely', async () => {
    const gapVulns = Array.from({ length: 25 }, (_, i) =>
      nvdVuln({ id: `CVE-2026-9${String(i).padStart(4, '0')}`, hasCwe: false }),
    );
    const cweVulns = Array.from({ length: 5 }, (_, i) =>
      nvdVuln({ id: `CVE-2026-8${String(i).padStart(4, '0')}`, hasCwe: true }),
    );
    stubFetch(nvdDeltaResponse([...gapVulns, ...cweVulns]), await gzip(emptyEpssCsv()));

    const sendBatchSpy = vi.spyOn(testEnv.MITRE_QUEUE, 'sendBatch');

    const ctx = createExecutionContext();
    await runDailyFullDelta(testEnv, ctx);
    await waitOnExecutionContext(ctx);

    expect(sendBatchSpy).toHaveBeenCalledTimes(1); // 25/20 = 2 messages, well under the 100/call cap
    const sentMessages = sendBatchSpy.mock.calls[0]?.[0] as { body: MitreCweQueueMessage }[];
    expect(sentMessages.length).toBe(2);
    for (const msg of sentMessages.slice(0, -1)) {
      expect(msg.body.cveIds.length).toBe(MITRE_QUEUE_CHUNK_SIZE);
    }

    const sentIds = sentMessages.flatMap((m) => m.body.cveIds);
    expect(sentIds).toHaveLength(25);
    expect(new Set(sentIds)).toEqual(new Set(gapVulns.map((v) => v.cve.id)));
    // None of the CWE-bearing records leaked in.
    for (const v of cweVulns) expect(sentIds).not.toContain(v.cve.id);

    const ingestRow = await testEnv.DB.prepare(
      'SELECT last_status, records_processed, records_failed FROM ingest_run WHERE source = ?',
    )
      .bind('MITRE')
      .first<{ last_status: string; records_processed: number; records_failed: number }>();
    expect(ingestRow).toEqual({ last_status: 'OK', records_processed: 25, records_failed: 0 });
  }, 30_000);

  it('enqueues nothing and reports an OK zero-work MITRE run when every NVD record already has a CWE', async () => {
    const vulns = Array.from({ length: 5 }, (_, i) =>
      nvdVuln({ id: `CVE-2026-7${String(i).padStart(4, '0')}`, hasCwe: true }),
    );
    stubFetch(nvdDeltaResponse(vulns), await gzip(emptyEpssCsv()));

    const sendBatchSpy = vi.spyOn(testEnv.MITRE_QUEUE, 'sendBatch');

    const ctx = createExecutionContext();
    await runDailyFullDelta(testEnv, ctx);
    await waitOnExecutionContext(ctx);

    expect(sendBatchSpy).not.toHaveBeenCalled();
    const ingestRow = await testEnv.DB.prepare(
      'SELECT last_status, records_processed FROM ingest_run WHERE source = ?',
    )
      .bind('MITRE')
      .first<{ last_status: string; records_processed: number }>();
    expect(ingestRow).toEqual({ last_status: 'OK', records_processed: 0 });
  }, 30_000);

  it(`caps collection at MITRE_LOOKUP_MAX_PER_RUN (${MITRE_LOOKUP_MAX_PER_RUN}), counts (never silently drops) the overage, and still enqueues exactly the capped set`, async () => {
    const overCount = 7;
    const vulns = Array.from({ length: MITRE_LOOKUP_MAX_PER_RUN + overCount }, (_, i) =>
      nvdVuln({ id: `CVE-2027-${String(10000 + i)}`, hasCwe: false }),
    );
    stubFetch(nvdDeltaResponse(vulns), await gzip(emptyEpssCsv()));

    const sendBatchSpy = vi.spyOn(testEnv.MITRE_QUEUE, 'sendBatch');
    const analyticsSpy = vi.spyOn(testEnv.ANALYTICS, 'writeDataPoint');

    const ctx = createExecutionContext();
    await runDailyFullDelta(testEnv, ctx);
    await waitOnExecutionContext(ctx);

    const sentMessages = sendBatchSpy.mock.calls.flatMap(
      ([msgs]) => msgs as { body: MitreCweQueueMessage }[],
    );
    const sentIds = sentMessages.flatMap((m) => m.body.cveIds);
    expect(sentIds).toHaveLength(MITRE_LOOKUP_MAX_PER_RUN); // capped, not the full 1007

    const capPoints = analyticsSpy.mock.calls
      .map(([p]) => p as { blobs: string[] })
      .filter((p) => p.blobs[0] === 'MITRE_PRODUCER' && p.blobs[1] === 'LOOKUP_CAP_EXCEEDED');
    expect(capPoints).toHaveLength(1);
    expect(capPoints[0]?.blobs[2]).toBe(String(overCount));

    const ingestRow = await testEnv.DB.prepare(
      'SELECT last_status, records_processed, records_failed FROM ingest_run WHERE source = ?',
    )
      .bind('MITRE')
      .first<{ last_status: string; records_processed: number; records_failed: number }>();
    expect(ingestRow).toEqual({
      last_status: 'PARTIAL',
      records_processed: MITRE_LOOKUP_MAX_PER_RUN,
      records_failed: overCount,
    });
  }, 30_000);

  it('makes zero D1 calls of its own beyond ingest_run bookkeeping (pure in-memory collection)', async () => {
    const vulns = Array.from({ length: 10 }, (_, i) =>
      nvdVuln({ id: `CVE-2026-6${String(i).padStart(4, '0')}`, hasCwe: i % 2 === 0 }),
    );
    stubFetch(nvdDeltaResponse(vulns), await gzip(emptyEpssCsv()));

    const spies = spyOnBindings();

    const ctx = createExecutionContext();
    await runDailyFullDelta(testEnv, ctx);
    await waitOnExecutionContext(ctx);

    const nonBookkeepingSql = spies.preparedSql().filter((sql) => !/\bingest_run\b/i.test(sql));
    expect(nonBookkeepingSql).toEqual([]);
    expect(spies.dbBatch).not.toHaveBeenCalled();
  }, 30_000);
});
