import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import type { KevQueueMessage } from '@threat-lens/contracts';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { runKevFastLane } from '../src/pipelines/kev';
import { spyOnBindings, testEnv, useCleanBindings } from './helpers';

// KEV queue PRODUCER coverage (pipelines/kev.ts). The fix's whole point:
// runKevFastLane must fetch the catalog, chunk it, and enqueue onto KEV_QUEUE
// WITHOUT applying any patch to D1 itself — that work moved to the
// kev-ingest consumer (pipelines/kevQueue.ts), each message a fresh
// invocation with its own 50-D1-query budget. The old inline per-entry loop
// is the exact thing this replaces.
//
// Same `vi.stubGlobal('fetch', ...)` approach as the other producer tests
// (see nvdProducer/epssProducer/mitreProducer headers for why `vi.mock` on
// adapter source doesn't work under @cloudflare/vitest-plugin's workerd).
//
// KEV_MESSAGE_CHUNK_SIZE isn't exported from kev.ts; copied here and will go
// stale if kev.ts changes it — same convention the other producer tests use.
const KEV_MESSAGE_CHUNK_SIZE = 500;

function requestUrl(input: RequestInfo | URL): string {
  if (typeof input === 'string') return input;
  if (input instanceof URL) return input.href;
  return input.url;
}

function kevCatalog(count: number) {
  return {
    title: 'CISA KEV',
    catalogVersion: '2026.10.30',
    dateReleased: '2026-10-30T12:00:00.000Z',
    count,
    vulnerabilities: Array.from({ length: count }, (_, i) => ({
      cveID: `CVE-2026-${String(10000 + i)}`,
      vendorProject: 'acme',
      product: 'widget',
      vulnerabilityName: 'Example',
      dateAdded: '2026-10-01',
      shortDescription: 'An actively exploited flaw.',
      requiredAction: 'Apply vendor updates per CISA guidance.',
      dueDate: '2026-10-21',
      knownRansomwareCampaignUse: 'Unknown',
      notes: '',
    })),
  };
}

function stubKevFetch(catalog: unknown): void {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      const url = requestUrl(input);
      if (url.includes('known_exploited_vulnerabilities.json')) {
        return new Response(JSON.stringify(catalog), { status: 200 });
      }
      throw new Error(`unexpected fetch() call in test: ${url}`);
    }),
  );
}

describe('KEV queue producer (kev.ts)', () => {
  useCleanBindings();

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('enqueues every catalog entry exactly once, chunked under the 128KB cap, with ZERO D1 patch-apply work of its own', async () => {
    const CATALOG_SIZE = 1234; // > 2 full KEV_MESSAGE_CHUNK_SIZE chunks, not a round multiple
    stubKevFetch(kevCatalog(CATALOG_SIZE));

    const spies = spyOnBindings();
    const sendBatchSpy = vi.spyOn(testEnv.KEV_QUEUE, 'sendBatch');

    const ctx = createExecutionContext();
    await runKevFastLane(testEnv, ctx);
    await waitOnExecutionContext(ctx);

    const sentMessages = sendBatchSpy.mock.calls.flatMap(
      ([msgs]) => msgs as { body: KevQueueMessage }[],
    );

    // (a) chunk count + sizing: ceil(1234/500) = 3 messages, first two full.
    expect(sentMessages.length).toBe(3);
    expect(sentMessages[0]?.body.patches.length).toBe(KEV_MESSAGE_CHUNK_SIZE);
    expect(sentMessages[1]?.body.patches.length).toBe(KEV_MESSAGE_CHUNK_SIZE);
    expect(sentMessages[2]?.body.patches.length).toBe(CATALOG_SIZE - 2 * KEV_MESSAGE_CHUNK_SIZE);

    // (b) every message is under Cloudflare Queues' 128KB (131,072 byte) cap.
    for (const msg of sentMessages) {
      const bytes = new TextEncoder().encode(JSON.stringify(msg.body)).length;
      expect(bytes).toBeLessThanOrEqual(131_072);
    }

    // (c) collectively cover every input cveId exactly once.
    const sentIds = sentMessages.flatMap((m) => m.body.patches.map((p) => p.cveId));
    expect(sentIds).toHaveLength(CATALOG_SIZE);
    expect(new Set(sentIds).size).toBe(CATALOG_SIZE);

    // (d) the producer does NO D1 patch-apply work. Only ingest_run
    // bookkeeping (markIngestStarted/Finished) is expected; nothing resembling
    // the KEV apply shape (cve_state / cve_id IN / kev columns) may appear.
    const nonBookkeepingSql = spies.preparedSql().filter((sql) => !/\bingest_run\b/i.test(sql));
    expect(nonBookkeepingSql).toEqual([]);
    expect(spies.dbBatch).not.toHaveBeenCalled();
    // (e) no unconditional KV delete on the producer side anymore — the
    // consumer invalidates threat:kev:list only when something changes.
    expect(spies.cacheDelete).not.toHaveBeenCalled();

    const ingestRow = await testEnv.DB.prepare(
      'SELECT last_status, records_processed, records_failed FROM ingest_run WHERE source = ?',
    )
      .bind('KEV')
      .first<{ last_status: string; records_processed: number; records_failed: number }>();
    expect(ingestRow).toEqual({
      last_status: 'OK',
      records_processed: CATALOG_SIZE,
      records_failed: 0,
    });
  }, 30_000);

  it('records a FAILED KEV run (and enqueues nothing) when the catalog fetch errors', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('upstream down', { status: 503 })),
    );

    const sendBatchSpy = vi.spyOn(testEnv.KEV_QUEUE, 'sendBatch');

    const ctx = createExecutionContext();
    await runKevFastLane(testEnv, ctx);
    await waitOnExecutionContext(ctx);

    expect(sendBatchSpy).not.toHaveBeenCalled();
    const ingestRow = await testEnv.DB.prepare(
      'SELECT last_status FROM ingest_run WHERE source = ?',
    )
      .bind('KEV')
      .first<{ last_status: string }>();
    expect(ingestRow?.last_status).toBe('FAILED');
  }, 30_000);
});
