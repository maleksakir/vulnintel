import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import type { KevPatch, KevQueueMessage } from '@threat-lens/contracts';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { chunkKevPatches, groupForSendBatch, runKevFastLane } from '../src/pipelines/kev';
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

describe('chunkKevPatches message sizing', () => {
  // Cloudflare Queues rejects any single message over 128KB (131,072 bytes).
  // The producer originally chunked by COUNT alone, 500 patches per message,
  // on an estimate of "~250 bytes/patch pessimistic". Production disagreed:
  // every KEV run failed with
  //   message in batch has length 187596 bytes which exceeds single message limit
  // i.e. 375 bytes/patch, because CISA's kevRequiredAction is routinely a full
  // remediation sentence with no upstream length bound. KEV is the
  // actively-exploited feed, so a failing run means real KEV-listed CVEs go
  // unflagged.

  const QUEUE_MESSAGE_LIMIT = 131_072;

  function patch(i: number, actionLength: number): KevPatch {
    return {
      cveId: `CVE-2026-${String(i).padStart(5, '0')}`,
      kevDateAdded: Date.UTC(2026, 0, 1),
      kevDueDate: Date.UTC(2026, 0, 21),
      kevRequiredAction: 'R'.repeat(actionLength),
    };
  }

  function serializedBytes(patches: KevPatch[]): number {
    return new TextEncoder().encode(JSON.stringify({ patches })).length;
  }

  it('keeps every message under the 128KB queue limit at realistic patch sizes', () => {
    // 1,800 patches at ~375 bytes each — the shape that broke production.
    const patches = Array.from({ length: 1800 }, (_, i) => patch(i, 300));
    const { messages, oversized } = chunkKevPatches(patches);

    expect(oversized).toHaveLength(0);
    expect(messages.length).toBeGreaterThan(1); // it genuinely split
    for (const msg of messages) {
      expect(serializedBytes(msg)).toBeLessThan(QUEUE_MESSAGE_LIMIT);
    }
    // Nothing lost in the split.
    expect(messages.reduce((n, m) => n + m.length, 0)).toBe(1800);
  });

  it('splits by bytes, not by count, when required actions are long', () => {
    // 600 patches x ~2KB of required-action text. A count-based chunk of 500
    // would be ~1MB in one message.
    const patches = Array.from({ length: 600 }, (_, i) => patch(i, 2000));
    const { messages } = chunkKevPatches(patches);

    for (const msg of messages) {
      expect(serializedBytes(msg)).toBeLessThan(QUEUE_MESSAGE_LIMIT);
      expect(msg.length).toBeLessThan(500); // byte budget bit before the count cap
    }
    expect(messages.reduce((n, m) => n + m.length, 0)).toBe(600);
  });

  it('still caps by count when patches are tiny', () => {
    const patches = Array.from({ length: 1200 }, (_, i) => patch(i, 1));
    const { messages } = chunkKevPatches(patches);
    for (const msg of messages) {
      expect(msg.length).toBeLessThanOrEqual(500);
    }
    expect(messages.reduce((n, m) => n + m.length, 0)).toBe(1200);
  });

  it('reports a single un-sendable patch instead of retrying it forever', () => {
    // Bigger than a whole message on its own: it could never be enqueued, so
    // it must surface rather than silently stall the catalog.
    const patches = [patch(1, 200_000), patch(2, 100)];
    const { messages, oversized } = chunkKevPatches(patches);

    expect(oversized.map((p) => p.cveId)).toEqual(['CVE-2026-00001']);
    expect(messages).toHaveLength(1);
    expect(messages[0]?.map((p) => p.cveId)).toEqual(['CVE-2026-00002']);
  });

  it('an empty catalog produces no messages', () => {
    expect(chunkKevPatches([])).toEqual({ messages: [], oversized: [] });
  });
});

describe('groupForSendBatch cumulative-size packing', () => {
  // Cloudflare Queues' sendBatch() rejects a call whose messages sum to over
  // 256,000 bytes, independently of the per-message cap. Every KEV run in
  // production failed with "batch size of 398286 bytes exceeds limit of
  // 256000" because the old loop sliced by message COUNT only and packed
  // several ~100KB messages into one call. groupForSendBatch bounds each call
  // by BOTH caps.
  const SENDBATCH_LIMIT = 256_000;

  function msgBytes(msg: KevPatch[]): number {
    return new TextEncoder().encode(JSON.stringify({ patches: msg })).length;
  }

  /** A message of roughly `kb` kilobytes: one patch with a padded action. */
  function bigMessage(kb: number): KevPatch[] {
    return [
      {
        cveId: 'CVE-2026-00001',
        kevDateAdded: Date.UTC(2026, 0, 1),
        kevDueDate: Date.UTC(2026, 0, 21),
        kevRequiredAction: 'R'.repeat(kb * 1024),
      },
    ];
  }

  it('keeps every sendBatch group under the 256KB cumulative limit', () => {
    // Five ~90KB messages = ~450KB total; must split into multiple calls.
    const messages = Array.from({ length: 5 }, () => bigMessage(90));
    const groups = groupForSendBatch(messages);

    expect(groups.length).toBeGreaterThan(1);
    for (const g of groups) {
      const total = g.reduce((n, m) => n + msgBytes(m), 0);
      expect(total).toBeLessThan(SENDBATCH_LIMIT);
    }
    // Nothing dropped: every message lands in exactly one group.
    expect(groups.reduce((n, g) => n + g.length, 0)).toBe(5);
  });

  it('caps a group at 100 messages even when they are tiny', () => {
    const messages = Array.from({ length: 250 }, (_, i) => [
      {
        cveId: `CVE-2026-${String(i).padStart(5, '0')}`,
        kevDateAdded: 0,
        kevDueDate: 0,
        kevRequiredAction: 'x',
      },
    ]);
    const groups = groupForSendBatch(messages);
    for (const g of groups) {
      expect(g.length).toBeLessThanOrEqual(100);
    }
    expect(groups.reduce((n, g) => n + g.length, 0)).toBe(250);
  });

  it('puts the realistic full catalog in a single call', () => {
    // ~1,800 patches at ~375 bytes chunk to ~7 messages of ~100KB… wait, no:
    // chunkKevPatches caps each message at 100KB, so the whole catalog is a
    // few hundred KB. That is >256KB total, so it legitimately splits — the
    // point is only that it splits CORRECTLY, never exceeding a call budget.
    const patches = Array.from({ length: 1800 }, (_, i) => ({
      cveId: `CVE-2026-${String(i).padStart(5, '0')}`,
      kevDateAdded: 0,
      kevDueDate: 0,
      kevRequiredAction: 'R'.repeat(300),
    }));
    const { messages } = chunkKevPatches(patches);
    const groups = groupForSendBatch(messages);
    for (const g of groups) {
      expect(g.reduce((n, m) => n + msgBytes(m), 0)).toBeLessThan(SENDBATCH_LIMIT);
      expect(g.length).toBeLessThanOrEqual(100);
    }
    expect(groups.reduce((n, g) => n + g.flat().length, 0)).toBe(1800);
  });

  it('an empty message list produces no groups', () => {
    expect(groupForSendBatch([])).toEqual([]);
  });
});
