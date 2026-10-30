import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import type {
  EpssQueueMessage,
  MitreCweQueueMessage,
  NvdQueueMessage,
  RetryMessage,
} from '@threat-lens/contracts';
import { afterEach, describe, expect, it, vi } from 'vitest';
import worker from '../src/index';
import {
  makeRecord,
  seedCveRow,
  seedCveState,
  spyOnBindings,
  testEnv,
  useCleanBindings,
} from './helpers';

// index.ts's queue() dispatch logic: a batch's queue NAME decides whether
// messages go to the new EPSS consumer path (applyEpssPatchBatch, keyed off
// `message.patches`) or the pre-existing RetryMessage/processRecord path
// (keyed off `message.normalizedRecord`) — they must never cross.
//
// This is tested against the real local D1 (not `vi.mock`-ed pipeline
// modules): `@cloudflare/vitest-plugin` runs each test file inside the
// Workers runtime (workerd), where plain `vi.mock('../src/...', factory)`
// on project source files does not reliably intercept the module graph the
// way it does under Vitest's Node pool (verified empirically — mocked
// functions were never invoked; the real implementations ran against a
// bare fake `env` and threw instead). Real D1 side effects distinguish the
// two code paths unambiguously and don't depend on that mechanism working.

interface FakeMessage<T> {
  body: T;
  ack: ReturnType<typeof vi.fn>;
  retry: ReturnType<typeof vi.fn>;
}

function makeMessage<T>(body: T): FakeMessage<T> {
  return { body, ack: vi.fn(), retry: vi.fn() };
}

function makeBatch<T>(queueName: string, messages: FakeMessage<T>[]): MessageBatch {
  return { queue: queueName, messages } as unknown as MessageBatch;
}

describe('index.ts queue() dispatch', () => {
  useCleanBindings();

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('routes an "epss-ingest" batch to the EPSS consumer path (applyEpssPatchBatch), not the RetryMessage path', async () => {
    const cveId = 'CVE-2026-70001';
    await seedCveRow({ cveId });
    await seedCveState({ cveId, epssScore: 0.1, epssPercentile: 0.1 });

    const epssBody: EpssQueueMessage = {
      patches: [{ cveId, epssScore: 0.93, epssPercentile: 0.95, epssUpdatedAt: Date.now() }],
    };
    const msg = makeMessage(epssBody);
    const batch = makeBatch('epss-ingest', [msg]);

    const ctx = createExecutionContext();
    await worker.queue(batch, testEnv, ctx);
    await waitOnExecutionContext(ctx);

    expect(msg.ack).toHaveBeenCalledTimes(1);
    expect(msg.retry).not.toHaveBeenCalled();

    const stateRow = await testEnv.DB.prepare(
      'SELECT epss_score, epss_percentile FROM cve_state WHERE cve_id = ?',
    )
      .bind(cveId)
      .first<{ epss_score: number; epss_percentile: number }>();
    expect(stateRow).toEqual({ epss_score: 0.93, epss_percentile: 0.95 });

    // If this had wrongly fallen through to the RetryMessage/processRecord
    // path, `body.normalizedRecord` would be undefined and `processRecord`
    // would throw before writing anything — the cve row's description
    // (never touched by applyEpssPatchBatch) stays at its seeded value.
    const cveRow = await testEnv.DB.prepare('SELECT description FROM cve WHERE cve_id = ?')
      .bind(cveId)
      .first<{ description: string }>();
    expect(cveRow?.description).toBe('seed description');
  });

  it('routes an "epss-ingest-staging" batch to the EPSS consumer too (the -staging suffix variant)', async () => {
    const cveId = 'CVE-2026-70002';
    await seedCveRow({ cveId });
    await seedCveState({ cveId, epssScore: 0.1, epssPercentile: 0.1 });

    const epssBody: EpssQueueMessage = {
      patches: [{ cveId, epssScore: 0.77, epssPercentile: 0.8, epssUpdatedAt: Date.now() }],
    };
    const msg = makeMessage(epssBody);
    const batch = makeBatch('epss-ingest-staging', [msg]);

    const ctx = createExecutionContext();
    await worker.queue(batch, testEnv, ctx);
    await waitOnExecutionContext(ctx);

    expect(msg.ack).toHaveBeenCalledTimes(1);
    expect(msg.retry).not.toHaveBeenCalled();

    const row = await testEnv.DB.prepare('SELECT epss_score FROM cve_state WHERE cve_id = ?')
      .bind(cveId)
      .first<{ epss_score: number }>();
    expect(row?.epss_score).toBe(0.77);
  });

  it('acks (does not retry) an epss-ingest message with a malformed body, without ever landing in the RetryMessage/processRecord path', async () => {
    // Missing `patches` — runEpssConsumer's own shape validation catches this
    // before calling applyEpssPatchBatch; a malformed message can never
    // succeed no matter how many times it's retried, so it's dropped (acked)
    // rather than retried into the DLQ (see pipelines/epssQueue.ts).
    const msg = makeMessage({} as unknown as EpssQueueMessage);
    const batch = makeBatch('epss-ingest', [msg]);

    await worker.queue(batch, testEnv, createExecutionContext());

    expect(msg.ack).toHaveBeenCalledTimes(1);
    expect(msg.retry).not.toHaveBeenCalled();
  });

  it('routes an "nvd-ingest" batch to the NVD consumer path (runNvdConsumer → processRecord), not the RetryMessage/EPSS path', async () => {
    spyOnBindings(); // AI has no local simulator — stub it the same way the cve-ingest-retry test below does
    const record = makeRecord({ cveId: 'CVE-2026-70020' });
    const nvdBody: NvdQueueMessage = { records: [record] };
    const msg = makeMessage(nvdBody);
    const batch = makeBatch('nvd-ingest', [msg]);

    const ctx = createExecutionContext();
    await worker.queue(batch, testEnv, ctx);
    await waitOnExecutionContext(ctx);

    expect(msg.ack).toHaveBeenCalledTimes(1);
    expect(msg.retry).not.toHaveBeenCalled();

    const row = await testEnv.DB.prepare('SELECT description, severity FROM cve WHERE cve_id = ?')
      .bind(record.cveId)
      .first<{ description: string; severity: string }>();
    expect(row).toEqual({ description: record.description, severity: record.severity });
  });

  it('routes an "nvd-ingest-staging" batch to the NVD consumer too (the -staging suffix variant)', async () => {
    spyOnBindings();
    const record = makeRecord({ cveId: 'CVE-2026-70021' });
    const nvdBody: NvdQueueMessage = { records: [record] };
    const msg = makeMessage(nvdBody);
    const batch = makeBatch('nvd-ingest-staging', [msg]);

    const ctx = createExecutionContext();
    await worker.queue(batch, testEnv, ctx);
    await waitOnExecutionContext(ctx);

    expect(msg.ack).toHaveBeenCalledTimes(1);
    expect(msg.retry).not.toHaveBeenCalled();

    const row = await testEnv.DB.prepare('SELECT description FROM cve WHERE cve_id = ?')
      .bind(record.cveId)
      .first<{ description: string }>();
    expect(row?.description).toBe(record.description);
  });

  it('acks (does not retry) an nvd-ingest message with a malformed body, without ever landing in the RetryMessage/processRecord path', async () => {
    // Missing `records` — runNvdConsumer's own shape validation catches this
    // before calling processRecord; a malformed message can never succeed no
    // matter how many times it's retried, so it's dropped (acked) rather
    // than retried into the DLQ (see pipelines/nvdQueue.ts).
    const msg = makeMessage({} as unknown as NvdQueueMessage);
    const batch = makeBatch('nvd-ingest', [msg]);

    await worker.queue(batch, testEnv, createExecutionContext());

    expect(msg.ack).toHaveBeenCalledTimes(1);
    expect(msg.retry).not.toHaveBeenCalled();
  });

  it('routes a "mitre-ingest" batch to the MITRE CWE consumer path (runMitreCweConsumer), not the RetryMessage/NVD/EPSS path', async () => {
    const cveId = 'CVE-2026-70030';
    await seedCveRow({ cveId });

    vi.stubGlobal(
      'fetch',
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({
              cveMetadata: { state: 'PUBLISHED' },
              containers: {
                cna: { problemTypes: [{ descriptions: [{ description: 'CWE-79 XSS' }] }] },
              },
            }),
            { status: 200 },
          ),
      ),
    );

    const mitreBody: MitreCweQueueMessage = { cveIds: [cveId] };
    const msg = makeMessage(mitreBody);
    const batch = makeBatch('mitre-ingest', [msg]);

    const ctx = createExecutionContext();
    await worker.queue(batch, testEnv, ctx);
    await waitOnExecutionContext(ctx);

    expect(msg.ack).toHaveBeenCalledTimes(1);
    expect(msg.retry).not.toHaveBeenCalled();

    const row = await testEnv.DB.prepare('SELECT cwe_id FROM cve_cwe WHERE cve_id = ?')
      .bind(cveId)
      .first<{ cwe_id: string }>();
    expect(row?.cwe_id).toBe('CWE-79');

    // If this had wrongly fallen through to the RetryMessage/processRecord
    // path, `body.normalizedRecord` would be undefined and processRecord
    // would throw before writing anything — the cve row's description
    // (never touched by runMitreCweConsumer) stays at its seeded value.
    const cveRow = await testEnv.DB.prepare('SELECT description FROM cve WHERE cve_id = ?')
      .bind(cveId)
      .first<{ description: string }>();
    expect(cveRow?.description).toBe('seed description');
  });

  it('routes a "mitre-ingest-staging" batch to the MITRE CWE consumer too (the -staging suffix variant)', async () => {
    const cveId = 'CVE-2026-70031';
    await seedCveRow({ cveId });
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('not found', { status: 404 })),
    );

    const mitreBody: MitreCweQueueMessage = { cveIds: [cveId] };
    const msg = makeMessage(mitreBody);
    const batch = makeBatch('mitre-ingest-staging', [msg]);

    const ctx = createExecutionContext();
    await worker.queue(batch, testEnv, ctx);
    await waitOnExecutionContext(ctx);

    expect(msg.ack).toHaveBeenCalledTimes(1);
    expect(msg.retry).not.toHaveBeenCalled();
  });

  it('acks (does not retry) a mitre-ingest message with a malformed body, without ever landing in the RetryMessage/processRecord path', async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);

    const msg = makeMessage({} as unknown as MitreCweQueueMessage);
    const batch = makeBatch('mitre-ingest', [msg]);

    await worker.queue(batch, testEnv, createExecutionContext());

    expect(msg.ack).toHaveBeenCalledTimes(1);
    expect(msg.retry).not.toHaveBeenCalled();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('retries (does not ack) a mitre-ingest message whose MITRE fetch fails with a 500', async () => {
    const cveId = 'CVE-2026-70032';
    await seedCveRow({ cveId });
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('boom', { status: 500 })),
    );

    const mitreBody: MitreCweQueueMessage = { cveIds: [cveId] };
    const msg = makeMessage(mitreBody);
    const batch = makeBatch('mitre-ingest', [msg]);

    await worker.queue(batch, testEnv, createExecutionContext());

    expect(msg.retry).toHaveBeenCalledTimes(1);
    expect(msg.ack).not.toHaveBeenCalled();
  });

  it('routes a "cve-ingest-retry" batch to the RetryMessage/processRecord path (writes a full cve row), not the EPSS consumer', async () => {
    // A fresh (text-changed) record makes processRecord call the AI binding
    // to embed it; AI has no local simulator (see test/helpers.ts), so it
    // must be stubbed here the same way processRecord.test.ts does.
    spyOnBindings();
    const record = makeRecord({ cveId: 'CVE-2026-70010' });
    const retryBody: RetryMessage = {
      attempt: 1,
      source: 'NVD',
      cveId: record.cveId,
      normalizedRecord: record,
      opType: 'UPSERT_ALL',
      lastError: { code: 'D1_WRITE_FAILED', message: 'x', occurredAt: Date.now() },
    };
    const msg = makeMessage(retryBody);
    const batch = makeBatch('cve-ingest-retry', [msg]);

    const ctx = createExecutionContext();
    await worker.queue(batch, testEnv, ctx);
    await waitOnExecutionContext(ctx);

    expect(msg.ack).toHaveBeenCalledTimes(1);
    expect(msg.retry).not.toHaveBeenCalled();

    const row = await testEnv.DB.prepare('SELECT description, severity FROM cve WHERE cve_id = ?')
      .bind(record.cveId)
      .first<{ description: string; severity: string }>();
    expect(row).toEqual({ description: record.description, severity: record.severity });
  });

  it('routes a "cve-ingest-retry-staging" batch to the RetryMessage path too (the -staging suffix variant)', async () => {
    spyOnBindings();
    const record = makeRecord({ cveId: 'CVE-2026-70011' });
    const retryBody: RetryMessage = {
      attempt: 1,
      source: 'MITRE',
      cveId: record.cveId,
      normalizedRecord: record,
      opType: 'UPSERT_ALL',
      lastError: { code: 'D1_WRITE_FAILED', message: 'x', occurredAt: Date.now() },
    };
    const msg = makeMessage(retryBody);
    const batch = makeBatch('cve-ingest-retry-staging', [msg]);

    const ctx = createExecutionContext();
    await worker.queue(batch, testEnv, ctx);
    await waitOnExecutionContext(ctx);

    expect(msg.ack).toHaveBeenCalledTimes(1);
    const row = await testEnv.DB.prepare('SELECT description FROM cve WHERE cve_id = ?')
      .bind(record.cveId)
      .first<{ description: string }>();
    expect(row?.description).toBe(record.description);
  });

  it('retries (does not ack) a cve-ingest-retry message with a malformed body, without ever landing in the EPSS consumer path', async () => {
    // Missing `normalizedRecord` — processRecord destructures `record.cpes` and throws.
    const badBody = {
      attempt: 1,
      source: 'NVD',
      cveId: 'CVE-2026-70099',
      opType: 'UPSERT_ALL',
      lastError: { code: 'D1_WRITE_FAILED', message: 'x', occurredAt: Date.now() },
    } as unknown as RetryMessage;
    const msg = makeMessage(badBody);
    const batch = makeBatch('cve-ingest-retry', [msg]);

    await worker.queue(batch, testEnv, createExecutionContext());

    expect(msg.retry).toHaveBeenCalledTimes(1);
    expect(msg.ack).not.toHaveBeenCalled();
  });
});
