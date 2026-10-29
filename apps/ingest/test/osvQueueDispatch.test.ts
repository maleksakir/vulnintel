import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import type { OsvQueueMessage } from '@threat-lens/contracts';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import worker from '../src/index';
import { spyOnBindings, testEnv, useCleanBindings } from './helpers';

// index.ts's queue() dispatch for the 'osv-ingest' queue: OSV_DISCOVER routes
// to runOsvDiscovery, OSV_FETCH routes to runOsvFetchBatch, and a malformed
// body is acked (dropped) rather than retried — mirrors queueDispatch.test.ts's
// coverage of the epss-ingest/cve-ingest-retry split.

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

function requestUrl(input: RequestInfo | URL): string {
  if (typeof input === 'string') return input;
  if (input instanceof URL) return input.href;
  return input.url;
}

describe('index.ts queue() dispatch — osv-ingest', () => {
  useCleanBindings();

  beforeEach(() => {
    // Every GCS ecosystem-dir CSV is empty (no new work) and every OSV API
    // lookup 404s — keeps these dispatch tests focused on routing, not on
    // discovery/fetch-batch internals (covered separately in
    // osvAdapter.test.ts / osvPatchBatch.test.ts).
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const url = requestUrl(input);
        if (url.includes('storage.googleapis.com/osv-vulnerabilities/')) {
          return new Response('', { status: 200 });
        }
        if (url.startsWith('https://api.osv.dev/v1/vulns/')) {
          return new Response('not found', { status: 404 });
        }
        throw new Error(`unexpected fetch() call in test: ${url}`);
      }),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('routes OSV_DISCOVER to runOsvDiscovery (updates the ingest_run OSV row)', async () => {
    const msg = makeMessage<OsvQueueMessage>({ kind: 'OSV_DISCOVER' });
    const batch = makeBatch('osv-ingest', [msg]);

    const ctx = createExecutionContext();
    await worker.queue(batch, testEnv, ctx);
    await waitOnExecutionContext(ctx);

    expect(msg.ack).toHaveBeenCalledTimes(1);
    expect(msg.retry).not.toHaveBeenCalled();

    const row = await testEnv.DB.prepare(
      'SELECT last_status, last_finished_at FROM ingest_run WHERE source = ?',
    )
      .bind('OSV')
      .first<{ last_status: string; last_finished_at: number }>();
    expect(row?.last_status).toBe('OK');
    expect(row?.last_finished_at).toBeGreaterThan(0);
  }, 30_000);

  it('routes OSV_FETCH to runOsvFetchBatch (writes a WITHDRAWN state row for a 404)', async () => {
    const msg = makeMessage<OsvQueueMessage>({
      kind: 'OSV_FETCH',
      items: [
        { osvId: 'GHSA-jf75-q64q-g65r', ecosystemDir: 'npm', modified: '2026-10-28T00:00:00Z' },
      ],
    });
    const batch = makeBatch('osv-ingest', [msg]);

    const ctx = createExecutionContext();
    await worker.queue(batch, testEnv, ctx);
    await waitOnExecutionContext(ctx);

    expect(msg.ack).toHaveBeenCalledTimes(1);
    expect(msg.retry).not.toHaveBeenCalled();

    const row = await testEnv.DB.prepare('SELECT status FROM osv_record_state WHERE osv_id = ?')
      .bind('GHSA-jf75-q64q-g65r')
      .first<{ status: string }>();
    expect(row?.status).toBe('WITHDRAWN');
  });

  it('routes an "osv-ingest-staging" batch too (the -staging suffix variant)', async () => {
    const msg = makeMessage<OsvQueueMessage>({ kind: 'OSV_DISCOVER' });
    const batch = makeBatch('osv-ingest-staging', [msg]);

    await worker.queue(batch, testEnv, createExecutionContext());
    expect(msg.ack).toHaveBeenCalledTimes(1);
  }, 30_000);

  it('acks (does not retry) a malformed osv-ingest message body', async () => {
    const msg = makeMessage({ kind: 'NOT_A_REAL_KIND' } as unknown as OsvQueueMessage);
    const batch = makeBatch('osv-ingest', [msg]);

    await worker.queue(batch, testEnv, createExecutionContext());

    expect(msg.ack).toHaveBeenCalledTimes(1);
    expect(msg.retry).not.toHaveBeenCalled();
  });

  it('acks (does not retry) an OSV_FETCH message whose items are not an array', async () => {
    const msg = makeMessage({
      kind: 'OSV_FETCH',
      items: 'not-an-array',
    } as unknown as OsvQueueMessage);
    const batch = makeBatch('osv-ingest', [msg]);

    await worker.queue(batch, testEnv, createExecutionContext());

    expect(msg.ack).toHaveBeenCalledTimes(1);
    expect(msg.retry).not.toHaveBeenCalled();
  });

  it('does not cross-route an osv-ingest batch into the epss consumer or RetryMessage paths', async () => {
    const spies = spyOnBindings();
    const msg = makeMessage<OsvQueueMessage>({ kind: 'OSV_DISCOVER' });
    const batch = makeBatch('osv-ingest', [msg]);

    const ctx = createExecutionContext();
    await worker.queue(batch, testEnv, ctx);
    await waitOnExecutionContext(ctx);

    // applyEpssPatchBatch's tell-tale query shape must never appear.
    const sql = spies.preparedSql();
    expect(sql.some((s) => /cve_state.*epss_score.*epss_percentile/is.test(s))).toBe(false);
  }, 30_000);
});
