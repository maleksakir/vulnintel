import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import type { WatchlistQueueMessage } from '@threat-lens/contracts';
import { describe, expect, it } from 'vitest';
import { runWatchlistConsumer } from '../src/pipelines/watchlistQueue';
import { spyOnBindings, testEnv, useCleanBindings } from './helpers';

// Watchlist reconciliation CONSUMER (pipelines/watchlistQueue.ts), end to end
// against real local D1 — same convention as epssQueueConsumer.ts.

async function seedMatchableCve(cveId: string, vendor: string): Promise<void> {
  const now = Date.now();
  await testEnv.DB.batch([
    testEnv.DB.prepare(
      `INSERT INTO cve (cve_id, published_at, last_modified_at, description, severity, source,
                        text_hash, state_hash, ingested_at)
       VALUES (?, ?, ?, 'desc', 'HIGH', 'NVD', 'h', 'h', ?)`,
    ).bind(cveId, now - 1000, now - 1000, now),
    testEnv.DB.prepare(
      `INSERT INTO cpe (cve_id, cpe_uri, part, vendor, product)
       VALUES (?, ?, 'a', ?, 'widget')`,
    ).bind(cveId, `cpe:2.3:a:${vendor}:widget:*:*:*:*:*:*:*:*`, vendor),
  ]);
}

describe('runWatchlistConsumer', () => {
  useCleanBindings();

  it('reconciles matches and records an OK WATCHLIST ingest_run + analytics point', async () => {
    const now = Date.now();
    await testEnv.DB.prepare(
      `INSERT INTO watchlist (watchlist_id, name, created_at, updated_at) VALUES (1, 'w', ?, ?)`,
    )
      .bind(now, now)
      .run();
    await testEnv.DB.prepare(
      `INSERT INTO watchlist_subscription (watchlist_id, vendor, product, created_at)
       VALUES (1, 'acme', NULL, ?)`,
    )
      .bind(now)
      .run();
    await seedMatchableCve('CVE-2026-7001', 'acme');

    const spies = spyOnBindings();
    const ctx = createExecutionContext();
    await runWatchlistConsumer({ kind: 'WATCHLIST_RECONCILE' }, testEnv, ctx);
    await waitOnExecutionContext(ctx);

    const match = await testEnv.DB.prepare(
      `SELECT status FROM watchlist_match WHERE watchlist_id = 1 AND cve_id = 'CVE-2026-7001'`,
    ).first<{ status: string }>();
    expect(match?.status).toBe('NEW');

    const run = await testEnv.DB.prepare(
      `SELECT last_status, records_processed FROM ingest_run WHERE source = 'WATCHLIST'`,
    ).first<{ last_status: string; records_processed: number }>();
    expect(run?.last_status).toBe('OK');
    expect(run?.records_processed).toBe(1);

    const point = spies.analyticsWrite.mock.calls
      .map(([p]) => p as { blobs: string[] })
      .find((p) => p.blobs[0] === 'WATCHLIST_QUEUE');
    expect(point?.blobs[1]).toBe('OK');
  }, 30_000);

  it('on a D1 failure: rethrows (for queue retry) and records a FAILED run + analytics point', async () => {
    const spies = spyOnBindings();
    spies.dbPrepare.mockImplementation(() => {
      throw new Error('simulated D1 outage');
    });

    await expect(
      runWatchlistConsumer({ kind: 'WATCHLIST_RECONCILE' }, testEnv, createExecutionContext()),
    ).rejects.toThrow('simulated D1 outage');

    const point = spies.analyticsWrite.mock.calls
      .map(([p]) => p as { blobs: string[] })
      .find((p) => p.blobs[0] === 'WATCHLIST_QUEUE');
    expect(point?.blobs[1]).toBe('FAILED');
  });

  it('on a malformed message: acks (no throw) and emits MALFORMED_MESSAGE without touching D1', async () => {
    const spies = spyOnBindings();

    await expect(
      runWatchlistConsumer({} as WatchlistQueueMessage, testEnv, createExecutionContext()),
    ).resolves.toBeUndefined();

    expect(spies.dbPrepare).not.toHaveBeenCalled();
    const point = spies.analyticsWrite.mock.calls[0]?.[0] as { blobs: string[] } | undefined;
    expect(point?.blobs?.[0]).toBe('WATCHLIST_QUEUE');
    expect(point?.blobs?.[1]).toBe('MALFORMED_MESSAGE');
  });
});
