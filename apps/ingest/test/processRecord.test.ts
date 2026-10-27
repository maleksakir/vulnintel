import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { processRecord } from '../src/lib/server/processRecord';
import { makeRecord, spyOnBindings, testEnv, useCleanBindings } from './helpers';

// Regression coverage for the two-hash change-detection gate added 2026-10-27
// after the KV free-tier quota incident (CLAUDE.md "Known constraints"):
// re-ingesting an unchanged record must never touch D1 or KV.

describe('processRecord', () => {
  useCleanBindings();

  it('unchanged input on re-ingest: zero D1 writes, zero KV deletes, zero AI/Vectorize calls', async () => {
    const record = makeRecord();
    const spies = spyOnBindings();

    const seedCtx = createExecutionContext();
    await processRecord(record, testEnv, seedCtx);
    await waitOnExecutionContext(seedCtx);
    spies.clearAll();

    // Re-ingest the exact same record (as a full daily snapshot re-ingest would).
    const ctx = createExecutionContext();
    await processRecord(record, testEnv, ctx);
    await waitOnExecutionContext(ctx);

    expect(spies.dbBatch).not.toHaveBeenCalled();
    expect(spies.cacheDelete).not.toHaveBeenCalled();
    expect(spies.aiRun).not.toHaveBeenCalled();
    expect(spies.vectorizeUpsert).not.toHaveBeenCalled();
    expect(spies.vectorizeGetByIds).not.toHaveBeenCalled();
    expect(spies.retryQueueSend).not.toHaveBeenCalled();
  });

  it('text-changed path: full D1 write, one new embedding, Vectorize upsert with the new vector', async () => {
    const spies = spyOnBindings();

    const seedCtx = createExecutionContext();
    await processRecord(makeRecord(), testEnv, seedCtx);
    await waitOnExecutionContext(seedCtx);
    spies.clearAll();

    const changed = makeRecord({ description: 'A materially different description entirely.' });
    const ctx = createExecutionContext();
    await processRecord(changed, testEnv, ctx);
    await waitOnExecutionContext(ctx);

    // writeD1: one batch for cve/cve_state/provenance + one for the single
    // CWE + one for the single CPE (the fixture has no references).
    expect(spies.dbBatch).toHaveBeenCalledTimes(3);
    expect(spies.cacheDelete).toHaveBeenCalledTimes(1);
    expect(spies.cacheDelete).toHaveBeenCalledWith(`cve:${changed.cveId}`);
    expect(spies.aiRun).toHaveBeenCalledTimes(1);
    expect(spies.vectorizeGetByIds).not.toHaveBeenCalled();
    expect(spies.vectorizeUpsert).toHaveBeenCalledTimes(1);
    expect(spies.vectorizeUpsert.mock.calls[0]?.[0]?.[0]?.values).toEqual([0.1, 0.2, 0.3]);
    expect(spies.retryQueueSend).not.toHaveBeenCalled();
  });

  it('state-changed-only path: D1 write happens, but no AI call — the existing vector is reused', async () => {
    const spies = spyOnBindings();

    const seedCtx = createExecutionContext();
    await processRecord(makeRecord({ severity: 'CRITICAL' }), testEnv, seedCtx);
    await waitOnExecutionContext(seedCtx);
    spies.clearAll();

    // Simulate an embedding already present from the earlier (mocked) upsert.
    spies.vectorizeGetByIds.mockResolvedValueOnce([
      { id: 'CVE-2026-00001', values: [0.9, 0.8, 0.7] },
    ] as never);

    // Same description/cwes/cpes (text hash unchanged) — only severity differs,
    // which is part of the state hash but not the text hash.
    const changed = makeRecord({ severity: 'HIGH' });
    const ctx = createExecutionContext();
    await processRecord(changed, testEnv, ctx);
    await waitOnExecutionContext(ctx);

    expect(spies.dbBatch).toHaveBeenCalledTimes(3);
    expect(spies.cacheDelete).toHaveBeenCalledTimes(1);
    expect(spies.aiRun).not.toHaveBeenCalled();
    expect(spies.vectorizeGetByIds).toHaveBeenCalledTimes(1);
    expect(spies.vectorizeGetByIds).toHaveBeenCalledWith([changed.cveId]);
    expect(spies.vectorizeUpsert).toHaveBeenCalledTimes(1);
    // Reuses the existing vector rather than computing a new one.
    expect(spies.vectorizeUpsert.mock.calls[0]?.[0]?.[0]?.values).toEqual([0.9, 0.8, 0.7]);
    expect(spies.retryQueueSend).not.toHaveBeenCalled();
  });

  it('state-changed-only path with no existing vector: no Vectorize upsert at all (backfilled on the next daily run)', async () => {
    const spies = spyOnBindings(); // vectorizeGetByIds defaults to [] (no existing vector)

    const seedCtx = createExecutionContext();
    await processRecord(makeRecord({ severity: 'CRITICAL' }), testEnv, seedCtx);
    await waitOnExecutionContext(seedCtx);
    spies.clearAll();

    const changed = makeRecord({ severity: 'HIGH' });
    const ctx = createExecutionContext();
    await processRecord(changed, testEnv, ctx);
    await waitOnExecutionContext(ctx);

    expect(spies.vectorizeGetByIds).toHaveBeenCalledTimes(1);
    expect(spies.vectorizeUpsert).not.toHaveBeenCalled();
    // D1/KV still reflect the state change even though Vectorize doesn't.
    expect(spies.dbBatch).toHaveBeenCalledTimes(3);
    expect(spies.cacheDelete).toHaveBeenCalledTimes(1);
  });

  it('both text and state changed: behaves like the text-changed path (one embedding, no vector reuse)', async () => {
    const spies = spyOnBindings();

    const seedCtx = createExecutionContext();
    await processRecord(makeRecord({ description: 'Original text.', severity: 'LOW' }), testEnv, seedCtx);
    await waitOnExecutionContext(seedCtx);
    spies.clearAll();

    const changed = makeRecord({ description: 'Completely rewritten text.', severity: 'CRITICAL' });
    const ctx = createExecutionContext();
    await processRecord(changed, testEnv, ctx);
    await waitOnExecutionContext(ctx);

    expect(spies.dbBatch).toHaveBeenCalledTimes(3);
    expect(spies.cacheDelete).toHaveBeenCalledTimes(1);
    expect(spies.aiRun).toHaveBeenCalledTimes(1);
    expect(spies.vectorizeGetByIds).not.toHaveBeenCalled();
    expect(spies.vectorizeUpsert).toHaveBeenCalledTimes(1);
  });

  it('persists the written row for real in D1 (not just a call-count check)', async () => {
    spyOnBindings();
    const record = makeRecord({ cveId: 'CVE-2026-00002' });

    const ctx = createExecutionContext();
    await processRecord(record, testEnv, ctx);
    await waitOnExecutionContext(ctx);

    const row = await testEnv.DB.prepare('SELECT description, severity FROM cve WHERE cve_id = ?')
      .bind(record.cveId)
      .first<{ description: string; severity: string }>();
    expect(row).toEqual({ description: record.description, severity: record.severity });
  });
});
