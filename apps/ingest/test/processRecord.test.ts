import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import type { SsvcDecision } from '@threat-lens/contracts';
import { describe, expect, it } from 'vitest';
import { computeStateHash, computeTextHash } from '../src/lib/server/hash';
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
    await processRecord(
      makeRecord({ description: 'Original text.', severity: 'LOW' }),
      testEnv,
      seedCtx,
    );
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

  // ── KV-delete-on-new-CVE guard ──────────────────────────────────────────
  // Added alongside the SSVC/NVD-queue fix: a brand-new CVE was never cached
  // under `cve:{id}` to begin with, so deleting that key is pure waste — at
  // NVD-ingestion-actually-landing-records volume this could itself eat into
  // the 1,000/day KV write+delete cap (see processRecord.ts's comment at the
  // `if (cur)` guard, and CLAUDE.md's 2026-10-27 incident).

  it('a brand-new CVE (no prior row) does NOT call env.CACHE.delete', async () => {
    const spies = spyOnBindings();

    const ctx = createExecutionContext();
    await processRecord(makeRecord({ cveId: 'CVE-2026-09001' }), testEnv, ctx);
    await waitOnExecutionContext(ctx);

    expect(spies.cacheDelete).not.toHaveBeenCalled();
    // Sanity: it still actually wrote the row — this isn't short-circuiting
    // the whole write, only the now-pointless cache invalidation.
    expect(spies.dbBatch).toHaveBeenCalledTimes(3);
  });

  it('an update to an EXISTING CVE still calls env.CACHE.delete exactly once, contrasted directly against the new-CVE case above', async () => {
    const spies = spyOnBindings();

    const seedCtx = createExecutionContext();
    await processRecord(makeRecord({ cveId: 'CVE-2026-09002' }), testEnv, seedCtx);
    await waitOnExecutionContext(seedCtx);
    spies.clearAll();

    const ctx = createExecutionContext();
    await processRecord(
      makeRecord({ cveId: 'CVE-2026-09002', description: 'An updated description.' }),
      testEnv,
      ctx,
    );
    await waitOnExecutionContext(ctx);

    expect(spies.cacheDelete).toHaveBeenCalledTimes(1);
    expect(spies.cacheDelete).toHaveBeenCalledWith('cve:CVE-2026-09002');
  });
});

describe('processRecord — SSVC change-detection isolation', () => {
  useCleanBindings();

  // Pinned regression constants: sha256 hex of computeTextHash/
  // computeStateHash's own documented input strings
  // ('Example vulnerability in a widget factory.|CWE-79|acme' and
  // 'CRITICAL|9.8|0|null|acme' respectively) for makeRecord()'s exact
  // default shape, computed independently of this codebase (plain
  // node:crypto sha256, not the app's own hash.ts) so this constant can't
  // silently drift alongside a bug in hash.ts itself. If SSVC — or anything
  // else — is ever accidentally folded into either hash's input, THIS
  // breaks loudly, not just the "does adding ssvc change the hash" check
  // below (which would also break, but wouldn't catch an unrelated hash
  // algorithm change that affected both paths identically).
  const PINNED_TEXT_HASH = '76ad65c1425d3782f9bd832520af9316a08a584988b9bef8967f644700c094d1';
  const PINNED_STATE_HASH = '30559a542da9f5ccfd95e3afd5890ee9b5d13211932c129168517c10c9dd2a94';

  const SSVC_A: SsvcDecision = {
    exploitation: 'active',
    automatable: 'yes',
    technicalImpact: 'total',
    decidedAt: Date.UTC(2026, 9, 1),
  };
  const SSVC_A_NEWER_TIMESTAMP: SsvcDecision = { ...SSVC_A, decidedAt: Date.UTC(2026, 9, 15) };
  const SSVC_B: SsvcDecision = {
    exploitation: 'none',
    automatable: 'no',
    technicalImpact: 'partial',
    decidedAt: Date.UTC(2026, 9, 1),
  };

  it('pinned hash regression constant: computeTextHash/computeStateHash for the fixture record match an exact, externally-computed sha256 hex', async () => {
    const record = makeRecord();
    const topVendor = 'acme';

    await expect(computeTextHash(record)).resolves.toBe(PINNED_TEXT_HASH);
    await expect(
      computeStateHash(record.severity, record.cvss?.base ?? null, false, null, topVendor),
    ).resolves.toBe(PINNED_STATE_HASH);
  });

  it("adding/changing SSVC data on the SAME record does not change either hash — SSVC is provably outside both hashes' inputs", async () => {
    const withoutSsvc = makeRecord();
    const withSsvc = makeRecord({ ssvc: SSVC_A });

    expect(await computeTextHash(withSsvc)).toBe(await computeTextHash(withoutSsvc));
    expect(await computeTextHash(withSsvc)).toBe(PINNED_TEXT_HASH);

    // computeStateHash doesn't take the record at all (ssvc was never a
    // candidate input) — included for completeness/documentation of that
    // fact, pinned against the same constant as above.
    const stateHash = await computeStateHash(
      withSsvc.severity,
      withSsvc.cvss?.base ?? null,
      false,
      null,
      'acme',
    );
    expect(stateHash).toBe(PINNED_STATE_HASH);
  });

  it("SSVC changing ALONE (text/state otherwise unchanged): writes only cve_state's SSVC columns — text_hash/state_hash in D1 stay exactly the pinned values, no Vectorize call, no KV delete", async () => {
    const spies = spyOnBindings();

    const seedCtx = createExecutionContext();
    await processRecord(makeRecord({ cveId: 'CVE-2026-09101' }), testEnv, seedCtx);
    await waitOnExecutionContext(seedCtx);
    spies.clearAll();

    const ctx = createExecutionContext();
    await processRecord(makeRecord({ cveId: 'CVE-2026-09101', ssvc: SSVC_A }), testEnv, ctx);
    await waitOnExecutionContext(ctx);

    // Exactly one additional write (applySsvcOnly's single-row upsert) —
    // NOT writeD1's 3-call batch shape.
    expect(spies.dbBatch).not.toHaveBeenCalled();
    expect(spies.aiRun).not.toHaveBeenCalled();
    expect(spies.vectorizeUpsert).not.toHaveBeenCalled();
    expect(spies.vectorizeGetByIds).not.toHaveBeenCalled();
    expect(spies.cacheDelete).not.toHaveBeenCalled();
    expect(spies.retryQueueSend).not.toHaveBeenCalled();

    const row = await testEnv.DB.prepare(
      `SELECT c.text_hash, c.state_hash,
              s.ssvc_exploitation, s.ssvc_automatable, s.ssvc_technical_impact
       FROM cve c LEFT JOIN cve_state s USING (cve_id)
       WHERE c.cve_id = ?`,
    )
      .bind('CVE-2026-09101')
      .first<{
        text_hash: string;
        state_hash: string;
        ssvc_exploitation: string;
        ssvc_automatable: string;
        ssvc_technical_impact: string;
      }>();

    expect(row?.text_hash).toBe(PINNED_TEXT_HASH);
    expect(row?.state_hash).toBe(PINNED_STATE_HASH);
    expect(row).toMatchObject({
      ssvc_exploitation: SSVC_A.exploitation,
      ssvc_automatable: SSVC_A.automatable,
      ssvc_technical_impact: SSVC_A.technicalImpact,
    });
  });

  it('an SSVC change alongside a genuine text/state change still goes through the normal writeD1 path (SSVC columns folded into the SAME upsert, not a second write)', async () => {
    const spies = spyOnBindings();

    const seedCtx = createExecutionContext();
    await processRecord(makeRecord({ cveId: 'CVE-2026-09102' }), testEnv, seedCtx);
    await waitOnExecutionContext(seedCtx);
    spies.clearAll();

    const ctx = createExecutionContext();
    await processRecord(
      makeRecord({
        cveId: 'CVE-2026-09102',
        description: 'A materially different description entirely.',
        ssvc: SSVC_A,
      }),
      testEnv,
      ctx,
    );
    await waitOnExecutionContext(ctx);

    // Same call count as the plain text-changed case in the describe block
    // above (3) — SSVC adds zero extra statements/batches.
    expect(spies.dbBatch).toHaveBeenCalledTimes(3);
    expect(spies.cacheDelete).toHaveBeenCalledTimes(1);

    const row = await testEnv.DB.prepare('SELECT ssvc_exploitation FROM cve_state WHERE cve_id = ?')
      .bind('CVE-2026-09102')
      .first<{ ssvc_exploitation: string }>();
    expect(row?.ssvc_exploitation).toBe('active');
  });

  it('a timestamp-only SSVC change (identical exploitation/automatable/technicalImpact, newer decidedAt) produces ZERO writes', async () => {
    const spies = spyOnBindings();

    const seedCtx = createExecutionContext();
    await processRecord(makeRecord({ cveId: 'CVE-2026-09103', ssvc: SSVC_A }), testEnv, seedCtx);
    await waitOnExecutionContext(seedCtx);
    spies.clearAll();

    const ctx = createExecutionContext();
    await processRecord(
      makeRecord({ cveId: 'CVE-2026-09103', ssvc: SSVC_A_NEWER_TIMESTAMP }),
      testEnv,
      ctx,
    );
    await waitOnExecutionContext(ctx);

    expect(spies.dbBatch).not.toHaveBeenCalled();
    expect(spies.cacheDelete).not.toHaveBeenCalled();
    expect(spies.aiRun).not.toHaveBeenCalled();
    expect(spies.vectorizeUpsert).not.toHaveBeenCalled();
    expect(spies.vectorizeGetByIds).not.toHaveBeenCalled();
    expect(spies.retryQueueSend).not.toHaveBeenCalled();
    // Also confirm no standalone applySsvcOnly UPDATE slipped through
    // (its own db.prepare().run() would show up in queryCalls).
    expect(spies.queryCalls.filter((c) => c.method === 'run')).toHaveLength(0);

    // decidedAt in storage is still the OLDER value — the newer timestamp
    // was correctly treated as "no change", not silently applied anyway.
    const row = await testEnv.DB.prepare('SELECT ssvc_updated_at FROM cve_state WHERE cve_id = ?')
      .bind('CVE-2026-09103')
      .first<{ ssvc_updated_at: number }>();
    expect(row?.ssvc_updated_at).toBe(SSVC_A.decidedAt);
  });

  it('a genuinely different SSVC decision (not just a timestamp) on top of unchanged text/state DOES write — contrast case for the timestamp-only test above', async () => {
    const spies = spyOnBindings();

    const seedCtx = createExecutionContext();
    await processRecord(makeRecord({ cveId: 'CVE-2026-09104', ssvc: SSVC_A }), testEnv, seedCtx);
    await waitOnExecutionContext(seedCtx);
    spies.clearAll();

    const ctx = createExecutionContext();
    await processRecord(makeRecord({ cveId: 'CVE-2026-09104', ssvc: SSVC_B }), testEnv, ctx);
    await waitOnExecutionContext(ctx);

    expect(spies.dbBatch).not.toHaveBeenCalled(); // still the SSVC-only path, not writeD1
    expect(spies.cacheDelete).not.toHaveBeenCalled();
    expect(spies.aiRun).not.toHaveBeenCalled();

    const row = await testEnv.DB.prepare(
      'SELECT ssvc_exploitation, ssvc_automatable, ssvc_technical_impact FROM cve_state WHERE cve_id = ?',
    )
      .bind('CVE-2026-09104')
      .first<{
        ssvc_exploitation: string;
        ssvc_automatable: string;
        ssvc_technical_impact: string;
      }>();
    expect(row).toEqual({
      ssvc_exploitation: 'none',
      ssvc_automatable: 'no',
      ssvc_technical_impact: 'partial',
    });
  });
});
