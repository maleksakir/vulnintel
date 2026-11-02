import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import type { EpssPatch } from '@threat-lens/contracts';
import { describe, expect, it } from 'vitest';
import { applyEpssPatchBatch } from '../src/lib/server/processRecord';
import { seedCveRow, seedCveState, spyOnBindings, testEnv, useCleanBindings } from './helpers';

// This is the exact code path that caused the 2026-10-27 KV quota incident:
// FIRST.org ships a full daily snapshot (250k+ rows), so the per-chunk
// batched read + "only write what actually changed" gate here is what keeps
// ingest within Cloudflare's free-tier KV write/delete cap.

describe('applyEpssPatchBatch', () => {
  useCleanBindings();

  it('empty input: a true no-op — no D1 read, no D1 write, no cache traffic', async () => {
    const spies = spyOnBindings();

    await applyEpssPatchBatch([], testEnv, createExecutionContext());

    expect(spies.dbPrepare).not.toHaveBeenCalled();
    expect(spies.dbBatch).not.toHaveBeenCalled();
    expect(spies.cacheDelete).not.toHaveBeenCalled();
  });

  it('all rows in the chunk unchanged: the batch read happens, but zero writes', async () => {
    await seedCveRow({ cveId: 'CVE-2026-20001' });
    await seedCveRow({ cveId: 'CVE-2026-20002' });
    await seedCveState({ cveId: 'CVE-2026-20001', epssScore: 0.1234, epssPercentile: 0.5 });
    await seedCveState({ cveId: 'CVE-2026-20002', epssScore: 0.9, epssPercentile: 0.99 });

    const spies = spyOnBindings();
    const patches: EpssPatch[] = [
      {
        cveId: 'CVE-2026-20001',
        epssScore: 0.1234,
        epssPercentile: 0.5,
        epssUpdatedAt: Date.now(),
      },
      { cveId: 'CVE-2026-20002', epssScore: 0.9, epssPercentile: 0.99, epssUpdatedAt: Date.now() },
    ];

    await applyEpssPatchBatch(patches, testEnv, createExecutionContext());

    expect(spies.dbPrepare).toHaveBeenCalledTimes(1); // the one batched `IN (...)` read
    expect(spies.preparedSql()[0]).toMatch(/^\s*SELECT.*WHERE cve_id IN/is);
    expect(spies.dbBatch).not.toHaveBeenCalled();
    expect(spies.cacheDelete).not.toHaveBeenCalled();
  });

  it('mixed chunk: unchanged rows produce zero writes, changed rows produce exactly one batched write + one cache delete each', async () => {
    await seedCveRow({ cveId: 'CVE-2026-20010' });
    await seedCveRow({ cveId: 'CVE-2026-20011' });
    await seedCveRow({ cveId: 'CVE-2026-20012' });
    await seedCveState({ cveId: 'CVE-2026-20010', epssScore: 0.1, epssPercentile: 0.2 }); // unchanged below
    await seedCveState({ cveId: 'CVE-2026-20011', epssScore: 0.3, epssPercentile: 0.4 }); // unchanged below
    await seedCveState({ cveId: 'CVE-2026-20012', epssScore: 0.5, epssPercentile: 0.6 }); // will change

    const spies = spyOnBindings();
    const now = Date.now();
    const patches: EpssPatch[] = [
      { cveId: 'CVE-2026-20010', epssScore: 0.1, epssPercentile: 0.2, epssUpdatedAt: now },
      { cveId: 'CVE-2026-20011', epssScore: 0.3, epssPercentile: 0.4, epssUpdatedAt: now },
      { cveId: 'CVE-2026-20012', epssScore: 0.77, epssPercentile: 0.88, epssUpdatedAt: now },
    ];

    const ctx = createExecutionContext();
    await applyEpssPatchBatch(patches, testEnv, ctx);
    await waitOnExecutionContext(ctx);

    expect(spies.dbBatch).toHaveBeenCalledTimes(1);
    const batchedStatements = spies.dbBatch.mock.calls[0]?.[0] as unknown[];
    expect(batchedStatements).toHaveLength(1); // only the changed row

    expect(spies.cacheDelete).toHaveBeenCalledTimes(1);
    expect(spies.cacheDelete).toHaveBeenCalledWith('cve:CVE-2026-20012');

    const unchanged1 = await testEnv.DB.prepare('SELECT epss_score FROM cve_state WHERE cve_id = ?')
      .bind('CVE-2026-20010')
      .first<{ epss_score: number }>();
    const unchanged2 = await testEnv.DB.prepare('SELECT epss_score FROM cve_state WHERE cve_id = ?')
      .bind('CVE-2026-20011')
      .first<{ epss_score: number }>();
    const changed = await testEnv.DB.prepare(
      'SELECT epss_score, epss_percentile FROM cve_state WHERE cve_id = ?',
    )
      .bind('CVE-2026-20012')
      .first<{ epss_score: number; epss_percentile: number }>();

    expect(unchanged1?.epss_score).toBe(0.1);
    expect(unchanged2?.epss_score).toBe(0.3);
    expect(changed).toEqual({ epss_score: 0.77, epss_percentile: 0.88 });
  });

  // Regression test for the actual bug this task fixes: D1 caps bound
  // parameters at 100 per query. The previous implementation built the
  // `WHERE cve_id IN (...)` read from the whole input array in one query —
  // fine for the 2-3 row fixtures above, but a 250-row input (or a real
  // 250k+-row EPSS snapshot) would have blown past that cap. This asserts
  // the chunking actually happens, not just that the call succeeds.
  it('input larger than 100 patches (250): does not throw, and no single SELECT exceeds 100 bound params', async () => {
    const patches: EpssPatch[] = Array.from({ length: 250 }, (_, i) => ({
      cveId: `CVE-2026-3${String(i).padStart(4, '0')}`,
      epssScore: 0.5,
      epssPercentile: 0.5,
      epssUpdatedAt: Date.now(),
    }));
    // cve_state.cve_id is FK-constrained to cve(cve_id) — seed a cve row
    // per patch so the writes this test provokes don't fail on that
    // constraint instead of exercising the thing under test.
    await Promise.all(patches.map((p) => seedCveRow({ cveId: p.cveId })));

    const spies = spyOnBindings();

    await expect(
      applyEpssPatchBatch(patches, testEnv, createExecutionContext()),
    ).resolves.not.toThrow();

    const selectCalls = spies.boundCalls.filter((c) => /WHERE cve_id IN/i.test(c.sql));

    // It must actually be chunked (more than one SELECT), not just happen
    // not to throw — a single 250-param query would pass "doesn't throw" in
    // this local D1 simulator even though it violates the real D1 cap.
    expect(selectCalls.length).toBeGreaterThan(1);
    for (const call of selectCalls) {
      expect(call.paramCount).toBeLessThanOrEqual(100);
    }
    // Exact expected chunking for 250 patches at 100/chunk: 100, 100, 50.
    expect(selectCalls.map((c) => c.paramCount)).toEqual([100, 100, 50]);
  }, 30_000);

  it('input of exactly 1,000 patches (one EPSS_MESSAGE_CHUNK_SIZE worth): still never exceeds 100 bound params per SELECT', async () => {
    const patches: EpssPatch[] = Array.from({ length: 1000 }, (_, i) => ({
      cveId: `CVE-2026-4${String(i).padStart(4, '0')}`,
      epssScore: 0.25,
      epssPercentile: 0.25,
      epssUpdatedAt: Date.now(),
    }));
    await Promise.all(patches.map((p) => seedCveRow({ cveId: p.cveId })));

    const spies = spyOnBindings();
    await applyEpssPatchBatch(patches, testEnv, createExecutionContext());

    const selectCalls = spies.boundCalls.filter((c) => /WHERE cve_id IN/i.test(c.sql));
    expect(selectCalls).toHaveLength(10); // 1000 / 100
    for (const call of selectCalls) {
      expect(call.paramCount).toBeLessThanOrEqual(100);
    }
  }, 30_000);
});

describe('applyEpssPatchBatch write-volume guards', () => {
  useCleanBindings();

  /**
   * FIRST.org recomputes EPSS for its whole corpus daily, so nearly every
   * score drifts a little every day. Comparing for exact inequality marked
   * ~60k of our ~119k CVEs as changed every day; D1 billed 117,450 written
   * rows for it on 2026-11-02 — the entire 100k/day free-tier write
   * allowance, gone before 05:00 UTC, which then blocked schema migrations
   * and every other write in the account.
   */
  it('ignores drift too small to change a rendered figure or a ranking', async () => {
    await seedCveRow({ cveId: 'CVE-2026-50001' });
    await seedCveState({ cveId: 'CVE-2026-50001', epssScore: 0.00042, epssPercentile: 0.9412 });

    const spies = spyOnBindings();
    await applyEpssPatchBatch(
      [
        {
          cveId: 'CVE-2026-50001',
          epssScore: 0.00043, // +0.00001
          epssPercentile: 0.9413, // +0.0001
          epssUpdatedAt: Date.now(),
        },
      ],
      testEnv,
      createExecutionContext(),
    );

    expect(spies.dbBatch).not.toHaveBeenCalled();
    expect(spies.cacheDelete).not.toHaveBeenCalled();
  });

  it('writes when the score moves materially', async () => {
    await seedCveRow({ cveId: 'CVE-2026-50002' });
    await seedCveState({ cveId: 'CVE-2026-50002', epssScore: 0.01, epssPercentile: 0.5 });

    const ctx = createExecutionContext();
    await applyEpssPatchBatch(
      [
        {
          cveId: 'CVE-2026-50002',
          epssScore: 0.012, // +0.002, over the 0.001 score epsilon
          epssPercentile: 0.5,
          epssUpdatedAt: Date.now(),
        },
      ],
      testEnv,
      ctx,
    );
    await waitOnExecutionContext(ctx);

    const row = await testEnv.DB.prepare('SELECT epss_score FROM cve_state WHERE cve_id = ?')
      .bind('CVE-2026-50002')
      .first<{ epss_score: number }>();
    expect(row?.epss_score).toBe(0.012);
  });

  it('writes when the percentile moves materially even if the score barely does', async () => {
    await seedCveRow({ cveId: 'CVE-2026-50003' });
    await seedCveState({ cveId: 'CVE-2026-50003', epssScore: 0.5, epssPercentile: 0.9 });

    const ctx = createExecutionContext();
    await applyEpssPatchBatch(
      [
        {
          cveId: 'CVE-2026-50003',
          epssScore: 0.5,
          epssPercentile: 0.95, // +0.05, over the 0.005 percentile epsilon
          epssUpdatedAt: Date.now(),
        },
      ],
      testEnv,
      ctx,
    );
    await waitOnExecutionContext(ctx);

    const row = await testEnv.DB.prepare('SELECT epss_percentile FROM cve_state WHERE cve_id = ?')
      .bind('CVE-2026-50003')
      .first<{ epss_percentile: number }>();
    expect(row?.epss_percentile).toBe(0.95);
  });

  it('always writes the first EPSS value for a CVE that had none', async () => {
    await seedCveRow({ cveId: 'CVE-2026-50004' });
    await seedCveState({ cveId: 'CVE-2026-50004' }); // null score/percentile

    const ctx = createExecutionContext();
    await applyEpssPatchBatch(
      [
        {
          cveId: 'CVE-2026-50004',
          epssScore: 0.00001, // tiny, but there was nothing before
          epssPercentile: 0.00002,
          epssUpdatedAt: Date.now(),
        },
      ],
      testEnv,
      ctx,
    );
    await waitOnExecutionContext(ctx);

    const row = await testEnv.DB.prepare('SELECT epss_score FROM cve_state WHERE cve_id = ?')
      .bind('CVE-2026-50004')
      .first<{ epss_score: number }>();
    expect(row?.epss_score).toBe(0.00001);
  });

  /**
   * The correctness half of the fix. FIRST.org's snapshot covers ~399k CVEs;
   * our 24-month corpus holds ~119k, so most of every snapshot is for CVEs we
   * never ingested. cve_state.cve_id REFERENCES cve(cve_id), so the old
   * upsert's INSERT path could not create those rows — it raised a
   * foreign-key error that failed the whole db.batch and took the legitimate
   * updates batched alongside it down with it. EPSS updates for CVEs we DO
   * track were being silently lost.
   */
  it('skips CVEs we do not track, and still applies the ones we do', async () => {
    await seedCveRow({ cveId: 'CVE-2026-50010' });
    await seedCveState({ cveId: 'CVE-2026-50010', epssScore: 0.1, epssPercentile: 0.1 });

    const ctx = createExecutionContext();
    await applyEpssPatchBatch(
      [
        // Not in our corpus at all — previously an FK error that poisoned the
        // batch; now simply skipped.
        { cveId: 'CVE-1999-00001', epssScore: 0.9, epssPercentile: 0.9, epssUpdatedAt: Date.now() },
        { cveId: 'CVE-2026-50010', epssScore: 0.8, epssPercentile: 0.8, epssUpdatedAt: Date.now() },
      ],
      testEnv,
      ctx,
    );
    await waitOnExecutionContext(ctx);

    // The tracked CVE's update survived.
    const tracked = await testEnv.DB.prepare('SELECT epss_score FROM cve_state WHERE cve_id = ?')
      .bind('CVE-2026-50010')
      .first<{ epss_score: number }>();
    expect(tracked?.epss_score).toBe(0.8);

    // And no row was conjured for the untracked one.
    const untracked = await testEnv.DB.prepare(
      'SELECT COUNT(*) AS n FROM cve_state WHERE cve_id = ?',
    )
      .bind('CVE-1999-00001')
      .first<{ n: number }>();
    expect(untracked?.n).toBe(0);
  });

  it('a whole snapshot of untracked CVEs costs zero writes', async () => {
    // The common case in production: more than half of every daily snapshot.
    const patches = Array.from({ length: 200 }, (_, i) => ({
      cveId: `CVE-1998-${String(i).padStart(5, '0')}`,
      epssScore: 0.5,
      epssPercentile: 0.5,
      epssUpdatedAt: Date.now(),
    }));

    const spies = spyOnBindings();
    await applyEpssPatchBatch(patches, testEnv, createExecutionContext());

    expect(spies.dbBatch).not.toHaveBeenCalled();
    expect(spies.cacheDelete).not.toHaveBeenCalled();
  }, 30_000);
});
