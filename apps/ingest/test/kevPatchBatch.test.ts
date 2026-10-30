import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import type { KevPatch } from '@threat-lens/contracts';
import { describe, expect, it } from 'vitest';
import { applyKevPatchBatch } from '../src/lib/server/processRecord';
import { seedCveRow, seedCveState, spyOnBindings, testEnv, useCleanBindings } from './helpers';

// Batched KEV patch path — the fix for the inline-per-entry D1 bug that
// (confirmed by code reading, see docs/EXECUTION_PLAN.md's KEV row) silently
// truncated the 6-hourly KEV fast-lane: applyKevPatch-per-entry issued a
// change-detect SELECT per catalog entry inside one cron invocation, blowing
// the Free plan's 50-D1-query cap after ~50 of a 1,000+-entry catalog.
//
// The two things that MUST hold for the fix to actually work:
//   (1) the change-detect read is chunked at ≤100 bound params (D1's cap);
//   (2) the TOTAL D1 query count does NOT grow with the number of changed
//       entries — it's a few batched reads + a couple of db.batch() writes,
//       not O(n). This is the property the old per-entry loop violated.

describe('applyKevPatchBatch', () => {
  useCleanBindings();

  it('empty input: a true no-op — no D1 read, no D1 write, no cache traffic', async () => {
    const spies = spyOnBindings();

    const result = await applyKevPatchBatch([], testEnv, createExecutionContext());

    expect(result).toEqual({ processed: 0, changed: 0 });
    expect(spies.dbPrepare).not.toHaveBeenCalled();
    expect(spies.dbBatch).not.toHaveBeenCalled();
    expect(spies.cacheDelete).not.toHaveBeenCalled();
  });

  it('all entries unchanged: the batched read happens, but zero writes and zero cache deletes', async () => {
    await seedCveRow({ cveId: 'CVE-2026-50001' });
    await seedCveRow({ cveId: 'CVE-2026-50002' });
    await seedCveState({
      cveId: 'CVE-2026-50001',
      kevListed: 1,
      kevDateAdded: 1_700_000_000_000,
      kevDueDate: 1_700_600_000_000,
      kevRequiredAction: 'Apply vendor patch',
    });
    await seedCveState({
      cveId: 'CVE-2026-50002',
      kevListed: 1,
      kevDateAdded: 1_700_100_000_000,
      kevDueDate: null,
      kevRequiredAction: 'Mitigate',
    });

    const spies = spyOnBindings();
    const patches: KevPatch[] = [
      {
        cveId: 'CVE-2026-50001',
        kevDateAdded: 1_700_000_000_000,
        kevDueDate: 1_700_600_000_000,
        kevRequiredAction: 'Apply vendor patch',
      },
      {
        cveId: 'CVE-2026-50002',
        kevDateAdded: 1_700_100_000_000,
        kevDueDate: null,
        kevRequiredAction: 'Mitigate',
      },
    ];

    const result = await applyKevPatchBatch(patches, testEnv, createExecutionContext());

    expect(result).toEqual({ processed: 2, changed: 0 });
    expect(spies.dbPrepare).toHaveBeenCalledTimes(1); // only the one batched IN(...) change-detect read
    expect(spies.preparedSql()[0]).toMatch(/^\s*SELECT.*WHERE cve_id IN/is);
    expect(spies.dbBatch).not.toHaveBeenCalled();
    expect(spies.cacheDelete).not.toHaveBeenCalled();
  });

  it('mixed: unchanged entries produce no write; changed entries get a state upsert + state_hash update + cache delete', async () => {
    await seedCveRow({ cveId: 'CVE-2026-50010', severity: 'HIGH' });
    await seedCveRow({ cveId: 'CVE-2026-50011', severity: 'CRITICAL' });
    // 50010 already listed & matches the patch below → unchanged.
    await seedCveState({
      cveId: 'CVE-2026-50010',
      kevListed: 1,
      kevDateAdded: 1_700_000_000_000,
      kevDueDate: null,
      kevRequiredAction: 'Apply update',
    });
    // 50011 has no cve_state row → `cur` undefined → changed.

    const spies = spyOnBindings();
    const now = 1_700_000_000_000;
    const patches: KevPatch[] = [
      {
        cveId: 'CVE-2026-50010',
        kevDateAdded: now,
        kevDueDate: null,
        kevRequiredAction: 'Apply update',
      },
      {
        cveId: 'CVE-2026-50011',
        kevDateAdded: now,
        kevDueDate: now + 1_000,
        kevRequiredAction: 'Patch now',
      },
    ];

    const ctx = createExecutionContext();
    const result = await applyKevPatchBatch(patches, testEnv, ctx);
    await waitOnExecutionContext(ctx);

    expect(result).toEqual({ processed: 2, changed: 1 });

    // Exactly the changed row is listed; the unchanged one is untouched.
    const changed = await testEnv.DB.prepare(
      'SELECT kev_listed, kev_required_action FROM cve_state WHERE cve_id = ?',
    )
      .bind('CVE-2026-50011')
      .first<{ kev_listed: number; kev_required_action: string }>();
    expect(changed).toEqual({ kev_listed: 1, kev_required_action: 'Patch now' });

    // state_hash was recomputed on the changed row (seeded 'seed-state-hash').
    const hashRow = await testEnv.DB.prepare('SELECT state_hash FROM cve WHERE cve_id = ?')
      .bind('CVE-2026-50011')
      .first<{ state_hash: string }>();
    expect(hashRow?.state_hash).not.toBe('seed-state-hash');

    // Only the changed cve:{id} key + the shared KEV list key are invalidated.
    expect(spies.cacheDelete).toHaveBeenCalledWith('cve:CVE-2026-50011');
    expect(spies.cacheDelete).toHaveBeenCalledWith('threat:kev:list');
    expect(spies.cacheDelete).not.toHaveBeenCalledWith('cve:CVE-2026-50010');
    expect(spies.cacheDelete).toHaveBeenCalledTimes(2);
  });

  it('a changed entry with an existing Vectorize vector: propagates kev_listed:1 into its metadata (metadata-only, no AI call)', async () => {
    const cveId = 'CVE-2026-50020';
    await seedCveRow({ cveId, severity: 'HIGH' });

    const spies = spyOnBindings();
    spies.vectorizeGetByIds.mockResolvedValueOnce([
      { id: cveId, values: [0.3, 0.4], metadata: { severity: 'HIGH' } },
    ] as never);

    const patches: KevPatch[] = [
      { cveId, kevDateAdded: 1_700_000_000_000, kevDueDate: null, kevRequiredAction: 'Mitigate' },
    ];
    await applyKevPatchBatch(patches, testEnv, createExecutionContext());

    expect(spies.aiRun).not.toHaveBeenCalled(); // metadata-only — never embeds
    expect(spies.vectorizeUpsert).toHaveBeenCalledTimes(1);
    const upserted = spies.vectorizeUpsert.mock.calls[0]?.[0]?.[0];
    expect(upserted?.values).toEqual([0.3, 0.4]);
    expect(upserted?.metadata).toMatchObject({ severity: 'HIGH', kev_listed: 1 });
  });

  // The core regression guard: D1 caps the change-detect SELECT at 100 bound
  // params, AND the whole point of the fix is that the total query count does
  // not scale with the entry count. 250 entries, all changed.
  it('250 entries all changed: never exceeds 100 bound params per SELECT, and total D1 queries stay small (not O(n))', async () => {
    const patches: KevPatch[] = Array.from({ length: 250 }, (_, i) => ({
      cveId: `CVE-2026-6${String(i).padStart(4, '0')}`,
      kevDateAdded: 1_700_000_000_000,
      kevDueDate: null,
      kevRequiredAction: 'Patch',
    }));
    await Promise.all(patches.map((p) => seedCveRow({ cveId: p.cveId })));

    const spies = spyOnBindings();

    const result = await applyKevPatchBatch(patches, testEnv, createExecutionContext());
    expect(result).toEqual({ processed: 250, changed: 250 });

    // (1) No single SELECT binds more than 100 params. There are TWO
    // chunked IN(...) reads — the change-detect (`WHERE cve_id IN`) and the
    // state_hash recompute (`WHERE c.cve_id IN`, aliased) — so match both
    // via the optional `c.` prefix; each chunks 100/100/50.
    const selectCalls = spies.boundCalls.filter((c) => /WHERE (c\.)?cve_id IN/i.test(c.sql));
    for (const call of selectCalls) expect(call.paramCount).toBeLessThanOrEqual(100);
    expect(selectCalls.map((c) => c.paramCount)).toEqual([100, 100, 50, 100, 100, 50]);

    // (2) Total per-invocation D1 query count = standalone queries + db.batch()
    // calls (see helpers.ts). It must stay well under the 50-query Free-tier
    // cap even with 250 changed entries — the property the old per-entry loop
    // (250+ SELECTs) violated. 6 reads (all()) + ceil(250/500)*2 batch writes
    // = 6 + 2 = 8.
    const standaloneQueries = spies.queryCalls.length;
    const batchCalls = spies.dbBatch.mock.calls.length;
    expect(standaloneQueries + batchCalls).toBeLessThanOrEqual(50);
    expect(standaloneQueries + batchCalls).toBe(8);
  }, 30_000);

  it('de-dupes repeated cveIds within one message (defensive): a doubled entry is processed once', async () => {
    const cveId = 'CVE-2026-50030';
    await seedCveRow({ cveId });
    spyOnBindings(); // Vectorize has no local simulator — stub it (getByIds returns [] by default)

    const patch: KevPatch = {
      cveId,
      kevDateAdded: 1_700_000_000_000,
      kevDueDate: null,
      kevRequiredAction: 'Patch',
    };
    const result = await applyKevPatchBatch([patch, patch], testEnv, createExecutionContext());

    expect(result).toEqual({ processed: 1, changed: 1 });
  });
});
