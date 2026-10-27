import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { applyKevPatch } from '../src/lib/server/processRecord';
import { seedCveRow, seedCveState, spyOnBindings, testEnv, useCleanBindings } from './helpers';
import type { KevPatch } from '@threat-lens/contracts';

describe('applyKevPatch', () => {
  useCleanBindings();

  it('unchanged patch: no-op — no D1 write, no cache delete, no analytics event', async () => {
    const cveId = 'CVE-2026-10001';
    await seedCveRow({ cveId });
    await seedCveState({
      cveId,
      kevListed: 1,
      kevDateAdded: 1_700_000_000_000,
      kevDueDate: 1_700_600_000_000,
      kevRequiredAction: 'Apply vendor patch',
    });

    const spies = spyOnBindings();
    const patch: KevPatch = {
      cveId,
      kevDateAdded: 1_700_000_000_000,
      kevDueDate: 1_700_600_000_000,
      kevRequiredAction: 'Apply vendor patch',
    };

    await applyKevPatch(patch, testEnv, createExecutionContext());

    // Only the initial read should have happened — no write statement at all.
    expect(spies.dbPrepare).toHaveBeenCalledTimes(1);
    expect(spies.preparedSql()[0]).toMatch(/^\s*SELECT/i);
    expect(spies.cacheDelete).not.toHaveBeenCalled();
    expect(spies.analyticsWrite).not.toHaveBeenCalled();
    expect(spies.vectorizeUpsert).not.toHaveBeenCalled();
  });

  it('changed patch (first time listed): writes cve_state, recomputes state_hash, invalidates both cache keys', async () => {
    const cveId = 'CVE-2026-10002';
    await seedCveRow({ cveId, severity: 'HIGH' });
    // No existing cve_state row — `unchanged` is false since `cur` is undefined.

    const spies = spyOnBindings();
    const ctx = createExecutionContext();
    const patch: KevPatch = {
      cveId,
      kevDateAdded: 1_700_000_000_000,
      kevDueDate: 1_700_600_000_000,
      kevRequiredAction: 'Apply vendor patch',
    };

    await applyKevPatch(patch, testEnv, ctx);
    await waitOnExecutionContext(ctx);

    const writeSql = spies.preparedSql().filter((sql) => /^\s*(INSERT|UPDATE)/i.test(sql));
    expect(writeSql).toHaveLength(2); // cve_state upsert + cve.state_hash update
    expect(writeSql[0]).toMatch(/INSERT INTO cve_state/i);
    expect(writeSql[1]).toMatch(/UPDATE cve SET state_hash/i);

    expect(spies.cacheDelete).toHaveBeenCalledTimes(2);
    expect(spies.cacheDelete).toHaveBeenCalledWith(`cve:${cveId}`);
    expect(spies.cacheDelete).toHaveBeenCalledWith('threat:kev:list');

    expect(spies.analyticsWrite).toHaveBeenCalledTimes(1);

    const row = await testEnv.DB.prepare('SELECT kev_listed, kev_required_action FROM cve_state WHERE cve_id = ?')
      .bind(cveId)
      .first<{ kev_listed: number; kev_required_action: string }>();
    expect(row).toEqual({ kev_listed: 1, kev_required_action: 'Apply vendor patch' });
  });

  it('changed patch with an existing Vectorize entry: propagates kev_listed into its metadata', async () => {
    const cveId = 'CVE-2026-10003';
    await seedCveRow({ cveId, severity: 'HIGH' });

    const spies = spyOnBindings();
    spies.vectorizeGetByIds.mockResolvedValueOnce([
      { id: cveId, values: [0.1, 0.2], metadata: { severity: 'HIGH' } },
    ] as never);

    const patch: KevPatch = {
      cveId,
      kevDateAdded: 1_700_000_000_000,
      kevDueDate: null,
      kevRequiredAction: 'Mitigate',
    };
    await applyKevPatch(patch, testEnv, createExecutionContext());

    expect(spies.vectorizeUpsert).toHaveBeenCalledTimes(1);
    const upserted = spies.vectorizeUpsert.mock.calls[0]?.[0]?.[0];
    expect(upserted?.values).toEqual([0.1, 0.2]);
    expect(upserted?.metadata).toMatchObject({ severity: 'HIGH', kev_listed: 1 });
  });
});
