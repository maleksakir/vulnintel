import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import type { OsvFetchItem, OsvPatch } from '@threat-lens/contracts';
import { describe, expect, it } from 'vitest';
import { applyOsvPatchBatch, type OsvFetchResult } from '../src/lib/server/osvPatch';
import { seedCveRow, spyOnBindings, testEnv, useCleanBindings } from './helpers';

function item(overrides: Partial<OsvFetchItem> = {}): OsvFetchItem {
  return {
    osvId: 'GHSA-aaaa-bbbb-cccc',
    ecosystemDir: 'npm',
    modified: '2026-10-28T00:00:00.000000000Z',
    ...overrides,
  };
}

function patch(overrides: Partial<OsvPatch> = {}): OsvPatch {
  return {
    osvId: 'GHSA-aaaa-bbbb-cccc',
    modified: '2026-10-28T00:00:00.000000000Z',
    published: '2026-10-20T00:00:00.000000000Z',
    withdrawn: false,
    cveIds: ['CVE-2026-50001'],
    affected: [
      {
        ecosystem: 'npm',
        name: 'left-pad-evil',
        purl: 'pkg:npm/left-pad-evil',
        ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.2.3' }] }],
        fixedVersions: ['1.2.3'],
      },
    ],
    ...overrides,
  };
}

describe('applyOsvPatchBatch', () => {
  useCleanBindings();

  it('empty input: a true no-op — no D1 read, no D1 write', async () => {
    const spies = spyOnBindings();

    const result = await applyOsvPatchBatch([], testEnv, createExecutionContext());

    expect(result).toEqual({ written: 0, skipped: 0, unlinked: 0, quarantined: 0 });
    expect(spies.dbPrepare).not.toHaveBeenCalled();
    expect(spies.dbBatch).not.toHaveBeenCalled();
  });

  it('OK + CVE already ingested: LINKED, writes one cve_osv_affected row', async () => {
    await seedCveRow({ cveId: 'CVE-2026-50001' });
    const it1 = item();
    const results: OsvFetchResult[] = [{ item: it1, outcome: 'OK', patch: patch() }];

    const ctx = createExecutionContext();
    const result = await applyOsvPatchBatch(results, testEnv, ctx);
    await waitOnExecutionContext(ctx);

    expect(result).toEqual({ written: 1, skipped: 0, unlinked: 0, quarantined: 0 });

    const stateRow = await testEnv.DB.prepare(
      'SELECT status, cve_ids, modified_at FROM osv_record_state WHERE osv_id = ?',
    )
      .bind(it1.osvId)
      .first<{ status: string; cve_ids: string; modified_at: string }>();
    expect(stateRow).toEqual({
      status: 'LINKED',
      cve_ids: 'CVE-2026-50001',
      modified_at: it1.modified,
    });

    const affectedRow = await testEnv.DB.prepare(
      'SELECT ecosystem, package_name, fixed_versions FROM cve_osv_affected WHERE osv_id = ?',
    )
      .bind(it1.osvId)
      .first<{ ecosystem: string; package_name: string; fixed_versions: string }>();
    expect(affectedRow).toEqual({
      ecosystem: 'npm',
      package_name: 'left-pad-evil',
      fixed_versions: '1.2.3',
    });
  });

  it('OK + no CVE alias: NO_CVE_ALIAS, no cve_osv_affected row, counted unlinked', async () => {
    const it1 = item({ osvId: 'GHSA-dddd-eeee-ffff' });
    const results: OsvFetchResult[] = [
      { item: it1, outcome: 'OK', patch: patch({ osvId: it1.osvId, cveIds: [] }) },
    ];

    const result = await applyOsvPatchBatch(results, testEnv, createExecutionContext());
    expect(result).toEqual({ written: 1, skipped: 0, unlinked: 1, quarantined: 0 });

    const stateRow = await testEnv.DB.prepare(
      'SELECT status FROM osv_record_state WHERE osv_id = ?',
    )
      .bind(it1.osvId)
      .first<{ status: string }>();
    expect(stateRow?.status).toBe('NO_CVE_ALIAS');

    const affectedCount = await testEnv.DB.prepare(
      'SELECT COUNT(*) AS n FROM cve_osv_affected WHERE osv_id = ?',
    )
      .bind(it1.osvId)
      .first<{ n: number }>();
    expect(affectedCount?.n).toBe(0);
  });

  it('OK + CVE alias not yet ingested by NVD/MITRE: CVE_NOT_INGESTED, no affected row (re-link pass picks it up later)', async () => {
    // Deliberately no seedCveRow — this is the "GHSA arrives before NVD" case.
    const it1 = item({ osvId: 'GHSA-1111-2222-3333' });
    const results: OsvFetchResult[] = [
      {
        item: it1,
        outcome: 'OK',
        patch: patch({ osvId: it1.osvId, cveIds: ['CVE-2026-99999'] }),
      },
    ];

    const result = await applyOsvPatchBatch(results, testEnv, createExecutionContext());
    expect(result).toEqual({ written: 1, skipped: 0, unlinked: 1, quarantined: 0 });

    const stateRow = await testEnv.DB.prepare(
      'SELECT status, cve_ids FROM osv_record_state WHERE osv_id = ?',
    )
      .bind(it1.osvId)
      .first<{ status: string; cve_ids: string }>();
    expect(stateRow).toEqual({ status: 'CVE_NOT_INGESTED', cve_ids: 'CVE-2026-99999' });
  });

  it('re-link: a previously CVE_NOT_INGESTED record is promoted to LINKED once the CVE now exists', async () => {
    const it1 = item({ osvId: 'GHSA-4444-5555-6666' });
    const first: OsvFetchResult[] = [
      { item: it1, outcome: 'OK', patch: patch({ osvId: it1.osvId, cveIds: ['CVE-2026-60000'] }) },
    ];
    await applyOsvPatchBatch(first, testEnv, createExecutionContext());

    let stateRow = await testEnv.DB.prepare('SELECT status FROM osv_record_state WHERE osv_id = ?')
      .bind(it1.osvId)
      .first<{ status: string }>();
    expect(stateRow?.status).toBe('CVE_NOT_INGESTED');

    // NVD/MITRE catches up...
    await seedCveRow({ cveId: 'CVE-2026-60000' });

    // ...and the re-link pass refetches the same record (modified unchanged
    // on OSV's side — only our D1 view of CVE existence changed).
    const second: OsvFetchResult[] = [
      { item: it1, outcome: 'OK', patch: patch({ osvId: it1.osvId, cveIds: ['CVE-2026-60000'] }) },
    ];
    await applyOsvPatchBatch(second, testEnv, createExecutionContext());

    stateRow = await testEnv.DB.prepare('SELECT status FROM osv_record_state WHERE osv_id = ?')
      .bind(it1.osvId)
      .first<{ status: string }>();
    expect(stateRow?.status).toBe('LINKED');

    const affectedCount = await testEnv.DB.prepare(
      'SELECT COUNT(*) AS n FROM cve_osv_affected WHERE osv_id = ? AND cve_id = ?',
    )
      .bind(it1.osvId, 'CVE-2026-60000')
      .first<{ n: number }>();
    expect(affectedCount?.n).toBe(1);
  });

  it('unchanged on rescan (same modified + same content): skipped, checked_at bumped, no affected-row churn', async () => {
    await seedCveRow({ cveId: 'CVE-2026-50001' });
    const it1 = item();
    const p = patch();

    await applyOsvPatchBatch(
      [{ item: it1, outcome: 'OK', patch: p }],
      testEnv,
      createExecutionContext(),
    );

    const spies = spyOnBindings();
    const result = await applyOsvPatchBatch(
      [{ item: it1, outcome: 'OK', patch: p }],
      testEnv,
      createExecutionContext(),
    );

    expect(result).toEqual({ written: 0, skipped: 1, unlinked: 0, quarantined: 0 });
    const batchedStatements = spies.dbBatch.mock.calls[0]?.[0] as unknown[];
    expect(batchedStatements).toHaveLength(1); // just the checked_at bump
  });

  it('NOT_FOUND (404 from OSV API): WITHDRAWN, clears any previously-linked affected rows', async () => {
    await seedCveRow({ cveId: 'CVE-2026-50001' });
    const it1 = item();
    await applyOsvPatchBatch(
      [{ item: it1, outcome: 'OK', patch: patch() }],
      testEnv,
      createExecutionContext(),
    );

    let affectedCount = await testEnv.DB.prepare(
      'SELECT COUNT(*) AS n FROM cve_osv_affected WHERE osv_id = ?',
    )
      .bind(it1.osvId)
      .first<{ n: number }>();
    expect(affectedCount?.n).toBe(1);

    const result = await applyOsvPatchBatch(
      [{ item: it1, outcome: 'NOT_FOUND' }],
      testEnv,
      createExecutionContext(),
    );
    expect(result).toEqual({ written: 1, skipped: 0, unlinked: 1, quarantined: 0 });

    const stateRow = await testEnv.DB.prepare(
      'SELECT status FROM osv_record_state WHERE osv_id = ?',
    )
      .bind(it1.osvId)
      .first<{ status: string }>();
    expect(stateRow?.status).toBe('WITHDRAWN');

    affectedCount = await testEnv.DB.prepare(
      'SELECT COUNT(*) AS n FROM cve_osv_affected WHERE osv_id = ?',
    )
      .bind(it1.osvId)
      .first<{ n: number }>();
    expect(affectedCount?.n).toBe(0);
  });

  it('MALFORMED: quarantined, no osv_record_state row written', async () => {
    const it1 = item({ osvId: 'GHSA-7777-8888-9999' });
    const result = await applyOsvPatchBatch(
      [
        {
          item: it1,
          outcome: 'MALFORMED',
          rawPayloadForQuarantine: '{"id":"GHSA-7777-8888-9999"}',
          errorMessage: 'missing modified field',
        },
      ],
      testEnv,
      createExecutionContext(),
    );
    expect(result).toEqual({ written: 0, skipped: 0, unlinked: 0, quarantined: 1 });

    const q = await testEnv.DB.prepare(
      'SELECT source, error_code, payload FROM cve_quarantine WHERE source = ?',
    )
      .bind('OSV')
      .first<{ source: string; error_code: string; payload: string }>();
    expect(q?.error_code).toBe('OSV_PARSE_FAILED');
    expect(q?.payload).toContain('GHSA-7777-8888-9999');

    const stateRow = await testEnv.DB.prepare(
      'SELECT osv_id FROM osv_record_state WHERE osv_id = ?',
    )
      .bind(it1.osvId)
      .first();
    expect(stateRow).toBeNull();
  });

  it('FETCH_FAILED: left untouched entirely (no state write, no quarantine) — counted skipped', async () => {
    const it1 = item({ osvId: 'GHSA-aaaa-1111-bbbb' });
    const result = await applyOsvPatchBatch(
      [{ item: it1, outcome: 'FETCH_FAILED', errorMessage: 'network error' }],
      testEnv,
      createExecutionContext(),
    );
    expect(result).toEqual({ written: 0, skipped: 1, unlinked: 0, quarantined: 0 });

    const stateRow = await testEnv.DB.prepare(
      'SELECT osv_id FROM osv_record_state WHERE osv_id = ?',
    )
      .bind(it1.osvId)
      .first();
    expect(stateRow).toBeNull();
  });

  // Regression test: D1 caps bound parameters at 100 per query. Both batch
  // reads in applyOsvPatchBatch (osv_record_state and cve existence) must
  // chunk regardless of input size — this asserts the chunking actually
  // happens for a batch far larger than this path ever sees in production
  // (OSV_FETCH_CHUNK_SIZE caps real input at 20).
  it('input larger than 100 items (150): no single SELECT exceeds 100 bound params', async () => {
    const results: OsvFetchResult[] = [];
    for (let i = 0; i < 150; i++) {
      const osvId = `GHSA-${String(1000 + i).padStart(4, '0')}-aaaa-bbbb`;
      const cveId = `CVE-2026-7${String(i).padStart(4, '0')}`;
      await seedCveRow({ cveId });
      results.push({
        item: item({ osvId, modified: `2026-10-2${i % 9}T00:00:00.000000000Z` }),
        outcome: 'OK',
        patch: patch({ osvId, cveIds: [cveId], modified: `2026-10-2${i % 9}T00:00:00.000000000Z` }),
      });
    }

    const spies = spyOnBindings();
    await expect(
      applyOsvPatchBatch(results, testEnv, createExecutionContext()),
    ).resolves.not.toThrow();

    const selectCalls = spies.boundCalls.filter((c) =>
      /WHERE osv_id IN|WHERE cve_id IN/i.test(c.sql),
    );
    expect(selectCalls.length).toBeGreaterThan(1); // actually chunked, not one 150-param query
    for (const call of selectCalls) {
      expect(call.paramCount).toBeLessThanOrEqual(100);
    }
  }, 30_000);
});
