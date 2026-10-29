import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import type { OsvFetchItem } from '@threat-lens/contracts';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { runOsvFetchBatch } from '../src/pipelines/osv';
import { seedCveRow, testEnv, useCleanBindings } from './helpers';

// Coverage for runOsvFetchBatch (the queue-consumer entry point: fetch each
// item from api.osv.dev, normalize it, then hand the whole batch to
// applyOsvPatchBatch) — end to end against a stubbed `fetch`, distinct from
// osvPatchBatch.test.ts, which calls applyOsvPatchBatch directly with
// pre-built OsvFetchResult[] and never exercises fetchAndNormalize/
// OSV_ID_ALLOW at this layer.

function requestUrl(input: RequestInfo | URL): string {
  if (typeof input === 'string') return input;
  if (input instanceof URL) return input.href;
  return input.url;
}

function item(overrides: Partial<OsvFetchItem> = {}): OsvFetchItem {
  return {
    osvId: 'GHSA-cccc-dddd-eeee',
    ecosystemDir: 'npm',
    modified: '2026-10-29T00:00:00.000000000Z',
    ...overrides,
  };
}

function osvApiRecord(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 'GHSA-cccc-dddd-eeee',
    modified: '2026-10-29T00:00:00.000000000Z',
    aliases: ['CVE-2026-80001'],
    affected: [
      {
        package: { ecosystem: 'npm', name: 'vulnerable-pkg', purl: 'pkg:npm/vulnerable-pkg' },
        ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '2.0.0' }] }],
      },
    ],
    ...overrides,
  };
}

describe('runOsvFetchBatch', () => {
  useCleanBindings();

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('fetches, normalizes, and links a record whose CVE alias already exists in `cve`', async () => {
    await seedCveRow({ cveId: 'CVE-2026-80001' });
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const url = requestUrl(input);
        if (url === 'https://api.osv.dev/v1/vulns/GHSA-cccc-dddd-eeee') {
          return new Response(JSON.stringify(osvApiRecord()), { status: 200 });
        }
        throw new Error(`unexpected fetch() call in test: ${url}`);
      }),
    );

    const ctx = createExecutionContext();
    await runOsvFetchBatch([item()], testEnv, ctx);
    await waitOnExecutionContext(ctx);

    const stateRow = await testEnv.DB.prepare(
      'SELECT status FROM osv_record_state WHERE osv_id = ?',
    )
      .bind('GHSA-cccc-dddd-eeee')
      .first<{ status: string }>();
    expect(stateRow?.status).toBe('LINKED');

    const affectedRow = await testEnv.DB.prepare(
      'SELECT package_name FROM cve_osv_affected WHERE osv_id = ? AND cve_id = ?',
    )
      .bind('GHSA-cccc-dddd-eeee', 'CVE-2026-80001')
      .first<{ package_name: string }>();
    expect(affectedRow?.package_name).toBe('vulnerable-pkg');
  });

  it('a 404 from the OSV API marks the record WITHDRAWN end to end', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('not found', { status: 404 })),
    );

    await runOsvFetchBatch(
      [item({ osvId: 'GHSA-ffff-0000-1111' })],
      testEnv,
      createExecutionContext(),
    );

    const stateRow = await testEnv.DB.prepare(
      'SELECT status FROM osv_record_state WHERE osv_id = ?',
    )
      .bind('GHSA-ffff-0000-1111')
      .first<{ status: string }>();
    expect(stateRow?.status).toBe('WITHDRAWN');
  });

  it('a network/non-404 HTTP error leaves the record untouched (FETCH_FAILED) instead of throwing the whole batch', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('server error', { status: 503 })),
    );

    await expect(
      runOsvFetchBatch([item({ osvId: 'GHSA-2222-3333-4444' })], testEnv, createExecutionContext()),
    ).resolves.toBeUndefined();

    const stateRow = await testEnv.DB.prepare(
      'SELECT osv_id FROM osv_record_state WHERE osv_id = ?',
    )
      .bind('GHSA-2222-3333-4444')
      .first();
    expect(stateRow).toBeNull(); // left untouched, not quarantined, not written
  });

  it('a malformed/unsafe osvId in the work item never reaches URL construction (fetch is never called for it) and is quarantined instead of thrown', async () => {
    const fetchSpy = vi.fn(async () => {
      throw new Error('fetch should never have been called for a malformed id');
    });
    vi.stubGlobal('fetch', fetchSpy);

    const maliciousItem = item({ osvId: 'GHSA-aaaa-bbbb-cccc/../../etc/passwd' });

    await expect(
      runOsvFetchBatch([maliciousItem], testEnv, createExecutionContext()),
    ).resolves.toBeUndefined();

    expect(fetchSpy).not.toHaveBeenCalled();

    const q = await testEnv.DB.prepare(
      'SELECT error_code, error_message FROM cve_quarantine WHERE source = ?',
    )
      .bind('OSV')
      .first<{ error_code: string; error_message: string }>();
    expect(q?.error_code).toBe('OSV_PARSE_FAILED');
    expect(q?.error_message).toMatch(/invalid OSV id shape/i);

    // Never written as if it were a real, trackable record.
    const stateRow = await testEnv.DB.prepare(
      'SELECT osv_id FROM osv_record_state WHERE osv_id = ?',
    )
      .bind(maliciousItem.osvId)
      .first();
    expect(stateRow).toBeNull();
  });

  it('a batch mixing a safe and a malicious id only ever calls fetch() for the safe one', async () => {
    const calledUrls: string[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const url = requestUrl(input);
        calledUrls.push(url);
        return new Response('not found', { status: 404 });
      }),
    );

    await runOsvFetchBatch(
      [
        item({ osvId: 'GHSA-5555-6666-7777' }),
        item({ osvId: "GHSA-5555-6666-7777'; DROP TABLE cve;--" }),
      ],
      testEnv,
      createExecutionContext(),
    );

    expect(calledUrls).toEqual(['https://api.osv.dev/v1/vulns/GHSA-5555-6666-7777']);
  });

  it('FK ON DELETE CASCADE: deleting the cve row removes its cve_osv_affected rows automatically', async () => {
    await seedCveRow({ cveId: 'CVE-2026-80001' });
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const url = requestUrl(input);
        if (url === 'https://api.osv.dev/v1/vulns/GHSA-cccc-dddd-eeee') {
          return new Response(JSON.stringify(osvApiRecord()), { status: 200 });
        }
        throw new Error(`unexpected fetch() call in test: ${url}`);
      }),
    );

    const ctx = createExecutionContext();
    await runOsvFetchBatch([item()], testEnv, ctx);
    await waitOnExecutionContext(ctx);

    const before = await testEnv.DB.prepare(
      'SELECT COUNT(*) AS n FROM cve_osv_affected WHERE cve_id = ?',
    )
      .bind('CVE-2026-80001')
      .first<{ n: number }>();
    expect(before?.n).toBe(1);

    await testEnv.DB.prepare('DELETE FROM cve WHERE cve_id = ?').bind('CVE-2026-80001').run();

    const after = await testEnv.DB.prepare(
      'SELECT COUNT(*) AS n FROM cve_osv_affected WHERE cve_id = ?',
    )
      .bind('CVE-2026-80001')
      .first<{ n: number }>();
    expect(after?.n).toBe(0);
  });

  it("FK ON DELETE CASCADE holds for a record linked to multiple CVE aliases: deleting one CVE only removes that CVE's rows", async () => {
    await seedCveRow({ cveId: 'CVE-2026-80010' });
    await seedCveRow({ cveId: 'CVE-2026-80011' });
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const url = requestUrl(input);
        if (url === 'https://api.osv.dev/v1/vulns/GHSA-m1t9-cve0-11nk') {
          return new Response(
            JSON.stringify(
              osvApiRecord({
                id: 'GHSA-m1t9-cve0-11nk',
                aliases: ['CVE-2026-80010', 'CVE-2026-80011'],
              }),
            ),
            { status: 200 },
          );
        }
        throw new Error(`unexpected fetch() call in test: ${url}`);
      }),
    );

    await runOsvFetchBatch(
      [item({ osvId: 'GHSA-m1t9-cve0-11nk' })],
      testEnv,
      createExecutionContext(),
    );

    const countFor = async (cveId: string) => {
      const row = await testEnv.DB.prepare(
        'SELECT COUNT(*) AS n FROM cve_osv_affected WHERE cve_id = ?',
      )
        .bind(cveId)
        .first<{ n: number }>();
      return row?.n ?? 0;
    };
    expect(await countFor('CVE-2026-80010')).toBe(1);
    expect(await countFor('CVE-2026-80011')).toBe(1);

    await testEnv.DB.prepare('DELETE FROM cve WHERE cve_id = ?').bind('CVE-2026-80010').run();

    expect(await countFor('CVE-2026-80010')).toBe(0);
    expect(await countFor('CVE-2026-80011')).toBe(1); // untouched
  });
});
