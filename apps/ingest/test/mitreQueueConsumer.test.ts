import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import type { MitreCweQueueMessage } from '@threat-lens/contracts';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { runMitreCweConsumer } from '../src/pipelines/mitreQueue';
import { seedCveRow, spyOnBindings, testEnv, useCleanBindings } from './helpers';

// MITRE CWE gap-fill queue CONSUMER coverage (pipelines/mitreQueue.ts's
// runMitreCweConsumer), end to end against real local D1
// (@cloudflare/vitest-plugin's workerd) — same convention as
// nvdQueueConsumer.test.ts/epssQueueConsumer.test.ts. The free-text
// CWE-extraction regex itself is covered in test/mitreAdapter.test.ts; this
// file is about the consumer's OWN contract: message validation, the
// qualifying-CVE recheck, bounded fetch, and the single conditional
// db.batch() write.
//
// Stubs the global `fetch` (same reasoning as nvdProducer.test.ts/
// epssProducer.test.ts — `vi.mock` on project-relative source paths does
// not reliably intercept the module graph under `@cloudflare/vitest-plugin`'s
// real workerd runtime).

function requestUrl(input: RequestInfo | URL): string {
  if (typeof input === 'string') return input;
  if (input instanceof URL) return input.href;
  return input.url;
}

/** Minimal MITRE CVE JSON 5.0 body carrying one free-text CWE on the CNA container. */
function mitreBody(cweText: string) {
  return {
    cveMetadata: { state: 'PUBLISHED' },
    containers: {
      cna: { problemTypes: [{ descriptions: [{ description: cweText }] }] },
    },
  };
}

async function seedCwe(cweId: string): Promise<void> {
  await testEnv.DB.prepare(
    'INSERT OR IGNORE INTO cwe (cwe_id, name, category) VALUES (?, NULL, NULL)',
  )
    .bind(cweId)
    .run();
}

async function seedCveCwe(cveId: string, cweId: string): Promise<void> {
  await seedCwe(cweId);
  await testEnv.DB.prepare('INSERT INTO cve_cwe (cve_id, cwe_id) VALUES (?, ?)')
    .bind(cveId, cweId)
    .run();
}

describe('runMitreCweConsumer', () => {
  useCleanBindings();

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('acks (resolves, no fetch/D1) a malformed message — missing/non-array cveIds', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('fetch must not be called for a malformed message');
      }),
    );
    const spies = spyOnBindings();

    await expect(
      runMitreCweConsumer({} as MitreCweQueueMessage, testEnv, createExecutionContext()),
    ).resolves.toBeUndefined();

    expect(spies.dbPrepare).not.toHaveBeenCalled();
    const point = spies.analyticsWrite.mock.calls.at(-1)?.[0] as { blobs: string[] };
    expect(point.blobs).toEqual(['MITRE_QUEUE', 'MALFORMED_MESSAGE', '', '', '', '', '']);
  });

  it('filters out CVE-ID-shaped-but-invalid entries (short year-number pattern) before ever building a URL, and drops the message entirely when nothing survives', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('fetch must not be called when no id is valid');
      }),
    );
    const spies = spyOnBindings();

    const message: MitreCweQueueMessage = { cveIds: ['not-a-cve', 'CVE-26-1', '12345'] };
    await expect(
      runMitreCweConsumer(message, testEnv, createExecutionContext()),
    ).resolves.toBeUndefined();

    expect(spies.dbPrepare).not.toHaveBeenCalled();
    const point = spies.analyticsWrite.mock.calls.at(-1)?.[0] as {
      blobs: string[];
      doubles: number[];
    };
    expect(point.blobs[1]).toBe('NO_VALID_IDS');
    expect(point.doubles[3]).toBe(3); // invalidCount
  });

  it("a batch mixing a safe and an injection-looking id only ever calls fetch() for the safe one — same ID-allowlist property as OSV's build", async () => {
    await seedCveRow({ cveId: 'CVE-2026-50001', textHash: 't', stateHash: 's' });
    const calledUrls: string[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        calledUrls.push(requestUrl(input));
        return new Response(JSON.stringify(mitreBody('CWE-79 Cross-Site Scripting (XSS)')), {
          status: 200,
        });
      }),
    );

    await runMitreCweConsumer(
      { cveIds: ['CVE-2026-50001', "CVE-2026-50002'; DROP TABLE cve;--"] },
      testEnv,
      createExecutionContext(),
    );

    expect(calledUrls).toEqual(['https://cveawg.mitre.org/api/cve/CVE-2026-50001']);
  });

  it('accepts a 6+ digit CVE sequence number (e.g. CVE-2026-115274) as valid', async () => {
    await seedCveRow({ cveId: 'CVE-2026-115274', textHash: 't', stateHash: 's' });
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const url = requestUrl(input);
        expect(url).toBe('https://cveawg.mitre.org/api/cve/CVE-2026-115274');
        return new Response(JSON.stringify(mitreBody('CWE-79 Cross-Site Scripting (XSS)')), {
          status: 200,
        });
      }),
    );

    await runMitreCweConsumer({ cveIds: ['CVE-2026-115274'] }, testEnv, createExecutionContext());

    const row = await testEnv.DB.prepare('SELECT cwe_id FROM cve_cwe WHERE cve_id = ?')
      .bind('CVE-2026-115274')
      .first<{ cwe_id: string }>();
    expect(row?.cwe_id).toBe('CWE-79');
  });

  it('skips a valid-shaped CVE ID that has no row in `cve` at all (never fetched)', async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);

    await runMitreCweConsumer({ cveIds: ['CVE-2026-00001'] }, testEnv, createExecutionContext());

    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('skips a CVE that already has at least one CWE — the correctness guard against overriding NVD data (never fetched)', async () => {
    await seedCveRow({ cveId: 'CVE-2026-00002', textHash: 't', stateHash: 's' });
    await seedCveCwe('CVE-2026-00002', 'CWE-89');

    const fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);

    await runMitreCweConsumer({ cveIds: ['CVE-2026-00002'] }, testEnv, createExecutionContext());

    expect(fetchSpy).not.toHaveBeenCalled();
    const rows = await testEnv.DB.prepare('SELECT cwe_id FROM cve_cwe WHERE cve_id = ?')
      .bind('CVE-2026-00002')
      .all<{ cwe_id: string }>();
    expect(rows.results.map((r) => r.cwe_id)).toEqual(['CWE-89']); // unchanged
  });

  it('writes cwe + cve_cwe + cve_source_provenance for a qualifying CVE whose MITRE record only has a free-text CWE, and touches nothing else (no text_hash/state_hash/Vectorize/AI/KV)', async () => {
    await seedCveRow({
      cveId: 'CVE-2026-00003',
      textHash: 'unchanged-text',
      stateHash: 'unchanged-state',
    });
    vi.stubGlobal(
      'fetch',
      vi.fn(
        async () =>
          new Response(JSON.stringify(mitreBody('CWE-79 Cross-Site Scripting (XSS)')), {
            status: 200,
          }),
      ),
    );
    const spies = spyOnBindings();

    const ctx = createExecutionContext();
    await runMitreCweConsumer({ cveIds: ['CVE-2026-00003'] }, testEnv, ctx);
    await waitOnExecutionContext(ctx);

    // Captured immediately after the consumer runs, BEFORE this test's own
    // verification SELECTs below (which also go through the spied
    // `db.prepare`) so they don't inflate the count being regression-tested.
    expect(spies.dbBatch).toHaveBeenCalledTimes(1);
    const totalD1Ops = spies.queryCalls.length + spies.dbBatch.mock.calls.length;
    // Exactly one write operation (the single conditional db.batch()) plus
    // the one qualifying-check read — the actual regression test for "one
    // db.batch(), not a write per row".
    expect(totalD1Ops).toBe(2);

    const cweRow = await testEnv.DB.prepare('SELECT cwe_id FROM cve_cwe WHERE cve_id = ?')
      .bind('CVE-2026-00003')
      .first<{ cwe_id: string }>();
    expect(cweRow?.cwe_id).toBe('CWE-79');

    const provRow = await testEnv.DB.prepare(
      'SELECT source FROM cve_source_provenance WHERE cve_id = ? AND source = ?',
    )
      .bind('CVE-2026-00003', 'MITRE')
      .first<{ source: string }>();
    expect(provRow?.source).toBe('MITRE');

    // text_hash/state_hash on the cve row are untouched.
    const cveRow = await testEnv.DB.prepare(
      'SELECT text_hash, state_hash FROM cve WHERE cve_id = ?',
    )
      .bind('CVE-2026-00003')
      .first<{ text_hash: string; state_hash: string }>();
    expect(cveRow).toEqual({ text_hash: 'unchanged-text', state_hash: 'unchanged-state' });

    expect(spies.aiRun).not.toHaveBeenCalled();
    expect(spies.vectorizeUpsert).not.toHaveBeenCalled();
    expect(spies.cacheDelete).not.toHaveBeenCalled();
  });

  it('treats a 404 (CVE_RECORD_DNE) as "nothing to add" — no write, no throw', async () => {
    await seedCveRow({ cveId: 'CVE-2026-00004', textHash: 't', stateHash: 's' });
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('not found', { status: 404 })),
    );

    await expect(
      runMitreCweConsumer({ cveIds: ['CVE-2026-00004'] }, testEnv, createExecutionContext()),
    ).resolves.toBeUndefined();

    const row = await testEnv.DB.prepare('SELECT cwe_id FROM cve_cwe WHERE cve_id = ?')
      .bind('CVE-2026-00004')
      .first();
    expect(row).toBeNull();
  });

  it('treats a REJECTED record state as "nothing to add" — no write, no throw', async () => {
    await seedCveRow({ cveId: 'CVE-2026-00005', textHash: 't', stateHash: 's' });
    vi.stubGlobal(
      'fetch',
      vi.fn(
        async () =>
          new Response(JSON.stringify({ cveMetadata: { state: 'REJECTED' }, containers: {} }), {
            status: 200,
          }),
      ),
    );

    await expect(
      runMitreCweConsumer({ cveIds: ['CVE-2026-00005'] }, testEnv, createExecutionContext()),
    ).resolves.toBeUndefined();

    const row = await testEnv.DB.prepare('SELECT cwe_id FROM cve_cwe WHERE cve_id = ?')
      .bind('CVE-2026-00005')
      .first();
    expect(row).toBeNull();
  });

  it('lets a 500/429 propagate (rejects) so the whole message gets retried by the queue, rather than swallowing the error', async () => {
    await seedCveRow({ cveId: 'CVE-2026-00006', textHash: 't', stateHash: 's' });
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('boom', { status: 500 })),
    );

    await expect(
      runMitreCweConsumer({ cveIds: ['CVE-2026-00006'] }, testEnv, createExecutionContext()),
    ).rejects.toThrow();
  });

  it('processes a full 20-CVE-ID message, bounding concurrency, making at most 20 fetches, and writes only the ones that gained a CWE', async () => {
    const ids = Array.from({ length: 20 }, (_, i) => `CVE-2026-010${String(i).padStart(2, '0')}`);
    for (const id of ids) {
      await seedCveRow({ cveId: id, textHash: `t-${id}`, stateHash: `s-${id}` });
    }

    let inFlight = 0;
    let maxInFlight = 0;
    let fetchCalls = 0;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        fetchCalls++;
        inFlight++;
        maxInFlight = Math.max(maxInFlight, inFlight);
        const url = requestUrl(input);
        const id = url.split('/').pop();
        // Every 3rd id has no recoverable CWE (404); the rest resolve OK.
        const idx = ids.indexOf(id ?? '');
        await Promise.resolve(); // yield once so concurrent calls can overlap
        inFlight--;
        if (idx % 3 === 0) {
          return new Response('not found', { status: 404 });
        }
        return new Response(JSON.stringify(mitreBody(`CWE-${100 + idx} Some Weakness`)), {
          status: 200,
        });
      }),
    );
    const spies = spyOnBindings();

    const ctx = createExecutionContext();
    await runMitreCweConsumer({ cveIds: ids }, testEnv, ctx);
    await waitOnExecutionContext(ctx);

    expect(maxInFlight).toBeLessThanOrEqual(6); // MITRE_FETCH_CONCURRENCY

    // Regression test for "don't repeat the 50-query bug a third time": a
    // 20-ID message makes AT MOST 20 fetches (one per qualifying id, never
    // more) and the D1 operation count — 1 qualifying-check read + 1
    // db.batch() write, regardless of how many of the 20 ids actually
    // gained a CWE — stays in the single digits, nowhere near the
    // 50-query-per-invocation Free-tier cap.
    expect(fetchCalls).toBeLessThanOrEqual(20);
    expect(fetchCalls).toBe(20); // all 20 ids qualify (fresh rows, no existing cve_cwe)
    const totalD1Ops = spies.queryCalls.length + spies.dbBatch.mock.calls.length;
    expect(totalD1Ops).toBeLessThan(10);
    expect(totalD1Ops).toBe(2);

    const rows = await testEnv.DB.prepare(
      `SELECT cve_id FROM cve_cwe WHERE cve_id IN (${ids.map(() => '?').join(',')})`,
    )
      .bind(...ids)
      .all<{ cve_id: string }>();
    const written = new Set(rows.results.map((r) => r.cve_id));
    const expectedWritten = ids.filter((_, i) => i % 3 !== 0);
    expect(written).toEqual(new Set(expectedWritten));
  }, 15_000);
});
