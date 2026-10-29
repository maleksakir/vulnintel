import { applyD1Migrations, reset } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import { EMBED_MODEL, type SearchRequest } from '@threat-lens/contracts';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { searchCves } from '../src/lib/server/queries/searchCves';
import { RERANK_DAILY_SEARCH_CAP, RERANK_MODEL } from '../src/lib/server/rerank';

// End-to-end coverage for the query-time reranker fused into searchCves()
// (see rerank.ts for the pure-function unit tests). Real local D1 via
// @cloudflare/vitest-plugin for the FTS5/RRF/D1-post-filter path; env.AI and
// env.VECTORIZE are mocked (no local simulator exists for either binding —
// same convention as apps/ingest/test/helpers.ts).
//
// Every scenario here that drives candidates through RRF uses VECTORIZE.query
// (mocked) as the sole ranking signal and a query string ("xenomorphic")
// that matches none of the seeded descriptions, so FTS5/bm25 contributes
// nothing and the resulting RRF order is fully deterministic from the mock
// alone — not dependent on bm25 internals.

const DAY = '2026-10-27';
const CLIENT_IP = '198.51.100.10';

function makePlatform(): App.Platform {
  return {
    env,
    context: { waitUntil: () => {} },
    cf: {},
  } as unknown as App.Platform;
}

async function seedCve(opts: {
  cveId: string;
  description?: string;
  severity?: string;
  cvssBase?: number | null;
  publishedAt?: number;
}): Promise<void> {
  const now = Date.now();
  await env.DB.prepare(
    `INSERT INTO cve
       (cve_id, published_at, last_modified_at, description, cvss_base, severity, source,
        text_hash, state_hash, ingested_at)
     VALUES (?, ?, ?, ?, ?, ?, 'NVD', ?, ?, ?)`,
  )
    .bind(
      opts.cveId,
      opts.publishedAt ?? now,
      opts.publishedAt ?? now,
      opts.description ?? `Seed description for ${opts.cveId}`,
      opts.cvssBase ?? null,
      opts.severity ?? 'HIGH',
      `hash-${opts.cveId}`,
      `hash-${opts.cveId}`,
      now,
    )
    .run();
}

/**
 * Builds a dispatcher for `env.AI.run` that branches on model id, mirroring
 * apps/ingest/test/helpers.ts's per-binding mock approach — extended here to
 * distinguish the embedding model from the reranker model, since a single
 * request can call both. Any call to a third, unexpected model throws.
 */
function aiDispatcher(opts: {
  embed?: () => unknown;
  rerank?: (input: unknown, options: unknown) => unknown;
}) {
  return (model: string, input: unknown, options?: unknown) => {
    if (model === EMBED_MODEL) {
      // Wrapped in Promise.resolve() so a plain success value still exposes
      // `.catch` to rerank.ts's `.run(...).catch(...)` chain — matters for
      // the reranker branch below, kept here too for symmetry. A synchronous
      // throw inside opts.embed() still propagates synchronously, since the
      // call happens while evaluating Promise.resolve()'s argument.
      return Promise.resolve(opts.embed ? opts.embed() : { data: [[0.1, 0.2, 0.3]] });
    }
    if (model === RERANK_MODEL) {
      if (!opts.rerank) {
        throw new Error('unexpected call to the reranker model in this test');
      }
      return Promise.resolve(opts.rerank(input, options));
    }
    throw new Error(`unexpected model passed to env.AI.run: ${model}`);
  };
}

function mockVectorMatches(ids: string[]) {
  return vi.spyOn(env.VECTORIZE, 'query').mockResolvedValue({
    matches: ids.map((id, i) => ({ id, score: 1 - i * 0.01 })),
    count: ids.length,
  } as never);
}

/** How many of env.AI.run's calls were for the reranker model specifically. */
function rerankCallCount(aiRun: ReturnType<typeof vi.spyOn>): number {
  return aiRun.mock.calls.filter(([model]) => model === RERANK_MODEL).length;
}

describe('searchCves — reranking integration', () => {
  beforeEach(async () => {
    await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
    vi.useFakeTimers();
    vi.setSystemTime(new Date(`${DAY}T12:00:00.000Z`));
    vi.spyOn(env.RATE_LIMITER, 'limit').mockResolvedValue({ success: true });
    vi.spyOn(env.VECTORIZE, 'getByIds').mockResolvedValue([]);
  });

  afterEach(async () => {
    vi.useRealTimers();
    vi.restoreAllMocks();
    await reset();
  });

  it('reorders results when the reranker succeeds, and falls back to identical plain-RRF order when it fails', async () => {
    await seedCve({ cveId: 'CVE-2026-10001' });
    await seedCve({ cveId: 'CVE-2026-10002' });
    await seedCve({ cveId: 'CVE-2026-10003' });
    mockVectorMatches(['CVE-2026-10001', 'CVE-2026-10002', 'CVE-2026-10003']);

    const req: SearchRequest = { query: 'xenomorphic', limit: 25 };

    // -- Reranker unavailable: plain RRF order (the vector match order, 1-2-3) --
    vi.spyOn(env.AI, 'run').mockImplementation(
      aiDispatcher({ rerank: () => Promise.reject(new Error('capacity')) }) as never,
    );
    const fallback = await searchCves(req, makePlatform(), CLIENT_IP);
    expect(fallback.quotaError).toBeUndefined();
    expect(fallback.response.results.map((r) => r.cveId)).toEqual([
      'CVE-2026-10001',
      'CVE-2026-10002',
      'CVE-2026-10003',
    ]);

    // -- Reranker succeeds: best-first indices [1,2,0] (doc B, doc C, doc A) --
    // Fused score math (K=60, weight=1): A=1/61+1/63, B=1/62+1/61, C=1/63+1/62
    // → B > A > C, a genuine reordering of the original 1-2-3 RRF order.
    vi.spyOn(env.AI, 'run').mockImplementation(
      aiDispatcher({
        rerank: () => ({
          response: [
            { id: 1, score: 0.9 },
            { id: 2, score: 0.6 },
            { id: 0, score: 0.1 },
          ],
        }),
      }) as never,
    );
    const reranked = await searchCves(req, makePlatform(), CLIENT_IP);
    expect(reranked.response.results.map((r) => r.cveId)).toEqual([
      'CVE-2026-10002',
      'CVE-2026-10001',
      'CVE-2026-10003',
    ]);
  });

  it('never calls the reranker for an exact-CVE-ID query', async () => {
    await seedCve({ cveId: 'CVE-2026-20001' });
    const aiRun = vi.spyOn(env.AI, 'run').mockImplementation(aiDispatcher({}) as never);

    const req: SearchRequest = { query: 'CVE-2026-20001', limit: 25 };
    const result = await searchCves(req, makePlatform(), CLIENT_IP);

    expect(result.response.results.map((r) => r.cveId)).toEqual(['CVE-2026-20001']);
    expect(aiRun).not.toHaveBeenCalled(); // not even embed() runs for the exact-ID shortcut
  });

  it('never calls the reranker for a similarTo-only query', async () => {
    await seedCve({ cveId: 'CVE-2026-20002' });
    await seedCve({ cveId: 'CVE-2026-20003' });
    vi.spyOn(env.VECTORIZE, 'getByIds').mockResolvedValue([
      { id: 'CVE-2026-20002', values: [0.1, 0.2, 0.3] },
    ] as never);
    mockVectorMatches(['CVE-2026-20002', 'CVE-2026-20003']);
    const aiRun = vi.spyOn(env.AI, 'run').mockImplementation(aiDispatcher({}) as never);

    const req: SearchRequest = { similarTo: 'CVE-2026-20002', limit: 25 };
    const result = await searchCves(req, makePlatform(), CLIENT_IP);

    expect(result.response.results.map((r) => r.cveId)).toEqual([
      'CVE-2026-20002',
      'CVE-2026-20003',
    ]);
    expect(aiRun).not.toHaveBeenCalled(); // similarTo never calls embed() or the reranker
  });

  it('never calls the reranker when fewer than 2 candidates survive D1 post-filtering', async () => {
    await seedCve({ cveId: 'CVE-2026-20004' });
    mockVectorMatches(['CVE-2026-20004']);
    const aiRun = vi.spyOn(env.AI, 'run').mockImplementation(aiDispatcher({}) as never);

    const req: SearchRequest = { query: 'xenomorphic', limit: 25 };
    const result = await searchCves(req, makePlatform(), CLIENT_IP);

    expect(result.response.results.map((r) => r.cveId)).toEqual(['CVE-2026-20004']);
    // embed() itself still runs (one call, for EMBED_MODEL) — only the
    // reranker call is gated on there being >=2 candidates.
    expect(rerankCallCount(aiRun)).toBe(0);
  });

  it('skips the reranker once the daily budget gate is tripped, without an extra D1/KV call', async () => {
    await env.DB.prepare('INSERT INTO search_quota_ledger (day, query_count) VALUES (?, ?)')
      .bind(DAY, RERANK_DAILY_SEARCH_CAP)
      .run();
    await seedCve({ cveId: 'CVE-2026-20005' });
    await seedCve({ cveId: 'CVE-2026-20006' });
    mockVectorMatches(['CVE-2026-20005', 'CVE-2026-20006']);
    const aiRun = vi.spyOn(env.AI, 'run').mockImplementation(aiDispatcher({}) as never);
    const dbPrepare = vi.spyOn(env.DB, 'prepare');

    const req: SearchRequest = { query: 'xenomorphic', limit: 25 };
    const result = await searchCves(req, makePlatform(), CLIENT_IP);

    expect(result.quotaError).toBeUndefined(); // org-wide 50k quota is nowhere near tripped
    expect(result.response.results.map((r) => r.cveId)).toEqual([
      'CVE-2026-20005',
      'CVE-2026-20006',
    ]); // plain RRF order — the reranker never ran
    expect(rerankCallCount(aiRun)).toBe(0);
    // checkAndIncrementQuota's own shape (1 SELECT + 1 INSERT) is unchanged —
    // the budget gate reused its existing read, it didn't add a query.
    const quotaSql = dbPrepare.mock.calls
      .map(([sql]) => sql)
      .filter((sql) => /search_quota_ledger/i.test(sql));
    expect(quotaSql).toHaveLength(2);
  });

  it('skips the reranker when the earlier embed() call already failed', async () => {
    await seedCve({
      cveId: 'CVE-2026-20007',
      description: 'A marshmallow-flavored kernel overflow bug.',
    });
    await seedCve({
      cveId: 'CVE-2026-20008',
      description: 'Another marshmallow overflow issue in the driver.',
    });
    const aiRun = vi.spyOn(env.AI, 'run').mockImplementation(
      aiDispatcher({
        embed: () => Promise.reject(new Error('3036: neuron budget exhausted')),
      }) as never,
    );

    // "marshmallow" matches both seeded descriptions via FTS, so filtered.length
    // is 2 (satisfying that gate) even though the vector branch never runs.
    const req: SearchRequest = { query: 'marshmallow', limit: 25 };
    const result = await searchCves(req, makePlatform(), CLIENT_IP);

    expect(result.response.results).toHaveLength(2);
    expect(rerankCallCount(aiRun)).toBe(0);
  });

  describe('never throws out of searchCves(), regardless of what the reranker call does', () => {
    beforeEach(async () => {
      await seedCve({ cveId: 'CVE-2026-30001' });
      await seedCve({ cveId: 'CVE-2026-30002' });
      await seedCve({ cveId: 'CVE-2026-30003' });
      mockVectorMatches(['CVE-2026-30001', 'CVE-2026-30002', 'CVE-2026-30003']);
    });

    it.each([
      ['rejects', () => Promise.reject(new Error('capacity'))],
      [
        'throws synchronously',
        () => {
          throw new Error('boom');
        },
      ],
      ['returns a non-array response', () => ({ response: 'nope' })],
      ['returns a response with the wrong count', () => ({ response: [{ id: 0, score: 1 }] })],
      [
        'returns duplicate ids',
        () => ({
          response: [
            { id: 0, score: 1 },
            { id: 0, score: 0.5 },
            { id: 1, score: 0.2 },
          ],
        }),
      ],
      [
        'returns a non-finite score',
        () => ({
          response: [
            { id: 0, score: 1 },
            { id: 1, score: Number.NaN },
            { id: 2, score: 0.5 },
          ],
        }),
      ],
    ])(
      'resolves with the plain-RRF fallback, not a throw, when the reranker %s',
      async (_label, rerankImpl) => {
        vi.spyOn(env.AI, 'run').mockImplementation(aiDispatcher({ rerank: rerankImpl }) as never);

        const req: SearchRequest = { query: 'xenomorphic', limit: 25 };
        // If searchCves() let an exception escape instead of degrading
        // gracefully, this `await` would reject and fail the test right here.
        const result = await searchCves(req, makePlatform(), CLIENT_IP);

        expect(result.quotaError).toBeUndefined();
        expect(result.response.results.map((r) => r.cveId)).toEqual([
          'CVE-2026-30001',
          'CVE-2026-30002',
          'CVE-2026-30003',
        ]);
      },
    );
  });
});
