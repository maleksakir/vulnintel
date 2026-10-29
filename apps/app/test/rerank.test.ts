import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  fuseRerank,
  RERANK_QUERY_MAX_CHARS,
  rerank,
  rerankWindowSize,
} from '../src/lib/server/rerank';

// `rerank()` must NEVER throw — every test below asserts that on failure it
// resolves to `null` rather than rejecting, so searchCves() can always fall
// back to plain RRF ordering without a try/catch of its own at the call site.

function fakeAi(run: (...args: unknown[]) => unknown): Ai {
  return { run } as unknown as Ai;
}

describe('rerankWindowSize', () => {
  it('floors at 40 for small page sizes', () => {
    expect(rerankWindowSize(10)).toBe(40);
    expect(rerankWindowSize(25)).toBe(40);
  });

  it('tracks the limit between the floor and the cap', () => {
    expect(rerankWindowSize(45)).toBe(45);
  });

  it('caps at 50 even if a larger limit were ever passed', () => {
    expect(rerankWindowSize(50)).toBe(50);
    expect(rerankWindowSize(999)).toBe(50);
  });
});

describe('fuseRerank', () => {
  const K = 60;

  it('boosts reranked entries by RERANK_WEIGHT / (K + rerank_rank)', () => {
    const window: Array<[string, number]> = [
      ['CVE-2026-0001', 0.01],
      ['CVE-2026-0002', 0.01],
    ];
    // Tied RRF scores — the reranker says index 1 ("…0002") is the better match.
    const result = fuseRerank(window, [1, 0], K, 1);

    expect(result[0]?.[0]).toBe('CVE-2026-0002');
    expect(result[0]?.[1]).toBeCloseTo(0.01 + 1 / (K + 1), 10);
    expect(result[1]?.[0]).toBe('CVE-2026-0001');
    expect(result[1]?.[1]).toBeCloseTo(0.01 + 1 / (K + 2), 10);
  });

  it('leaves entries the rerank order omits with no bonus, and sorting stays stable on ties', () => {
    const window: Array<[string, number]> = [
      ['CVE-2026-0001', 0.02],
      ['CVE-2026-0002', 0.02],
      ['CVE-2026-0003', 0.02],
    ];
    // Only index 2 was reranked; 0 and 1 tie at the original RRF score.
    const result = fuseRerank(window, [2], K, 1);

    expect(result[0]?.[0]).toBe('CVE-2026-0003'); // boosted, now highest
    expect(result[0]?.[1]).toBeCloseTo(0.02 + 1 / (K + 1), 10);
    // Original RRF order preserved among the untouched, tied entries — and
    // their scores are left completely unchanged (no bonus applied at all),
    // not just re-sorted into the same positions by coincidence.
    expect(result[1]).toEqual(['CVE-2026-0001', 0.02]);
    expect(result[2]).toEqual(['CVE-2026-0002', 0.02]);
  });

  it('respects the weight constant', () => {
    const window: Array<[string, number]> = [
      ['CVE-2026-0001', 0],
      ['CVE-2026-0002', 0],
    ];
    const zeroWeight = fuseRerank(window, [1, 0], K, 0);
    // With weight 0 the rerank order contributes nothing — original order (a tie) is kept.
    expect(zeroWeight.map(([id]) => id)).toEqual(['CVE-2026-0001', 'CVE-2026-0002']);
  });
});

describe('rerank', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('returns best-first indices derived from score, not response array order', async () => {
    const run = vi.fn().mockResolvedValue({
      response: [
        { id: 0, score: 0.2 },
        { id: 1, score: 0.9 },
        { id: 2, score: 0.5 },
      ],
    });

    const order = await rerank(fakeAi(run), 'remote code execution', ['doc a', 'doc b', 'doc c']);

    expect(order).toEqual([1, 2, 0]);
  });

  it('passes top_k equal to contexts.length and tags the call for attribution', async () => {
    const run = vi.fn().mockResolvedValue({
      response: [
        { id: 0, score: 1 },
        { id: 1, score: 0 },
      ],
    });

    await rerank(fakeAi(run), 'query', ['doc a', 'doc b']);

    expect(run).toHaveBeenCalledTimes(1);
    const [model, input, options] = run.mock.calls[0] as [string, unknown, { tags?: string[] }];
    expect(model).toBe('@cf/baai/bge-reranker-base');
    expect(input).toMatchObject({
      query: 'query',
      contexts: [{ text: 'doc a' }, { text: 'doc b' }],
      top_k: 2,
    });
    expect(options?.tags).toEqual(['search-rerank']);
  });

  it('truncates the query to RERANK_QUERY_MAX_CHARS (defense in depth)', async () => {
    const run = vi.fn().mockResolvedValue({ response: [{ id: 0, score: 1 }] });
    const longQuery = 'x'.repeat(RERANK_QUERY_MAX_CHARS + 50);

    await rerank(fakeAi(run), longQuery, ['doc a']);

    const [, input] = run.mock.calls[0] as [string, { query: string }];
    expect(input.query).toHaveLength(RERANK_QUERY_MAX_CHARS);
  });

  it('returns null, never throws, when the AI call rejects', async () => {
    const run = vi.fn().mockRejectedValue(new Error('3036: quota exhausted'));

    await expect(rerank(fakeAi(run), 'query', ['doc a', 'doc b'])).resolves.toBeNull();
  });

  it('returns null, never throws, when run() throws synchronously', async () => {
    const run = vi.fn().mockImplementation(() => {
      throw new Error('boom');
    });

    await expect(rerank(fakeAi(run), 'query', ['doc a', 'doc b'])).resolves.toBeNull();
  });

  it.each([
    ['response is missing', {}],
    ['response is not an array', { response: 'nope' }],
    ['count does not match what was sent', { response: [{ id: 0, score: 1 }] }],
    [
      'an id is out of range',
      {
        response: [
          { id: 0, score: 1 },
          { id: 5, score: 0.5 },
        ],
      },
    ],
    [
      'ids are duplicated',
      {
        response: [
          { id: 0, score: 1 },
          { id: 0, score: 0.5 },
        ],
      },
    ],
    [
      'a score is missing',
      {
        response: [{ id: 0, score: 1 }, { id: 1 }],
      },
    ],
    [
      'a score is non-finite',
      {
        response: [
          { id: 0, score: 1 },
          { id: 1, score: Number.NaN },
        ],
      },
    ],
  ])('returns null (malformed) when %s', async (_label, malformed) => {
    const run = vi.fn().mockResolvedValue(malformed);

    await expect(rerank(fakeAi(run), 'query', ['doc a', 'doc b'])).resolves.toBeNull();
  });

  it('returns null on timeout and does not reject even though the call never settles', async () => {
    const run = vi.fn().mockImplementation(() => new Promise(() => {})); // never resolves

    const result = await rerank(fakeAi(run), 'query', ['doc a', 'doc b']);

    expect(result).toBeNull();
  }, 5000);
});
