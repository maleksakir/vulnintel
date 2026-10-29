/**
 * Query-time reranking for /search (Phase 2 roadmap item).
 *
 * Reorders a window of already-RRF-ranked, already D1-post-filtered search
 * candidates using @cf/baai/bge-reranker-base, then fuses that order back
 * into the existing RRF score as a third term (see fuseRerank) so exact
 * lexical/CVE-ID matches stay protected — a pure semantic reranker could
 * otherwise de-prioritize them.
 *
 * Workers AI's free allocation (10,000 neurons/day) is account-wide and
 * shared with apps/ingest's embed() calls for every new/changed CVE — see
 * CLAUDE.md. Exceeding it fails ingestion (error 3036/HTTP 429), which
 * cascades into permanently-stale vectors (failed embed → retry queue →
 * exhausted retries → DLQ → next pass sees an unchanged text_hash and never
 * re-attempts). The daily budget gate (RERANK_DAILY_SEARCH_CAP) is enforced
 * by the caller (searchCves.ts) using the pre-increment count quota.ts
 * already reads — this module has no knowledge of the gate itself.
 *
 * Every function here is safe to call speculatively: `rerank()` NEVER
 * throws — any failure (quota-exhausted, capacity, timeout, network error,
 * malformed output) resolves to `null` and the caller continues with plain
 * RRF ordering exactly as before this feature existed.
 */

/** Workers AI model id for the reranker. */
export const RERANK_MODEL = '@cf/baai/bge-reranker-base' as const;

/** Account-wide daily cap on reranked searches (see CLAUDE.md neuron budget). */
export const RERANK_DAILY_SEARCH_CAP = 1000;

/**
 * Client-side timeout for the reranker call. The Workers AI binding doesn't
 * documented-ly honor `signal` reliably server-side, so this timer race
 * (not just the `signal` passed alongside it) is the real enforcement.
 */
export const RERANK_TIMEOUT_MS = 800;

/** Defense in depth — the SSR /search route already clamps `q` to this length. */
export const RERANK_QUERY_MAX_CHARS = 256;

/** Max length of each candidate's document text sent to the reranker. */
export const RERANK_DOC_MAX_CHARS = 512;

/** Weight of the rerank term in the fused score: rrf_score + RERANK_WEIGHT / (K + rerank_rank). */
export const RERANK_WEIGHT = 1;

const RERANK_WINDOW_FLOOR = 40;
const RERANK_WINDOW_CAP = 50;

/**
 * Number of top RRF candidates to send to the reranker for a given page
 * size: Math.max(limit, 40), capped at 50 — a caller asking for the max
 * 50-result page still gets the whole page reranked.
 */
export function rerankWindowSize(limit: number): number {
  return Math.min(Math.max(limit, RERANK_WINDOW_FLOOR), RERANK_WINDOW_CAP);
}

export type RerankOutcome = 'ok' | 'timeout' | 'error' | 'malformed' | 'budget-skip';

/**
 * Structured one-line log per rerank attempt (Workers Logs is already
 * enabled). Deliberately excludes raw query/document text.
 */
export function logRerankAttempt(
  outcome: RerankOutcome,
  latencyMs: number,
  windowSize: number,
): void {
  console.log(JSON.stringify({ event: 'search-rerank', outcome, latencyMs, windowSize }));
}

/**
 * Local, narrow typing of the Workers AI binding for this one model — same
 * workaround as embed.ts uses for its model. @cloudflare/workers-types
 * @4.20260521.1's `Ai_Cf_Baai_Bge_Reranker_Base_Input` is missing the
 * documented `query` property (the doc comment is present, the field
 * itself isn't), so a directly-typed `env.AI.run('@cf/baai/bge-reranker-base',
 * { query, ... })` call fails `tsc` with an excess-property error. This
 * type reflects the real, documented API contract instead of the installed
 * (buggy) one — batched call, not pairwise: one `query` string against many
 * `contexts`, response items carry an index back into `contexts` plus a
 * score whose scale (logit vs. sigmoid-mapped probability) isn't clearly
 * documented, which is why `rerank()` below uses relative rank, not the
 * raw score, for fusion.
 */
type RerankAiLike = {
  run: (
    model: string,
    input: { query: string; contexts: { text: string }[]; top_k: number },
    options?: { signal?: AbortSignal; tags?: string[] },
  ) => Promise<RerankRawOutput>;
};

type RerankRawOutput = {
  response?: ReadonlyArray<{ id?: number; score?: number }>;
};

/**
 * Validates a raw reranker response and converts it into best-first
 * indices into the original `docs` array, using RANKS (not raw scores) for
 * ordering. Returns null on any shape mismatch: not an array, count
 * mismatch, an out-of-range or duplicate id, or a non-finite score —
 * exactly the runtime validation the installed types can't give us for
 * free, since every field in the response is optional.
 */
function validateAndRank(raw: RerankRawOutput, expectedCount: number): number[] | null {
  const response = raw?.response;
  if (!Array.isArray(response)) return null;
  if (response.length !== expectedCount) return null;

  const seen = new Set<number>();
  for (const entry of response) {
    const id = entry?.id;
    const score = entry?.score;
    if (typeof id !== 'number' || !Number.isInteger(id) || id < 0 || id >= expectedCount) {
      return null;
    }
    if (seen.has(id)) return null;
    seen.add(id);
    if (typeof score !== 'number' || !Number.isFinite(score)) return null;
  }

  return [...response]
    .sort((a, b) => (b.score as number) - (a.score as number))
    .map((entry) => entry.id as number);
}

/**
 * Reranks `docs` against `query`, returning best-first indices into `docs`
 * on success, or `null` on ANY failure — quota-exhausted (3036), capacity
 * (3040), timeout (3007 or the local timer), a thrown/rejected call, or a
 * response that fails runtime validation. Never throws.
 *
 * Budget/skip decisions (daily cap, no query text, exact-CVE-ID shortcut,
 * nothing to reorder, an already-failed embed() in the same request) are
 * the caller's responsibility — see searchCves.ts — so this function always
 * attempts the call when invoked.
 */
export async function rerank(ai: Ai, query: string, docs: string[]): Promise<number[] | null> {
  const windowSize = docs.length;
  const start = Date.now();

  try {
    const truncatedQuery = query.slice(0, RERANK_QUERY_MAX_CHARS);
    const contexts = docs.map((text) => ({ text }));
    const controller = new AbortController();

    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<'timeout'>((resolve) => {
      timer = setTimeout(() => {
        controller.abort();
        resolve('timeout');
      }, RERANK_TIMEOUT_MS);
    });

    // `.catch` is attached here, not after the race, so the abandoned call
    // never produces an unhandled rejection if it settles after a timeout
    // has already won the race below.
    const call: Promise<RerankRawOutput | 'error'> = (ai as RerankAiLike)
      .run(
        RERANK_MODEL,
        { query: truncatedQuery, contexts, top_k: docs.length },
        { signal: controller.signal, tags: ['search-rerank'] },
      )
      .catch((): 'error' => 'error');

    const result = await Promise.race([call, timeout]);
    if (timer) clearTimeout(timer);

    if (result === 'timeout') {
      logRerankAttempt('timeout', Date.now() - start, windowSize);
      return null;
    }
    if (result === 'error') {
      logRerankAttempt('error', Date.now() - start, windowSize);
      return null;
    }

    const order = validateAndRank(result, docs.length);
    if (!order) {
      logRerankAttempt('malformed', Date.now() - start, windowSize);
      return null;
    }

    logRerankAttempt('ok', Date.now() - start, windowSize);
    return order;
  } catch {
    logRerankAttempt('error', Date.now() - start, windowSize);
    return null;
  }
}

/**
 * Fuses a rerank order back into existing RRF scores as a third RRF-style
 * term. `window` is a list of [cveId, rrfScore] pairs in their original RRF
 * order; `rerankOrder` is best-first indices into `window` (exactly what
 * `rerank()` returns). Returns the window re-sorted by the fused score —
 * entries outside the rerank order (shouldn't normally happen; defensive)
 * and ties keep their original RRF relative order via a stable sort.
 *
 * Pure, no I/O — kept separate from `rerank()` so the fusion math is
 * trivial to unit test without a Workers AI binding.
 */
export function fuseRerank(
  window: ReadonlyArray<readonly [string, number]>,
  rerankOrder: ReadonlyArray<number>,
  K: number,
  weight: number,
): Array<[string, number]> {
  const rerankRankByIndex = new Map<number, number>();
  rerankOrder.forEach((windowIdx, i) => {
    rerankRankByIndex.set(windowIdx, i + 1);
  });

  const fused: Array<[string, number]> = window.map(([id, rrfScore], idx) => {
    const rerankRank = rerankRankByIndex.get(idx);
    const bonus = rerankRank !== undefined ? weight / (K + rerankRank) : 0;
    return [id, rrfScore + bonus];
  });

  // Array.prototype.sort is stable (ES2019+, true in workerd/V8) — ties
  // (equal fused scores) keep their original RRF relative order.
  return fused.sort((a, b) => b[1] - a[1]);
}
