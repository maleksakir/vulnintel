import { error } from '@sveltejs/kit';
import type { CveDetailResponse } from '@threat-lens/contracts';
import { getCveDetail } from '$lib/server/queries/getCveDetail';
import { getRiskAcceptance } from '$lib/server/queries/remediation';
import type { PageServerLoad } from './$types';

// Same `cve:<id>` key + 300s TTL as the /api/cve/[id] JSON route, so an SSR
// page view and an API fetch of the same CVE share one cached entry, and the
// ingest worker's existing `cve:<id>` invalidation (processRecord.ts,
// applyKevPatchBatch, applyEpssPatchBatch — all delete this key on a real
// change) covers both. Before this, every /cve/[id] SSR load hit D1 directly
// with no cache and no rate limit — the same uncached-D1-on-an-SSR-path
// read-amplification shape that twice exhausted the 5M/day free-tier read
// quota (homepage, 2026-10-29). CVE detail is a multi-table join per load;
// at any real browse volume that is exactly the quota risk caching exists to
// remove.
//
// A 404 (no such CVE) is deliberately NOT cached — matching the /api route,
// which only writes the KV key after confirming `detail` is non-null. The
// ingest worker's `cve:<id>` invalidation skips brand-new CVEs (`if (cur)` in
// processRecord.ts — nothing to invalidate on a first write), so a cached
// `null` for a not-yet-ingested CVE could otherwise linger up to the full TTL
// after it finally lands. Reads hand-rolled here (not via cacheReadJson) for
// exactly that reason: the helper can't express "cache hits, skip misses".
const TTL = 300;

export const load: PageServerLoad = async ({ params, platform }) => {
  const env = platform?.env;
  const db = env?.DB;
  if (!db) error(503, { message: 'Service unavailable', code: 'INTERNAL_ERROR' });

  const cveId = (params.id ?? '').toUpperCase();
  if (!/^CVE-\d{4}-\d+$/i.test(cveId)) {
    error(400, { message: 'Invalid CVE ID format', code: 'VALIDATION_ERROR' });
  }

  // Risk acceptance is small, mutable, and NOT part of the cached CVE detail,
  // so fetch it directly every load (one indexed single-row read) — in both
  // the cache-hit and cache-miss paths below.
  const riskAcceptance = await getRiskAcceptance(db, cveId);

  const cacheKey = `cve:${cveId}`;
  if (env.CACHE) {
    const cached = await env.CACHE.get<CveDetailResponse>(cacheKey, 'json');
    if (cached !== null) return { detail: cached, riskAcceptance };
  }

  const detail = await getCveDetail(cveId, db);
  if (!detail) {
    error(404, { message: `${cveId} was not found.`, code: 'CVE_NOT_FOUND' });
  }

  if (env.CACHE) {
    platform?.context?.waitUntil(
      env.CACHE.put(cacheKey, JSON.stringify(detail), { expirationTtl: TTL }),
    );
  }

  return { detail, riskAcceptance };
};
