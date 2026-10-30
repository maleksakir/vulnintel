import type { EpssListResponse, KevListResponse } from '@threat-lens/contracts';
import { cacheReadJson } from '$lib/server/cacheRead';
import { getEpssList, getKevList } from '$lib/server/queries/getThreatIntel';
import type { PageServerLoad } from './$types';

// First-page (no cursor) KEV/EPSS lists share the same KV keys + 3600s TTL as
// the /api/threat-intel/{kev,epss} JSON routes, so an SSR page view and an API
// fetch share one cached entry. The ingest worker invalidates `threat:kev:list`
// on a real KEV change (applyKevPatchBatch); EPSS's `threat:epss:top:200` is
// TTL-only (its leaderboard shifts continuously, so event invalidation isn't
// worthwhile). Before this, every /threat-intel SSR load hit D1 directly with
// no cache — the same uncached-SSR read-amplification shape that twice
// exhausted the 5M/day read quota. Cursor (paginated) loads stay uncached,
// exactly as the API routes do: pagination is rare, bounded, and would
// otherwise multiply distinct KV keys.
const KEV_KEY = 'threat:kev:list';
const EPSS_KEY = 'threat:epss:top:200';
const TTL = 3600;
// Page sizes match each API route's default (KEV 100, EPSS 200) so whichever
// surface populates the SHARED KV key first stores the row count the other
// expects — otherwise an SSR load caching 100 EPSS rows under
// `threat:epss:top:200` would under-fill the key the API route serves at 200.
const KEV_PAGE_SIZE = 100;
const EPSS_PAGE_SIZE = 200;

export const load: PageServerLoad = async ({ url, platform }) => {
  const env = platform?.env;
  const db = env?.DB;
  const tab = url.searchParams.get('tab') === 'epss' ? 'epss' : 'kev';
  const cursor = url.searchParams.get('cursor') ?? undefined;

  if (!db) {
    return { tab, kev: { rows: [], nextCursor: null }, epss: { rows: [], nextCursor: null } };
  }

  const canCache = !cursor && !!env.CACHE;

  if (tab === 'epss') {
    const epss: EpssListResponse = canCache
      ? await cacheReadJson(env.CACHE, EPSS_KEY, TTL, () =>
          getEpssList(db, undefined, EPSS_PAGE_SIZE),
        )
      : await getEpssList(db, cursor, EPSS_PAGE_SIZE);
    return { tab, kev: { rows: [], nextCursor: null }, epss };
  }

  const kev: KevListResponse = canCache
    ? await cacheReadJson(env.CACHE, KEV_KEY, TTL, () => getKevList(db, undefined, KEV_PAGE_SIZE))
    : await getKevList(db, cursor, KEV_PAGE_SIZE);
  return { tab, kev, epss: { rows: [], nextCursor: null } };
};
