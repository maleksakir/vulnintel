import type { AffectedProductsResponse, AffectedVersionsResponse } from '@threat-lens/contracts';
import { cacheReadJson } from '$lib/server/cacheRead';
import { getAffectedProducts } from '$lib/server/queries/getAffectedProducts';
import { getProductVersions } from '$lib/server/queries/getProductVersions';
import { validateAffectedProductsParams } from '$lib/server/validate/index';
import type { PageServerLoad } from './$types';

// getAffectedProducts is the heaviest read in the app: a GROUP BY join across
// the full cpe × cve tables. Every /affected-products SSR load previously ran
// it directly against D1 with no cache — the same uncached-SSR read-
// amplification shape that twice exhausted the 5M/day free-tier read quota.
//
// Only the UNFILTERED default view (no vendor/product/minCvss/cursor, default
// limit) is cached, under one stable key. Filtered/paginated queries carry
// user-controlled, effectively-unbounded param combinations, so caching them
// would mint a distinct KV key per combination — the KV-write-storm shape the
// cve:<id> routes were hardened against. Those go straight to D1, bounded by
// the edge WAF/rate-limit layer. The default landing view is both the most
// repeated SSR hit and the most expensive query, so this single key removes
// the bulk of the risk at one KV read per load. No event invalidation: the
// product matrix shifts slowly and a 300s TTL is plenty fresh (same TTL the
// /api route advertises via Cache-Control).
const DEFAULT_VIEW_KEY = 'affected:products:default';
const TTL = 300;

export const load: PageServerLoad = async ({ url, platform }) => {
  const env = platform?.env;
  const db = env?.DB;
  const validation = validateAffectedProductsParams(url.searchParams);

  if (!db || !validation.ok) {
    return {
      rows: [],
      nextCursor: null,
      vendor: '',
      product: '',
      versions: null,
      dataError: false,
    };
  }

  const { vendor, product, minCvss, cursor } = validation.value;
  const isDefaultView =
    vendor === undefined && product === undefined && minCvss === undefined && cursor === undefined;
  // Drill-down mode: a specific vendor AND product are selected → also load
  // the version-level breakdown for that product.
  const drillDown = vendor !== undefined && product !== undefined;

  // Degrade to empty + a flag if D1 is unavailable on a cache miss (free-tier
  // read cap / outage), rather than 500ing the page.
  try {
    const result: AffectedProductsResponse =
      isDefaultView && env.CACHE
        ? await cacheReadJson(env.CACHE, DEFAULT_VIEW_KEY, TTL, () =>
            getAffectedProducts(validation.value, db),
          )
        : await getAffectedProducts(validation.value, db);

    let versions: AffectedVersionsResponse | null = null;
    if (drillDown && vendor && product) {
      versions = await getProductVersions(db, vendor, product);
    }

    return { ...result, vendor: vendor ?? '', product: product ?? '', versions, dataError: false };
  } catch {
    return {
      rows: [],
      nextCursor: null,
      vendor: vendor ?? '',
      product: product ?? '',
      versions: null,
      dataError: true,
    };
  }
};
