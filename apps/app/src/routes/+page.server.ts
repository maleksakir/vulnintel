import { cacheReadJson } from '$lib/server/cacheRead';
import { getMetrics } from '$lib/server/queries/getMetrics';
import type { PageServerLoad } from './$types';

// Same cache key/TTL as /api/metrics/90d (src/routes/api/metrics/[window]/+server.ts)
// so the two share one cached entry. getMetrics() runs a COUNT(*) over the full
// `cve` table plus 4 more scans — hitting D1 directly on every homepage SSR
// request (no caching) blew through the 5M/day free-tier read quota in a few
// hours on 2026-10-29 (a handful of pageviews was enough). Must go through KV.
const TTL = 300;

export const load: PageServerLoad = async ({ platform }) => {
  const env = platform?.env;
  const db = env?.DB;
  if (!db) {
    return {
      kpis: { totalCves: 0, criticalCount: 0, kevCount: 0, meanEpssPercentile7d: 0 },
      series: {
        severityDistribution: [],
        publicationVelocity: [],
        topVendors: [],
        kevInflow: [],
      },
      window: '90d' as const,
      generatedAt: new Date().toISOString(),
    };
  }
  if (!env.CACHE) return getMetrics('90d', db);
  return cacheReadJson(env.CACHE, 'dash:metrics:90d', TTL, () => getMetrics('90d', db));
};
