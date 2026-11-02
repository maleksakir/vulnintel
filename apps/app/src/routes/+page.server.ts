import { cacheReadJson } from '$lib/server/cacheRead';
import { getMetrics } from '$lib/server/queries/getMetrics';
import type { PageServerLoad } from './$types';

// Same cache key/TTL as /api/metrics/90d (src/routes/api/metrics/[window]/+server.ts)
// so the two share one cached entry. getMetrics() runs a COUNT(*) over the full
// `cve` table plus 4 more scans — hitting D1 directly on every homepage SSR
// request (no caching) blew through the 5M/day free-tier read quota in a few
// hours on 2026-10-29 (a handful of pageviews was enough). Must go through KV.
const TTL = 300;

const EMPTY = {
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

export const load: PageServerLoad = async ({ platform }) => {
  const env = platform?.env;
  const db = env?.DB;
  if (!db) return { ...EMPTY, dataError: false };

  // A cache MISS falls through to D1. If D1 is unavailable — most commonly the
  // free-tier daily read cap (error 7500), but any outage counts — a thrown
  // read used to 500 the homepage, the most-visited page in the app. Degrade
  // to the empty state with a flag the page renders as a calm "telemetry
  // offline" banner instead. A cache HIT is unaffected, so the dashboard keeps
  // serving its last good numbers right through a quota exhaustion.
  try {
    const metrics = env.CACHE
      ? await cacheReadJson(env.CACHE, 'dash:metrics:90d', TTL, () => getMetrics('90d', db))
      : await getMetrics('90d', db);
    return { ...metrics, dataError: false };
  } catch {
    return { ...EMPTY, dataError: true };
  }
};
