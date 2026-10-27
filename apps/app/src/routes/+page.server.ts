import { getMetrics } from '$lib/server/queries/getMetrics';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ platform }) => {
  const db = platform?.env?.DB;
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
  return getMetrics('90d', db);
};
