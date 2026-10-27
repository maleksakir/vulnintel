import type { Severity } from '@threat-lens/contracts';
import { searchCves } from '$lib/server/queries/searchCves';
import type { PageServerLoad } from './$types';

const VALID_SEVERITIES = new Set<string>(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE']);

export const load: PageServerLoad = async ({ url, platform, locals }) => {
  const q = url.searchParams.get('q') ?? '';
  const kev = url.searchParams.get('kev') === 'true' ? true : undefined;
  const minCvssParam = url.searchParams.get('minCvss');
  const minCvss = minCvssParam !== null && minCvssParam !== '' ? Number(minCvssParam) : undefined;

  // Checkboxes submit multiple params with the same name
  const severity = url.searchParams
    .getAll('severity')
    .filter((s: string): s is Severity => VALID_SEVERITIES.has(s));

  // Return filter state so the UI can restore checkbox/input values on page load
  const filters = {
    ...(severity.length > 0 && { severity }),
    ...(kev !== undefined && { kev }),
    ...(minCvss !== undefined && { minCvss }),
  };

  if (!q.trim()) {
    return { query: q, results: [], truncated: false, quotaError: null, filters };
  }

  const { response, quotaError } = await searchCves(
    { query: q, filters, limit: 25 },
    platform!,
    locals.clientIp,
  );

  return { query: q, ...response, quotaError: quotaError ?? null, filters };
};
