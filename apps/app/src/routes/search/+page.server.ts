import type { Severity } from '@threat-lens/contracts';
import { searchCves } from '$lib/server/queries/searchCves';
import type { PageServerLoad } from './$types';

const VALID_SEVERITIES = new Set<string>(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE']);

// Same cap as the API route's validation (validate/index.ts's 1–256 check for
// `query`) — this route skips that validator entirely and passed `q` straight
// through to embed() uncapped. embed() has its own internal 1,500-char
// truncation, but that's still ~2.3 neurons/search against the account's
// shared 10,000-neurons/day Workers AI pool (same pool apps/ingest draws
// from for embeddings) — combined with this route's rate limiter being
// 500/minute (wrangler.toml), not the 500/hour the spec calls for, a single
// client could exhaust the whole day's budget in minutes, which then
// silently breaks ingest: a failed embed retries into cve-ingest-retry,
// exhausts its retries same-day (no retry_delay configured), lands in the
// DLQ, and the next ingest pass sees an unchanged text_hash and never
// re-attempts the vector. Clamping here, not just trusting embed()'s own
// truncation, keeps the worst case bounded the same way the API route's
// validator already does.
const MAX_QUERY_LENGTH = 256;

export const load: PageServerLoad = async ({ url, platform, locals }) => {
  const q = (url.searchParams.get('q') ?? '').slice(0, MAX_QUERY_LENGTH);
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
