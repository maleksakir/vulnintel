import type { EpssListResponse } from '@threat-lens/contracts';
import { cacheReadJson } from '$lib/server/cacheRead';
import { errorResponse } from '$lib/server/errorResponse';
import { getEpssList } from '$lib/server/queries/getThreatIntel';
import { checkRateLimit } from '$lib/server/quota';
import type { RequestHandler } from './$types';

const TTL = 3600;

export const GET: RequestHandler = async ({ url, platform, locals }) => {
  const env = platform!.env;

  // Paginated (cursor-bearing) requests bypass the KV cache entirely and
  // hit D1 directly, unbounded — see quota.ts's checkRateLimit doc.
  const rate = await checkRateLimit(env.RATE_LIMITER, locals.clientIp);
  if (!rate.allowed) {
    return errorResponse(
      'RATE_LIMITED',
      'Rate limit reached. Try again shortly.',
      locals.cfRay,
      429,
      { retryAfterSeconds: 60 },
    );
  }

  const cursor = url.searchParams.get('cursor') ?? undefined;
  const limit = Math.min(parseInt(url.searchParams.get('limit') ?? '200', 10), 200);

  const cacheKey = cursor ? null : 'threat:epss:top:200';

  const data: EpssListResponse = cacheKey
    ? await cacheReadJson(env.CACHE, cacheKey, TTL, () => getEpssList(env.DB, cursor, limit))
    : await getEpssList(env.DB, cursor, limit);

  return new Response(JSON.stringify(data), {
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': `public, max-age=${TTL}`,
    },
  });
};
