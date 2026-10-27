import type { RequestHandler } from './$types';
import { getEpssList } from '$lib/server/queries/getThreatIntel';
import { cacheReadJson } from '$lib/server/cacheRead';
import type { EpssListResponse } from '@threat-lens/contracts';

const TTL = 3600;

export const GET: RequestHandler = async ({ url, platform }) => {
  const env = platform!.env;
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
