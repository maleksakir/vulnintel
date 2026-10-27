import type { KevListResponse } from '@threat-lens/contracts';
import { cacheReadJson } from '$lib/server/cacheRead';
import { getKevList } from '$lib/server/queries/getThreatIntel';
import type { RequestHandler } from './$types';

const TTL = 3600;

export const GET: RequestHandler = async ({ url, platform }) => {
  const env = platform!.env;
  const cursor = url.searchParams.get('cursor') ?? undefined;
  const limit = Math.min(parseInt(url.searchParams.get('limit') ?? '100', 10), 200);

  // Only cache the first page (no cursor) at the well-known key.
  const cacheKey = cursor ? null : 'threat:kev:list';

  const data: KevListResponse = cacheKey
    ? await cacheReadJson(env.CACHE, cacheKey, TTL, () => getKevList(env.DB, cursor, limit))
    : await getKevList(env.DB, cursor, limit);

  return new Response(JSON.stringify(data), {
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': `public, max-age=${TTL}`,
    },
  });
};
