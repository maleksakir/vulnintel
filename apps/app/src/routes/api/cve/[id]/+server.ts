import type { RequestHandler } from './$types';
import { getCveDetail } from '$lib/server/queries/getCveDetail';
import { errorResponse } from '$lib/server/errorResponse';
import { isValidCveId } from '$lib/server/validate/index';

const TTL = 300;

export const GET: RequestHandler = async ({ params, platform, locals }) => {
  const env = platform!.env;
  const cveId = (params.id ?? '').toUpperCase();

  if (!isValidCveId(cveId)) {
    return errorResponse('VALIDATION_ERROR', 'Invalid CVE ID format. Expected CVE-YYYY-NNNNN.', locals.cfRay, 400);
  }

  // KV cache read
  const cacheKey = `cve:${cveId}`;
  const cached = await env.CACHE.get(cacheKey, 'json');
  if (cached !== null) {
    return new Response(JSON.stringify(cached), {
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': `public, max-age=${TTL}`,
        'X-Cache': 'HIT',
      },
    });
  }

  const detail = await getCveDetail(cveId, env.DB);

  if (!detail) {
    return errorResponse('CVE_NOT_FOUND', `${cveId} was not found.`, locals.cfRay, 404);
  }

  platform!.context.waitUntil(
    env.CACHE.put(cacheKey, JSON.stringify(detail), { expirationTtl: TTL }),
  );

  return new Response(JSON.stringify(detail), {
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': `public, max-age=${TTL}`,
      'X-Cache': 'MISS',
    },
  });
};
