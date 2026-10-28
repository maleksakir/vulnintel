import { errorResponse } from '$lib/server/errorResponse';
import { getCveDetail } from '$lib/server/queries/getCveDetail';
import { checkRateLimit } from '$lib/server/quota';
import { isValidCveId } from '$lib/server/validate/index';
import type { RequestHandler } from './$types';

const TTL = 300;

export const GET: RequestHandler = async ({ params, platform, locals }) => {
  const env = platform!.env;

  // CVE IDs are sequentially enumerable, and a cache miss writes a new KV
  // key per distinct ID — unthrottled, this is the same KV-write-storm
  // shape as the 2026-10-27 incident. See quota.ts's checkRateLimit doc.
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

  const cveId = (params.id ?? '').toUpperCase();

  if (!isValidCveId(cveId)) {
    return errorResponse(
      'VALIDATION_ERROR',
      'Invalid CVE ID format. Expected CVE-YYYY-NNNNN.',
      locals.cfRay,
      400,
    );
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
