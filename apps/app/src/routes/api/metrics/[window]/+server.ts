import { cacheReadJson } from '$lib/server/cacheRead';
import { errorResponse } from '$lib/server/errorResponse';
import { getMetrics } from '$lib/server/queries/getMetrics';
import { checkRateLimit } from '$lib/server/quota';
import { isValidMetricsWindow } from '$lib/server/validate/index';
import type { RequestHandler } from './$types';

const TTL = 300;

export const GET: RequestHandler = async ({ params, platform, locals }) => {
  // Cache keys are bounded (5 valid windows) so this isn't the KV-write-
  // storm shape the other routes had, but every public route gets the same
  // baseline throttle for consistency — see quota.ts's checkRateLimit doc.
  const rate = await checkRateLimit(platform!.env.RATE_LIMITER, locals.clientIp);
  if (!rate.allowed) {
    return errorResponse(
      'RATE_LIMITED',
      'Rate limit reached. Try again shortly.',
      locals.cfRay,
      429,
      { retryAfterSeconds: 60 },
    );
  }

  const win = params.window ?? '';
  if (!isValidMetricsWindow(win)) {
    return errorResponse(
      'VALIDATION_ERROR',
      `Invalid window "${win}". Must be one of: 1h, 24h, 7d, 30d, 90d.`,
      locals.cfRay,
      400,
    );
  }

  const env = platform!.env;
  const cacheKey = `dash:metrics:${win}`;

  const data = await cacheReadJson(env.CACHE, cacheKey, TTL, () => getMetrics(win, env.DB));

  return new Response(JSON.stringify(data), {
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': `public, max-age=${TTL}`,
    },
  });
};
