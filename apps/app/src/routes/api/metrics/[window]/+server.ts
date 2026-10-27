import type { RequestHandler } from './$types';
import { getMetrics } from '$lib/server/queries/getMetrics';
import { cacheReadJson } from '$lib/server/cacheRead';
import { isValidMetricsWindow } from '$lib/server/validate/index';
import { errorResponse } from '$lib/server/errorResponse';

const TTL = 300;

export const GET: RequestHandler = async ({ params, platform, locals }) => {
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
