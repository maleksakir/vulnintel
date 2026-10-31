import { errorResponse } from '$lib/server/errorResponse';
import { getWatchlists } from '$lib/server/queries/getWatchlists';
import { checkRateLimit } from '$lib/server/quota';
import type { RequestHandler } from './$types';

// GET /api/watchlists — list all watchlists with subscription + per-status
// match counts. Cheap indexed aggregate reads (bounded by the small,
// human-managed watchlist count). No KV cache: the list changes whenever a
// reconciliation run adds matches or an admin edits a watchlist, and the
// payload is small; the per-IP throttle is the cost guard.
export const GET: RequestHandler = async ({ platform, locals }) => {
  const env = platform!.env;

  const rate = await checkRateLimit(env.RATE_LIMITER, locals.clientIp);
  if (!rate.allowed) {
    return errorResponse(
      'RATE_LIMITED',
      'Rate limit reached. Try again shortly.',
      locals.cfRay,
      429,
      {
        retryAfterSeconds: 60,
      },
    );
  }

  const data = await getWatchlists(env.DB);
  return new Response(JSON.stringify(data), {
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
};
