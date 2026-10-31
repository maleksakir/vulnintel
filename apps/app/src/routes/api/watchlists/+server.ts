import { isAdminAuthorized } from '$lib/server/adminAuth';
import { isAdminRequest } from '$lib/server/adminSession';
import { errorResponse } from '$lib/server/errorResponse';
import { getWatchlists } from '$lib/server/queries/getWatchlists';
import { createWatchlist } from '$lib/server/queries/watchlistMutations';
import { checkRateLimit } from '$lib/server/quota';
import { validateCreateWatchlist } from '$lib/server/validate/index';
import type { RequestHandler } from './$types';

// GET /api/watchlists — list all watchlists with subscription + per-status
// match counts. Cheap indexed aggregate reads (bounded by the small,
// human-managed watchlist count). No KV cache: the list changes whenever a
// reconciliation run adds matches or an admin edits a watchlist, and the
// payload is small; the per-IP throttle is the cost guard.
// Operator-only (see $lib/server/adminSession.ts): which vendors we watch is
// a map of what we run.
export const GET: RequestHandler = async ({ request, platform, cookies, locals }) => {
  const env = platform!.env;

  if (!isAdminRequest(request, cookies, env.ADMIN_BEARER)) {
    return errorResponse('UNAUTHORIZED', 'Admin bearer token required.', locals.cfRay, 403);
  }

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

  const data = await getWatchlists(env.DB);
  return new Response(JSON.stringify(data), {
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
};

// POST /api/watchlists — create a watchlist (admin-gated).
export const POST: RequestHandler = async ({ request, platform, locals }) => {
  const env = platform!.env;

  if (!isAdminAuthorized(request.headers.get('Authorization'), env.ADMIN_BEARER)) {
    return errorResponse('UNAUTHORIZED', 'Admin bearer token required.', locals.cfRay, 403);
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return errorResponse('VALIDATION_ERROR', 'Body must be valid JSON.', locals.cfRay, 400);
  }

  const v = validateCreateWatchlist(body);
  if (!v.ok) {
    return errorResponse('VALIDATION_ERROR', 'Invalid watchlist.', locals.cfRay, 400, {
      details: v.details,
    });
  }

  const watchlistId = await createWatchlist(env.DB, v.value.name, v.value.description);
  return new Response(JSON.stringify({ watchlistId }), {
    status: 201,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
};
