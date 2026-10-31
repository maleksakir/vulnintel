import { isAdminAuthorized } from '$lib/server/adminAuth';
import { errorResponse } from '$lib/server/errorResponse';
import { removeSubscription } from '$lib/server/queries/watchlistMutations';
import type { RequestHandler } from './$types';

// DELETE /api/watchlists/[id]/subscriptions/[subId] — remove a subscription
// (admin-gated). Already-materialized matches are left in place (triage
// history shouldn't vanish because a subscription was dropped).
export const DELETE: RequestHandler = async ({ params, request, platform, locals }) => {
  const env = platform!.env;
  if (!isAdminAuthorized(request.headers.get('Authorization'), env.ADMIN_BEARER)) {
    return errorResponse('UNAUTHORIZED', 'Admin bearer token required.', locals.cfRay, 403);
  }

  const watchlistId = Number.parseInt(params.id ?? '', 10);
  const subscriptionId = Number.parseInt(params.subId ?? '', 10);
  if (
    !Number.isInteger(watchlistId) ||
    watchlistId < 1 ||
    !Number.isInteger(subscriptionId) ||
    subscriptionId < 1
  ) {
    return errorResponse('VALIDATION_ERROR', 'Invalid id.', locals.cfRay, 400);
  }

  const ok = await removeSubscription(env.DB, watchlistId, subscriptionId);
  if (!ok) {
    return errorResponse('WATCHLIST_NOT_FOUND', 'Subscription not found.', locals.cfRay, 404);
  }
  return new Response(JSON.stringify({ ok: true }), {
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
};
