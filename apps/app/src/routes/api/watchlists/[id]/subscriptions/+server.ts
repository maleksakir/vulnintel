import { isAdminAuthorized } from '$lib/server/adminAuth';
import { errorResponse } from '$lib/server/errorResponse';
import { addSubscription, watchlistExists } from '$lib/server/queries/watchlistMutations';
import { validateCreateSubscription } from '$lib/server/validate/index';
import type { RequestHandler } from './$types';

// POST /api/watchlists/[id]/subscriptions — add a vendor/product subscription
// (admin-gated). Backfills matching CVEs immediately so the subscription is
// useful right away, rather than waiting for the next reconciliation run.
export const POST: RequestHandler = async ({ params, request, platform, locals }) => {
  const env = platform!.env;
  if (!isAdminAuthorized(request.headers.get('Authorization'), env.ADMIN_BEARER)) {
    return errorResponse('UNAUTHORIZED', 'Admin bearer token required.', locals.cfRay, 403);
  }

  const watchlistId = Number.parseInt(params.id ?? '', 10);
  if (!Number.isInteger(watchlistId) || watchlistId < 1) {
    return errorResponse('VALIDATION_ERROR', 'Invalid watchlist id.', locals.cfRay, 400);
  }

  if (!(await watchlistExists(env.DB, watchlistId))) {
    return errorResponse(
      'WATCHLIST_NOT_FOUND',
      `Watchlist ${watchlistId} not found.`,
      locals.cfRay,
      404,
    );
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return errorResponse('VALIDATION_ERROR', 'Body must be valid JSON.', locals.cfRay, 400);
  }

  const v = validateCreateSubscription(body);
  if (!v.ok) {
    return errorResponse('VALIDATION_ERROR', 'Invalid subscription.', locals.cfRay, 400, {
      details: v.details,
    });
  }

  const result = await addSubscription(env.DB, watchlistId, v.value.vendor, v.value.product);
  return new Response(JSON.stringify(result), {
    status: 201,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
};
