import { isAdminAuthorized } from '$lib/server/adminAuth';
import { errorResponse } from '$lib/server/errorResponse';
import { removeWebhook } from '$lib/server/queries/watchlistMutations';
import type { RequestHandler } from './$types';

// DELETE /api/watchlists/[id]/webhooks/[webhookId] — remove a webhook (admin-gated).
export const DELETE: RequestHandler = async ({ params, request, platform, locals }) => {
  const env = platform!.env;
  if (!isAdminAuthorized(request.headers.get('Authorization'), env.ADMIN_BEARER)) {
    return errorResponse('UNAUTHORIZED', 'Admin bearer token required.', locals.cfRay, 403);
  }

  const watchlistId = Number.parseInt(params.id ?? '', 10);
  const webhookId = Number.parseInt(params.webhookId ?? '', 10);
  if (
    !Number.isInteger(watchlistId) ||
    watchlistId < 1 ||
    !Number.isInteger(webhookId) ||
    webhookId < 1
  ) {
    return errorResponse('VALIDATION_ERROR', 'Invalid id.', locals.cfRay, 400);
  }

  const ok = await removeWebhook(env.DB, watchlistId, webhookId);
  if (!ok) {
    return errorResponse('WATCHLIST_NOT_FOUND', 'Webhook not found.', locals.cfRay, 404);
  }
  return new Response(JSON.stringify({ ok: true }), {
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
};
