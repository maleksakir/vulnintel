import type { WatchlistMatchStatus } from '@threat-lens/contracts';
import { isAdminAuthorized } from '$lib/server/adminAuth';
import { errorResponse } from '$lib/server/errorResponse';
import { getWatchlistDetail } from '$lib/server/queries/getWatchlists';
import { deleteWatchlist, updateWatchlist } from '$lib/server/queries/watchlistMutations';
import { checkRateLimit } from '$lib/server/quota';
import { validateUpdateWatchlist } from '$lib/server/validate/index';
import type { RequestHandler } from './$types';

const VALID_STATUSES: ReadonlySet<string> = new Set([
  'NEW',
  'TRIAGING',
  'ACKNOWLEDGED',
  'RESOLVED',
  'IGNORED',
]);

function parseId(raw: string | undefined): number | null {
  const id = Number.parseInt(raw ?? '', 10);
  return Number.isInteger(id) && id >= 1 ? id : null;
}

// GET /api/watchlists/[id] — one watchlist: subscriptions + a page of matches
// (optional ?status= filter, cursor-paginated by status_updated_at DESC).
export const GET: RequestHandler = async ({ params, url, platform, locals }) => {
  const env = platform!.env;

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

  const watchlistId = parseId(params.id);
  if (watchlistId === null) {
    return errorResponse('VALIDATION_ERROR', 'Invalid watchlist id.', locals.cfRay, 400);
  }

  const statusParam = url.searchParams.get('status') ?? undefined;
  if (statusParam !== undefined && !VALID_STATUSES.has(statusParam)) {
    return errorResponse('VALIDATION_ERROR', `Invalid status "${statusParam}".`, locals.cfRay, 400);
  }

  const cursor = url.searchParams.get('cursor');
  const data = await getWatchlistDetail(env.DB, watchlistId, {
    ...(statusParam !== undefined && { status: statusParam as WatchlistMatchStatus }),
    ...(cursor !== null && { cursor }),
  });

  if (!data) {
    return errorResponse(
      'WATCHLIST_NOT_FOUND',
      `Watchlist ${watchlistId} not found.`,
      locals.cfRay,
      404,
    );
  }

  return new Response(JSON.stringify(data), {
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
};

// PATCH /api/watchlists/[id] — rename / edit description (admin-gated).
export const PATCH: RequestHandler = async ({ params, request, platform, locals }) => {
  const env = platform!.env;
  if (!isAdminAuthorized(request.headers.get('Authorization'), env.ADMIN_BEARER)) {
    return errorResponse('UNAUTHORIZED', 'Admin bearer token required.', locals.cfRay, 403);
  }

  const watchlistId = parseId(params.id);
  if (watchlistId === null) {
    return errorResponse('VALIDATION_ERROR', 'Invalid watchlist id.', locals.cfRay, 400);
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return errorResponse('VALIDATION_ERROR', 'Body must be valid JSON.', locals.cfRay, 400);
  }

  const v = validateUpdateWatchlist(body);
  if (!v.ok) {
    return errorResponse('VALIDATION_ERROR', 'Invalid update.', locals.cfRay, 400, {
      details: v.details,
    });
  }

  const ok = await updateWatchlist(env.DB, watchlistId, v.value);
  if (!ok) {
    return errorResponse(
      'WATCHLIST_NOT_FOUND',
      `Watchlist ${watchlistId} not found.`,
      locals.cfRay,
      404,
    );
  }
  return new Response(JSON.stringify({ ok: true }), {
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
};

// DELETE /api/watchlists/[id] — delete a watchlist and (CASCADE) its
// subscriptions + matches (admin-gated).
export const DELETE: RequestHandler = async ({ params, request, platform, locals }) => {
  const env = platform!.env;
  if (!isAdminAuthorized(request.headers.get('Authorization'), env.ADMIN_BEARER)) {
    return errorResponse('UNAUTHORIZED', 'Admin bearer token required.', locals.cfRay, 403);
  }

  const watchlistId = parseId(params.id);
  if (watchlistId === null) {
    return errorResponse('VALIDATION_ERROR', 'Invalid watchlist id.', locals.cfRay, 400);
  }

  const ok = await deleteWatchlist(env.DB, watchlistId);
  if (!ok) {
    return errorResponse(
      'WATCHLIST_NOT_FOUND',
      `Watchlist ${watchlistId} not found.`,
      locals.cfRay,
      404,
    );
  }
  return new Response(JSON.stringify({ ok: true }), {
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
};
