import type { WatchlistMatchStatus } from '@threat-lens/contracts';
import { errorResponse } from '$lib/server/errorResponse';
import { getWatchlistDetail } from '$lib/server/queries/getWatchlists';
import { checkRateLimit } from '$lib/server/quota';
import type { RequestHandler } from './$types';

const VALID_STATUSES: ReadonlySet<string> = new Set([
  'NEW',
  'TRIAGING',
  'ACKNOWLEDGED',
  'RESOLVED',
  'IGNORED',
]);

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
      {
        retryAfterSeconds: 60,
      },
    );
  }

  const watchlistId = Number.parseInt(params.id ?? '', 10);
  if (!Number.isInteger(watchlistId) || watchlistId < 1) {
    return errorResponse('VALIDATION_ERROR', 'Invalid watchlist id.', locals.cfRay, 400);
  }

  const statusParam = url.searchParams.get('status') ?? undefined;
  if (statusParam !== undefined && !VALID_STATUSES.has(statusParam)) {
    return errorResponse('VALIDATION_ERROR', `Invalid status "${statusParam}".`, locals.cfRay, 400);
  }

  const data = await getWatchlistDetail(env.DB, watchlistId, {
    ...(statusParam !== undefined && { status: statusParam as WatchlistMatchStatus }),
    ...(url.searchParams.get('cursor') !== null && {
      cursor: url.searchParams.get('cursor') as string,
    }),
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
