import { error } from '@sveltejs/kit';
import type { WatchlistMatchStatus } from '@threat-lens/contracts';
import { getWatchlistDetail } from '$lib/server/queries/getWatchlists';
import type { PageServerLoad } from './$types';

const VALID_STATUSES: ReadonlySet<string> = new Set([
  'NEW',
  'TRIAGING',
  'ACKNOWLEDGED',
  'RESOLVED',
  'IGNORED',
]);

export const load: PageServerLoad = async ({ params, url, platform }) => {
  const db = platform?.env?.DB;
  if (!db) error(503, { message: 'Service unavailable', code: 'INTERNAL_ERROR' });

  const watchlistId = Number.parseInt(params.id ?? '', 10);
  if (!Number.isInteger(watchlistId) || watchlistId < 1) {
    error(400, { message: 'Invalid watchlist id', code: 'VALIDATION_ERROR' });
  }

  const statusParam = url.searchParams.get('status') ?? undefined;
  const status =
    statusParam !== undefined && VALID_STATUSES.has(statusParam)
      ? (statusParam as WatchlistMatchStatus)
      : undefined;
  const cursor = url.searchParams.get('cursor') ?? undefined;

  const detail = await getWatchlistDetail(db, watchlistId, {
    ...(status !== undefined && { status }),
    ...(cursor !== undefined && { cursor }),
  });

  if (!detail) {
    error(404, { message: `Watchlist ${watchlistId} was not found.`, code: 'WATCHLIST_NOT_FOUND' });
  }

  return { detail, activeStatus: status ?? null };
};
