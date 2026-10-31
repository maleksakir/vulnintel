import { getWatchlists } from '$lib/server/queries/getWatchlists';
import type { PageServerLoad } from './$types';

// Watchlists list. getWatchlists is cheap indexed aggregate reads bounded by
// the small, human-managed watchlist count (not match volume), so it runs
// directly against D1 — no KV cache, since the list changes whenever a
// reconciliation run adds matches and the payload is tiny.
export const load: PageServerLoad = async ({ platform }) => {
  const db = platform?.env?.DB;
  if (!db) return { watchlists: [] };
  const data = await getWatchlists(db);
  return { watchlists: data.watchlists };
};
