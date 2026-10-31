import { adminPageGate } from '$lib/server/adminSession';
import { getWatchlists } from '$lib/server/queries/getWatchlists';
import type { PageServerLoad } from './$types';

// Watchlists list — operator-only: the set of vendors/products we monitor
// describes our own stack. Gated before any D1 read.
//
// getWatchlists is cheap indexed aggregate reads bounded by the small,
// human-managed watchlist count (not match volume), so it runs directly
// against D1 — no KV cache, since the list changes whenever a reconciliation
// run adds matches and the payload is tiny.
export const load: PageServerLoad = async ({ url, platform, cookies }) => {
  const env = platform?.env;
  if (!adminPageGate(url, cookies, env?.ADMIN_BEARER)) {
    return { authed: false, watchlists: [] };
  }

  const db = env?.DB;
  if (!db) return { authed: true, watchlists: [] };
  const data = await getWatchlists(db);
  return { authed: true, watchlists: data.watchlists };
};
