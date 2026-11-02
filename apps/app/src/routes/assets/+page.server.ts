import { adminPageGate } from '$lib/server/adminSession';
import { cacheReadJson } from '$lib/server/cacheRead';
import { ASSETS_LIST_CACHE_KEY, ASSETS_LIST_TTL, getAssets } from '$lib/server/queries/getAssets';
import { readOrEmpty } from '$lib/server/tableGuard';
import type { PageServerLoad } from './$types';

// Asset inventory list — operator-only (the list names our own systems).
// The gate runs before any D1 access, so an unauthenticated hit costs zero
// queries; getAssets' second statement is a full aggregate over
// asset_component_match, so it's KV-cached and invalidated by the mutation
// routes (see getAssets.ts).
export const load: PageServerLoad = async ({ url, platform, cookies }) => {
  const env = platform?.env;
  if (!adminPageGate(url, cookies, env?.ADMIN_BEARER)) {
    return { authed: false, assets: [] };
  }

  const db = env?.DB;
  if (!db) return { authed: true, assets: [] };

  // The asset tables are added by migration 0011, which may not be applied
  // yet (see tableGuard.ts) — render an empty inventory rather than 500.
  const { data, schemaReady } = await readOrEmpty(
    () =>
      env?.CACHE
        ? cacheReadJson(env.CACHE, ASSETS_LIST_CACHE_KEY, ASSETS_LIST_TTL, () => getAssets(db))
        : getAssets(db),
    { assets: [] },
  );
  return { authed: true, assets: data.assets, schemaReady };
};
