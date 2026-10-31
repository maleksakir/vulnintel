import { getAssets } from '$lib/server/queries/getAssets';
import type { PageServerLoad } from './$types';

// Asset inventory list. Cheap indexed aggregate reads bounded by the small,
// human-managed asset count — direct D1, no KV cache.
export const load: PageServerLoad = async ({ platform }) => {
  const db = platform?.env?.DB;
  if (!db) return { assets: [] };
  const data = await getAssets(db);
  return { assets: data.assets };
};
