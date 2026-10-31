import { error } from '@sveltejs/kit';
import { requireAdminPage } from '$lib/server/adminSession';
import { getAssetDetail } from '$lib/server/queries/getAssets';
import type { PageServerLoad } from './$types';

// Operator-only: an asset's component list is our exact dependency inventory
// with versions. Gated before any D1 read.
export const load: PageServerLoad = async ({ params, url, platform, cookies }) => {
  const env = platform?.env;
  requireAdminPage(url, cookies, env?.ADMIN_BEARER);

  const db = env?.DB;
  if (!db) error(503, { message: 'Service unavailable', code: 'INTERNAL_ERROR' });

  const assetId = Number.parseInt(params.id ?? '', 10);
  if (!Number.isInteger(assetId) || assetId < 1) {
    error(400, { message: 'Invalid asset id', code: 'VALIDATION_ERROR' });
  }

  const cursor = url.searchParams.get('cursor') ?? undefined;
  const detail = await getAssetDetail(db, assetId, {
    ...(cursor !== undefined && { cveCursor: cursor }),
  });
  if (!detail) {
    error(404, { message: `Asset ${assetId} was not found.`, code: 'ASSET_NOT_FOUND' });
  }

  return { detail };
};
