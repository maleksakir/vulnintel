import { isAdminAuthorized } from '$lib/server/adminAuth';
import { isAdminRequest } from '$lib/server/adminSession';
import { errorResponse } from '$lib/server/errorResponse';
import { deleteAsset } from '$lib/server/queries/assetMutations';
import { getAssetDetail, invalidateAssetsList } from '$lib/server/queries/getAssets';
import { checkRateLimit } from '$lib/server/quota';
import type { RequestHandler } from './$types';

function parseId(raw: string | undefined): number | null {
  const id = Number.parseInt(raw ?? '', 10);
  return Number.isInteger(id) && id >= 1 ? id : null;
}

// GET /api/assets/[id] — components + a page of matched CVEs.
// Operator-only: an SBOM is a list of exact library versions we run.
export const GET: RequestHandler = async ({ params, url, request, platform, cookies, locals }) => {
  const env = platform!.env;
  if (!isAdminRequest(request, cookies, env.ADMIN_BEARER)) {
    return errorResponse('UNAUTHORIZED', 'Admin bearer token required.', locals.cfRay, 403);
  }
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

  const assetId = parseId(params.id);
  if (assetId === null) {
    return errorResponse('VALIDATION_ERROR', 'Invalid asset id.', locals.cfRay, 400);
  }

  const cursor = url.searchParams.get('cursor');
  const data = await getAssetDetail(env.DB, assetId, {
    ...(cursor !== null && { cveCursor: cursor }),
  });
  if (!data) {
    return errorResponse('ASSET_NOT_FOUND', `Asset ${assetId} not found.`, locals.cfRay, 404);
  }

  return new Response(JSON.stringify(data), {
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
};

// DELETE /api/assets/[id] — delete an asset + (CASCADE) components + matches.
export const DELETE: RequestHandler = async ({ params, request, platform, locals }) => {
  const env = platform!.env;
  if (!isAdminAuthorized(request.headers.get('Authorization'), env.ADMIN_BEARER)) {
    return errorResponse('UNAUTHORIZED', 'Admin bearer token required.', locals.cfRay, 403);
  }

  const assetId = parseId(params.id);
  if (assetId === null) {
    return errorResponse('VALIDATION_ERROR', 'Invalid asset id.', locals.cfRay, 400);
  }

  const ok = await deleteAsset(env.DB, assetId);
  await invalidateAssetsList(env.CACHE);
  if (!ok) {
    return errorResponse('ASSET_NOT_FOUND', `Asset ${assetId} not found.`, locals.cfRay, 404);
  }
  return new Response(JSON.stringify({ ok: true }), {
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
};
