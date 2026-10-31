import { isAdminAuthorized } from '$lib/server/adminAuth';
import { errorResponse } from '$lib/server/errorResponse';
import { deleteAsset } from '$lib/server/queries/assetMutations';
import { getAssetDetail } from '$lib/server/queries/getAssets';
import { checkRateLimit } from '$lib/server/quota';
import type { RequestHandler } from './$types';

function parseId(raw: string | undefined): number | null {
  const id = Number.parseInt(raw ?? '', 10);
  return Number.isInteger(id) && id >= 1 ? id : null;
}

// GET /api/assets/[id] — components + a page of matched CVEs.
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
  if (!ok) {
    return errorResponse('ASSET_NOT_FOUND', `Asset ${assetId} not found.`, locals.cfRay, 404);
  }
  return new Response(JSON.stringify({ ok: true }), {
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
};
