import { isAdminAuthorized } from '$lib/server/adminAuth';
import { isAdminRequest } from '$lib/server/adminSession';
import { cacheReadJson } from '$lib/server/cacheRead';
import { errorResponse } from '$lib/server/errorResponse';
import { createAsset } from '$lib/server/queries/assetMutations';
import {
  ASSETS_LIST_CACHE_KEY,
  ASSETS_LIST_TTL,
  getAssets,
  invalidateAssetsList,
} from '$lib/server/queries/getAssets';
import { checkRateLimit } from '$lib/server/quota';
import { validateCreateAsset } from '$lib/server/validate/index';
import type { RequestHandler } from './$types';

// GET /api/assets — inventory list with component + vulnerability counts.
// Operator-only: the asset list names our own systems (see adminSession.ts).
export const GET: RequestHandler = async ({ request, platform, cookies, locals }) => {
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
  const data = env.CACHE
    ? await cacheReadJson(env.CACHE, ASSETS_LIST_CACHE_KEY, ASSETS_LIST_TTL, () =>
        getAssets(env.DB),
      )
    : await getAssets(env.DB);
  return new Response(JSON.stringify(data), {
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
};

// POST /api/assets — create an asset (admin-gated).
export const POST: RequestHandler = async ({ request, platform, locals }) => {
  const env = platform!.env;
  if (!isAdminAuthorized(request.headers.get('Authorization'), env.ADMIN_BEARER)) {
    return errorResponse('UNAUTHORIZED', 'Admin bearer token required.', locals.cfRay, 403);
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return errorResponse('VALIDATION_ERROR', 'Body must be valid JSON.', locals.cfRay, 400);
  }

  const v = validateCreateAsset(body);
  if (!v.ok) {
    return errorResponse('VALIDATION_ERROR', 'Invalid asset.', locals.cfRay, 400, {
      details: v.details,
    });
  }

  const assetId = await createAsset(env.DB, v.value.name, v.value.description);
  await invalidateAssetsList(env.CACHE);
  return new Response(JSON.stringify({ assetId }), {
    status: 201,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
};
