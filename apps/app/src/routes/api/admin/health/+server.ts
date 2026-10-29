import { timingSafeEqual } from '$lib/server/auth';
import { cacheReadJson } from '$lib/server/cacheRead';
import { errorResponse } from '$lib/server/errorResponse';
import { getAdminHealth } from '$lib/server/queries/getAdminHealth';
import type { RequestHandler } from './$types';

// Same cache key/TTL as admin/health/+page.server.ts — see its comment for
// why this needed caching. Cache-Control stays no-store below (the HTTP
// response itself is never browser/CDN-cached) — this only dedupes the D1
// work server-side across repeated requests within the TTL window.
const HEALTH_TTL = 30;

export const GET: RequestHandler = async ({ request, platform, locals }) => {
  const env = platform!.env;
  const authHeader = request.headers.get('Authorization') ?? '';

  // Fail closed if the secret itself isn't configured (e.g. a staging
  // deploy with no Worker secret set) — see admin/health/+page.server.ts.
  if (!env.ADMIN_BEARER || !timingSafeEqual(authHeader, `Bearer ${env.ADMIN_BEARER}`)) {
    return errorResponse(
      'FORBIDDEN_NETWORK',
      'Invalid or missing bearer token.',
      locals.cfRay,
      403,
    );
  }

  const data = env.CACHE
    ? await cacheReadJson(env.CACHE, 'admin:health', HEALTH_TTL, () =>
        getAdminHealth(env.DB, env.CLOUDFLARE_ACCOUNT_ID, env.CLOUDFLARE_API_TOKEN),
      )
    : await getAdminHealth(env.DB, env.CLOUDFLARE_ACCOUNT_ID, env.CLOUDFLARE_API_TOKEN);

  return new Response(JSON.stringify(data), {
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
    },
  });
};
