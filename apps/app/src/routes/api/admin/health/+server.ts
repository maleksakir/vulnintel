import { timingSafeEqual } from '$lib/server/auth';
import { errorResponse } from '$lib/server/errorResponse';
import { getAdminHealth } from '$lib/server/queries/getAdminHealth';
import type { RequestHandler } from './$types';

export const GET: RequestHandler = async ({ request, platform, locals }) => {
  const env = platform!.env;
  const authHeader = request.headers.get('Authorization') ?? '';

  if (!timingSafeEqual(authHeader, `Bearer ${env.ADMIN_BEARER}`)) {
    return errorResponse(
      'FORBIDDEN_NETWORK',
      'Invalid or missing bearer token.',
      locals.cfRay,
      403,
    );
  }

  const data = await getAdminHealth(env.DB, env.CLOUDFLARE_ACCOUNT_ID, env.CLOUDFLARE_API_TOKEN);

  return new Response(JSON.stringify(data), {
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
    },
  });
};
