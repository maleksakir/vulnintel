import { errorResponse } from '$lib/server/errorResponse';
import { getRiskAcceptances } from '$lib/server/queries/remediation';
import { checkRateLimit } from '$lib/server/quota';
import type { RequestHandler } from './$types';

// GET /api/remediation — all risk acceptances (active + recently expired).
export const GET: RequestHandler = async ({ platform, locals }) => {
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
  const data = await getRiskAcceptances(env.DB);
  return new Response(JSON.stringify(data), {
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
};
