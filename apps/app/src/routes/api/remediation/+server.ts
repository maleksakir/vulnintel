import { isAdminRequest } from '$lib/server/adminSession';
import { errorResponse } from '$lib/server/errorResponse';
import { getRiskAcceptances } from '$lib/server/queries/remediation';
import { checkRateLimit } from '$lib/server/quota';
import { readOrEmpty } from '$lib/server/tableGuard';
import type { RequestHandler } from './$types';

// GET /api/remediation — all risk acceptances (active + recently expired).
//
// Operator-only, and the most sensitive read in the app: this is a list of
// CVEs we have knowingly decided NOT to patch, with the date each decision
// expires. Published openly it's an attack calendar (security review
// 2026-10-31, finding #2).
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
  // cve_risk_acceptance is added by migration 0012; tolerate it being absent
  // (see tableGuard.ts) rather than 500 on a live API.
  const { data } = await readOrEmpty(() => getRiskAcceptances(env.DB), { acceptances: [] });
  return new Response(JSON.stringify(data), {
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
};
