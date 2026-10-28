import { errorResponse } from '$lib/server/errorResponse';
import { getAffectedProducts } from '$lib/server/queries/getAffectedProducts';
import { checkRateLimit } from '$lib/server/quota';
import { validateAffectedProductsParams } from '$lib/server/validate/index';
import type { RequestHandler } from './$types';

export const GET: RequestHandler = async ({ url, platform, locals }) => {
  // No KV cache on this route at all — every request hits D1 directly,
  // unbounded. See quota.ts's checkRateLimit doc.
  const rate = await checkRateLimit(platform!.env.RATE_LIMITER, locals.clientIp);
  if (!rate.allowed) {
    return errorResponse(
      'RATE_LIMITED',
      'Rate limit reached. Try again shortly.',
      locals.cfRay,
      429,
      { retryAfterSeconds: 60 },
    );
  }

  const validation = validateAffectedProductsParams(url.searchParams);
  if (!validation.ok) {
    return errorResponse('VALIDATION_ERROR', 'Invalid query parameters.', locals.cfRay, 400, {
      details: validation.details,
    });
  }

  const data = await getAffectedProducts(validation.value, platform!.env.DB);

  return new Response(JSON.stringify(data), {
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'public, max-age=300',
    },
  });
};
