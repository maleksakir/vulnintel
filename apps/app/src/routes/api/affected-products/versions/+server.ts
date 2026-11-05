import { errorResponse } from '$lib/server/errorResponse';
import { getProductVersions } from '$lib/server/queries/getProductVersions';
import { checkRateLimit } from '$lib/server/quota';
import type { RequestHandler } from './$types';

// GET /api/affected-products/versions?vendor=&product= — the vendor→product→
// version drill-down. Both params are required. Rate-limited (a per-product
// CPE scan is a real D1 read), uncached (vendor/product combinations are
// effectively unbounded — same reasoning as the parent affected-products API).

const MAX_LEN = 200;

export const GET: RequestHandler = async ({ url, platform, locals }) => {
  const env = platform?.env;
  if (!env?.DB) {
    return errorResponse('INTERNAL_ERROR', 'Service unavailable.', locals.cfRay, 503);
  }

  const rate = await checkRateLimit(env.RATE_LIMITER, locals.clientIp);
  if (!rate.allowed) {
    return errorResponse(
      'RATE_LIMITED',
      'Rate limit reached. Try again shortly.',
      locals.cfRay,
      429,
      {
        retryAfterSeconds: 60,
      },
    );
  }

  const vendor = url.searchParams.get('vendor')?.trim();
  const product = url.searchParams.get('product')?.trim();
  if (!vendor || !product || vendor.length > MAX_LEN || product.length > MAX_LEN) {
    return errorResponse(
      'VALIDATION_ERROR',
      'Both vendor and product query parameters are required.',
      locals.cfRay,
      400,
    );
  }

  const data = await getProductVersions(env.DB, vendor, product);

  return new Response(JSON.stringify(data), {
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'public, max-age=300',
    },
  });
};
