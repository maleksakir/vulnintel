import type { RequestHandler } from './$types';
import { getAffectedProducts } from '$lib/server/queries/getAffectedProducts';
import { validateAffectedProductsParams } from '$lib/server/validate/index';
import { errorResponse } from '$lib/server/errorResponse';

export const GET: RequestHandler = async ({ url, platform, locals }) => {
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
