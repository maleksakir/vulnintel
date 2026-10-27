import { getAffectedProducts } from '$lib/server/queries/getAffectedProducts';
import { validateAffectedProductsParams } from '$lib/server/validate/index';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ url, platform }) => {
  const db = platform?.env?.DB;
  const validation = validateAffectedProductsParams(url.searchParams);

  if (!db || !validation.ok) {
    return { rows: [], nextCursor: null, vendor: '', product: '' };
  }

  const result = await getAffectedProducts(validation.value, db);
  return {
    ...result,
    vendor: validation.value.vendor ?? '',
    product: validation.value.product ?? '',
  };
};
