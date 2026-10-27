import type { PageServerLoad } from './$types';
import { getCveDetail } from '$lib/server/queries/getCveDetail';
import { error } from '@sveltejs/kit';

export const load: PageServerLoad = async ({ params, platform }) => {
  const db = platform?.env?.DB;
  if (!db) error(503, { message: 'Service unavailable', code: 'INTERNAL_ERROR' });

  const cveId = (params.id ?? '').toUpperCase();
  if (!/^CVE-\d{4}-\d+$/i.test(cveId)) {
    error(400, { message: 'Invalid CVE ID format', code: 'VALIDATION_ERROR' });
  }

  const detail = await getCveDetail(cveId, db);
  if (!detail) {
    error(404, { message: `${cveId} was not found.`, code: 'CVE_NOT_FOUND' });
  }

  return { detail };
};
