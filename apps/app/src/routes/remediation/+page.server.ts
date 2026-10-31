import { getRiskAcceptances } from '$lib/server/queries/remediation';
import type { PageServerLoad } from './$types';

// Remediation overview — all risk acceptances (active + recently expired).
// Small human-managed set; direct D1 read, no KV cache.
export const load: PageServerLoad = async ({ platform }) => {
  const db = platform?.env?.DB;
  if (!db) return { acceptances: [] };
  const data = await getRiskAcceptances(db);
  return { acceptances: data.acceptances };
};
