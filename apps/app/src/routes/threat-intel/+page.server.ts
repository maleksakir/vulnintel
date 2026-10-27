import { getEpssList, getKevList } from '$lib/server/queries/getThreatIntel';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ url, platform }) => {
  const db = platform?.env?.DB;
  const tab = url.searchParams.get('tab') === 'epss' ? 'epss' : 'kev';
  const cursor = url.searchParams.get('cursor') ?? undefined;

  if (!db) {
    return { tab, kev: { rows: [], nextCursor: null }, epss: { rows: [], nextCursor: null } };
  }

  if (tab === 'epss') {
    const epss = await getEpssList(db, cursor, 100);
    return { tab, kev: { rows: [], nextCursor: null }, epss };
  }

  const kev = await getKevList(db, cursor, 100);
  return { tab, kev, epss: { rows: [], nextCursor: null } };
};
