import type { PageServerLoad } from './$types';
import type { HealthResponse } from '@threat-lens/contracts';
import { getAdminHealth } from '$lib/server/queries/getAdminHealth';

export const load: PageServerLoad = async ({ url, platform }) => {
  const env = platform?.env;
  const token = url.searchParams.get('token') ?? '';

  if (!env || !token || token !== env.ADMIN_BEARER) {
    return { health: null as HealthResponse | null, authed: false };
  }

  const health = await getAdminHealth(env.DB, env.CLOUDFLARE_ACCOUNT_ID, env.CLOUDFLARE_API_TOKEN);

  return { health, authed: true };
};
