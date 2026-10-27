import { redirect } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';
import type { HealthResponse } from '@threat-lens/contracts';
import { getAdminHealth } from '$lib/server/queries/getAdminHealth';
import { timingSafeEqual } from '$lib/server/auth';

const SESSION_COOKIE = 'admin_session';

/**
 * STOPGAP auth, not a real session system — see CLAUDE.md / planned Admin
 * work. A token in the URL query string gets captured by CF access logs,
 * browser history, and any outbound Referer header; a cookie doesn't.
 * This still ships the shared secret itself as the cookie value, which is
 * why it's a stopgap: replace with Cloudflare Access (or a real session
 * store) before this page holds anything more sensitive than read-only
 * health status.
 */
export const load: PageServerLoad = async ({ url, platform, cookies }) => {
  const env = platform?.env;
  if (!env) return { health: null as HealthResponse | null, authed: false };

  const urlToken = url.searchParams.get('token');
  if (urlToken !== null) {
    if (timingSafeEqual(urlToken, env.ADMIN_BEARER)) {
      cookies.set(SESSION_COOKIE, env.ADMIN_BEARER, {
        path: '/admin',
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        maxAge: 60 * 60,
      });
    }
    // Always redirect to strip the token from the URL/history, whether or
    // not it was valid — don't let a bad attempt reveal anything via timing
    // either (redirect happens either way, same shape).
    throw redirect(303, url.pathname);
  }

  const sessionToken = cookies.get(SESSION_COOKIE) ?? '';
  if (!timingSafeEqual(sessionToken, env.ADMIN_BEARER)) {
    return { health: null as HealthResponse | null, authed: false };
  }

  const health = await getAdminHealth(env.DB, env.CLOUDFLARE_ACCOUNT_ID, env.CLOUDFLARE_API_TOKEN);

  return { health, authed: true };
};
