import { redirect } from '@sveltejs/kit';
import type { HealthResponse } from '@threat-lens/contracts';
import { timingSafeEqual } from '$lib/server/auth';
import { cacheReadJson } from '$lib/server/cacheRead';
import { getAdminHealth } from '$lib/server/queries/getAdminHealth';
import type { PageServerLoad } from './$types';

const SESSION_COOKIE = 'admin_session';

// Same cache key/TTL as /api/admin/health (src/routes/api/admin/health/+server.ts)
// so the two share one cached entry. getAdminHealth() runs 5+ unfiltered
// COUNT(*) scans (cve, cpe, cve_state, cve_quarantine, audit_log) — this is
// the page someone checks WHEN something's wrong, so it's also the page most
// likely to get refreshed repeatedly; same uncached-D1-on-every-load shape
// that exhausted the account's daily read quota from the homepage on
// 2026-10-29 (see CLAUDE.md's constraints section). A 30s TTL keeps status
// close to live while bounding the worst case.
const HEALTH_TTL = 30;

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
  // An unset/empty ADMIN_BEARER (e.g. a staging deploy with no secret
  // configured) must fail CLOSED — without this check, an empty session
  // cookie compares equal to an empty secret and every visitor is "authed".
  if (!env || !env.ADMIN_BEARER) return { health: null as HealthResponse | null, authed: false };

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

  const health = env.CACHE
    ? await cacheReadJson(env.CACHE, 'admin:health', HEALTH_TTL, () =>
        getAdminHealth(env.DB, env.CLOUDFLARE_ACCOUNT_ID, env.CLOUDFLARE_API_TOKEN),
      )
    : await getAdminHealth(env.DB, env.CLOUDFLARE_ACCOUNT_ID, env.CLOUDFLARE_API_TOKEN);

  return { health, authed: true };
};
