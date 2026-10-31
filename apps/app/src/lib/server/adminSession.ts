import type { Cookies } from '@sveltejs/kit';
import { error, redirect } from '@sveltejs/kit';
import { isAdminAuthorized } from './adminAuth';
import { timingSafeEqual } from './auth';

/**
 * Operator-only READ surface gate.
 *
 * The CVE corpus itself is public data, but the inventory built on top of it
 * is not: an asset list names our own systems, an SBOM names the exact
 * library versions running in them, a watchlist names the vendors we care
 * about, and the risk-acceptance register is a published list of CVEs we have
 * knowingly left unpatched, with expiry dates. Any one of those is a target
 * map. They all shipped read-open while only the mutations were gated
 * (security review 2026-10-31, finding #2) — this module closes that.
 *
 * Two credentials, same secret:
 *  - `Authorization: Bearer <ADMIN_BEARER>` for API clients (scripts, curl).
 *  - an `admin_session` cookie for browser page loads, because an SSR
 *    navigation can't set a header.
 *
 * Both fail CLOSED when ADMIN_BEARER isn't configured — an unset secret must
 * never read as "open" (the empty-cookie-equals-empty-secret trap).
 *
 * STOPGAP, like /admin/health before it: the cookie value *is* the shared
 * secret, and signing in puts that secret in a URL query string once (where
 * CF access logs and browser history can see it) before the redirect strips
 * it. Replace with Cloudflare Access or a real session store when this holds
 * anything beyond single-operator inventory. Tracked in docs/EXECUTION_PLAN.md.
 */
export const ADMIN_SESSION_COOKIE = 'admin_session';

const SESSION_MAX_AGE = 60 * 60; // 1 hour

/** True when the request carries a valid admin session cookie. */
export function hasAdminSession(cookies: Cookies, adminBearer: string | undefined): boolean {
  if (!adminBearer) return false;
  return timingSafeEqual(cookies.get(ADMIN_SESSION_COOKIE) ?? '', adminBearer);
}

/**
 * Path is `/` (not `/admin`) so one sign-in covers every operator surface:
 * /admin/health, /assets, /watchlists, /remediation and the admin view of
 * /cve/[id] all live under different prefixes.
 */
export function setAdminSession(cookies: Cookies, adminBearer: string): void {
  cookies.set(ADMIN_SESSION_COOKIE, adminBearer, {
    path: '/',
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: SESSION_MAX_AGE,
  });
}

/**
 * Page-load gate. Call FIRST in a `load`, before touching D1 — an
 * unauthenticated hit must cost zero queries, or a crawler on /assets is a
 * free-tier read-quota drain as well as a leak.
 *
 * Handles browser sign-in (`?token=<secret>` → cookie → 303 to the same URL
 * without the token) and then reports whether the caller may read. Returns
 * false instead of throwing so pages can render a sign-in prompt rather than
 * a dead-end error page.
 */
export function adminPageGate(
  url: URL,
  cookies: Cookies,
  adminBearer: string | undefined,
): boolean {
  const urlToken = url.searchParams.get('token');
  if (urlToken !== null) {
    if (adminBearer && timingSafeEqual(urlToken, adminBearer)) {
      setAdminSession(cookies, adminBearer);
    }
    // Redirect whether or not the token was valid, so a bad attempt is
    // indistinguishable from a good one in shape, and a valid token never
    // survives in history or a Referer header.
    const stripped = new URL(url);
    stripped.searchParams.delete('token');
    redirect(303, `${stripped.pathname}${stripped.search}`);
  }
  return hasAdminSession(cookies, adminBearer);
}

/**
 * Same gate, but throws a 403 instead of reporting. For detail pages
 * (/assets/[id], /watchlists/[id]) whose whole body is one record — there's
 * nothing to render alongside a sign-in prompt, and they're only ever reached
 * from a list page that already required a session. `?token=` still works
 * here, so a bookmarked detail URL can sign itself in.
 */
export function requireAdminPage(
  url: URL,
  cookies: Cookies,
  adminBearer: string | undefined,
): void {
  if (adminPageGate(url, cookies, adminBearer)) return;
  error(403, {
    message: 'Operator access required. Append ?token=<ADMIN_BEARER> to sign in.',
    code: 'UNAUTHORIZED',
  });
}

/**
 * API gate for operator-only READ routes. Accepts the bearer header or, for a
 * signed-in browser, the session cookie. The cookie is `sameSite: 'strict'`,
 * so a cross-site request never carries it; mutations stay header-only
 * regardless (see isAdminAuthorized callers).
 */
export function isAdminRequest(
  request: Request,
  cookies: Cookies,
  adminBearer: string | undefined,
): boolean {
  if (!adminBearer) return false;
  if (isAdminAuthorized(request.headers.get('Authorization'), adminBearer)) return true;
  return hasAdminSession(cookies, adminBearer);
}
