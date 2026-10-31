import { timingSafeEqual } from './auth';

/**
 * Shared admin-bearer gate for mutation API routes (watchlist create/edit,
 * subscription + triage changes). Same contract as /api/admin/health:
 * requires `Authorization: Bearer <ADMIN_BEARER>`, constant-time compared,
 * and FAILS CLOSED when the secret isn't configured (e.g. a staging deploy
 * with no Worker secret) — an unset secret must never mean "open".
 *
 * Returns true if authorized. Callers return a 403 UNAUTHORIZED envelope on
 * false.
 */
export function isAdminAuthorized(
  authHeader: string | null,
  adminBearer: string | undefined,
): boolean {
  if (!adminBearer) return false;
  return timingSafeEqual(authHeader ?? '', `Bearer ${adminBearer}`);
}
