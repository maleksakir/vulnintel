import type { WatchlistMatchStatus } from '@threat-lens/contracts';
import { isAdminAuthorized } from '$lib/server/adminAuth';
import { errorResponse } from '$lib/server/errorResponse';
import { updateMatch } from '$lib/server/queries/watchlistMutations';
import { isValidCveId, validateUpdateMatch } from '$lib/server/validate/index';
import type { RequestHandler } from './$types';

// PATCH /api/watchlists/[id]/matches/[cveId] — update a matched CVE's triage
// status and/or note (admin-gated).
export const PATCH: RequestHandler = async ({ params, request, platform, locals }) => {
  const env = platform!.env;
  if (!isAdminAuthorized(request.headers.get('Authorization'), env.ADMIN_BEARER)) {
    return errorResponse('UNAUTHORIZED', 'Admin bearer token required.', locals.cfRay, 403);
  }

  const watchlistId = Number.parseInt(params.id ?? '', 10);
  if (!Number.isInteger(watchlistId) || watchlistId < 1) {
    return errorResponse('VALIDATION_ERROR', 'Invalid watchlist id.', locals.cfRay, 400);
  }

  const cveId = (params.cveId ?? '').toUpperCase();
  if (!isValidCveId(cveId)) {
    return errorResponse('VALIDATION_ERROR', 'Invalid CVE id.', locals.cfRay, 400);
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return errorResponse('VALIDATION_ERROR', 'Body must be valid JSON.', locals.cfRay, 400);
  }

  const v = validateUpdateMatch(body);
  if (!v.ok) {
    return errorResponse('VALIDATION_ERROR', 'Invalid update.', locals.cfRay, 400, {
      details: v.details,
    });
  }

  const patch: { status?: WatchlistMatchStatus; note?: string | null } = {};
  if (v.value.status !== undefined) patch.status = v.value.status as WatchlistMatchStatus;
  if (v.value.note !== undefined) patch.note = v.value.note;

  const ok = await updateMatch(env.DB, watchlistId, cveId, patch);
  if (!ok) {
    return errorResponse(
      'WATCHLIST_NOT_FOUND',
      'Match not found on this watchlist.',
      locals.cfRay,
      404,
    );
  }
  return new Response(JSON.stringify({ ok: true }), {
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
};
