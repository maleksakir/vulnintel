import { isAdminAuthorized } from '$lib/server/adminAuth';
import { errorResponse } from '$lib/server/errorResponse';
import { revokeRiskAcceptance, upsertRiskAcceptance } from '$lib/server/queries/remediation';
import { isValidCveId, validateAcceptRisk } from '$lib/server/validate/index';
import type { RequestHandler } from './$types';

// PUT /api/remediation/[cveId] — create or extend a CVE's risk acceptance
// (admin-gated). Expiry is mandatory and must be in the future.
export const PUT: RequestHandler = async ({ params, request, platform, locals }) => {
  const env = platform!.env;
  if (!isAdminAuthorized(request.headers.get('Authorization'), env.ADMIN_BEARER)) {
    return errorResponse('UNAUTHORIZED', 'Admin bearer token required.', locals.cfRay, 403);
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

  const v = validateAcceptRisk(body);
  if (!v.ok) {
    return errorResponse('VALIDATION_ERROR', 'Invalid risk acceptance.', locals.cfRay, 400, {
      details: v.details,
    });
  }

  await upsertRiskAcceptance(
    env.DB,
    cveId,
    v.value.justification,
    v.value.expiresAtMs,
    v.value.acceptedBy,
  );
  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
};

// DELETE /api/remediation/[cveId] — revoke an acceptance (re-activate now).
export const DELETE: RequestHandler = async ({ params, request, platform, locals }) => {
  const env = platform!.env;
  if (!isAdminAuthorized(request.headers.get('Authorization'), env.ADMIN_BEARER)) {
    return errorResponse('UNAUTHORIZED', 'Admin bearer token required.', locals.cfRay, 403);
  }

  const cveId = (params.cveId ?? '').toUpperCase();
  if (!isValidCveId(cveId)) {
    return errorResponse('VALIDATION_ERROR', 'Invalid CVE id.', locals.cfRay, 400);
  }

  const ok = await revokeRiskAcceptance(env.DB, cveId);
  if (!ok) {
    return errorResponse('CVE_NOT_FOUND', 'No acceptance for that CVE.', locals.cfRay, 404);
  }
  return new Response(JSON.stringify({ ok: true }), {
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
};
