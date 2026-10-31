import { isAdminAuthorized } from '$lib/server/adminAuth';
import { errorResponse } from '$lib/server/errorResponse';
import { assetExists, importSbom } from '$lib/server/queries/assetMutations';
import { parseCycloneDxSbom } from '$lib/server/sbom';
import type { RequestHandler } from './$types';

// POST /api/assets/[id]/import — upload a CycloneDX SBOM (admin-gated). Parses
// components, replaces the asset's component set, and re-matches each
// component to CVEs (PURL-first against cve_osv_affected, CPE fallback against
// cpe). Reuses already-ingested data — no external fetch.
export const POST: RequestHandler = async ({ params, request, platform, locals }) => {
  const env = platform!.env;
  if (!isAdminAuthorized(request.headers.get('Authorization'), env.ADMIN_BEARER)) {
    return errorResponse('UNAUTHORIZED', 'Admin bearer token required.', locals.cfRay, 403);
  }

  const assetId = Number.parseInt(params.id ?? '', 10);
  if (!Number.isInteger(assetId) || assetId < 1) {
    return errorResponse('VALIDATION_ERROR', 'Invalid asset id.', locals.cfRay, 400);
  }
  if (!(await assetExists(env.DB, assetId))) {
    return errorResponse('ASSET_NOT_FOUND', `Asset ${assetId} not found.`, locals.cfRay, 404);
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return errorResponse('VALIDATION_ERROR', 'Body must be valid JSON.', locals.cfRay, 400);
  }

  const parsed = parseCycloneDxSbom(body);
  if (!parsed.ok) {
    return errorResponse('VALIDATION_ERROR', parsed.error ?? 'Invalid SBOM.', locals.cfRay, 400);
  }

  const result = await importSbom(env.DB, assetId, parsed.components, parsed.skipped);
  return new Response(JSON.stringify(result), {
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
};
