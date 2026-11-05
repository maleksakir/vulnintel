import { errorResponse } from '$lib/server/errorResponse';
import { checkRateLimit } from '$lib/server/quota';
import { parseCycloneDxSbom } from '$lib/server/sbom';
import { scanSbom } from '$lib/server/sbomMatch';
import type { RequestHandler } from './$types';

// Max accepted upload: 8 MB. A CycloneDX BOM for a large app is typically well
// under 2 MB; this is a generous guard against a memory-blowing upload on the
// Workers Free plan. The component count itself is separately capped at
// MAX_SBOM_COMPONENTS inside parseCycloneDxSbom.
const MAX_BODY_BYTES = 8 * 1024 * 1024;

/**
 * POST /api/sbom/scan — stateless SBOM vulnerability scan.
 *
 * Body: a CycloneDX JSON SBOM. The server parses it, matches every component
 * against already-ingested OSV/CPE data, and returns the affected components
 * + their CVEs. Nothing is stored. Public (no auth) but rate-limited, since
 * each scan is an unbounded-ish set of D1 reads (bounded by the query budget
 * in sbomMatch.ts, but still a real cost per request).
 */
export const POST: RequestHandler = async ({ request, platform, locals }) => {
  const env = platform?.env;
  if (!env?.DB) {
    return errorResponse('INTERNAL_ERROR', 'Service unavailable.', locals.cfRay, 503);
  }

  const rate = await checkRateLimit(env.RATE_LIMITER, locals.clientIp);
  if (!rate.allowed) {
    return errorResponse(
      'RATE_LIMITED',
      'Rate limit reached. Try again shortly.',
      locals.cfRay,
      429,
      {
        retryAfterSeconds: 60,
      },
    );
  }

  // Reject oversized uploads before reading the whole body into memory.
  const lengthHeader = request.headers.get('content-length');
  if (lengthHeader && Number(lengthHeader) > MAX_BODY_BYTES) {
    return errorResponse(
      'VALIDATION_ERROR',
      `SBOM too large (max ${MAX_BODY_BYTES / 1024 / 1024} MB).`,
      locals.cfRay,
      413,
    );
  }

  let raw: unknown;
  try {
    const text = await request.text();
    if (text.length > MAX_BODY_BYTES) {
      return errorResponse(
        'VALIDATION_ERROR',
        `SBOM too large (max ${MAX_BODY_BYTES / 1024 / 1024} MB).`,
        locals.cfRay,
        413,
      );
    }
    raw = JSON.parse(text);
  } catch {
    return errorResponse('VALIDATION_ERROR', 'Body must be valid JSON.', locals.cfRay, 400);
  }

  const parsed = parseCycloneDxSbom(raw);
  if (!parsed.ok) {
    return errorResponse(
      'VALIDATION_ERROR',
      parsed.error ?? 'Not a valid CycloneDX SBOM.',
      locals.cfRay,
      400,
    );
  }

  const result = await scanSbom(env.DB, parsed.components, parsed.skipped);

  return new Response(JSON.stringify(result), {
    headers: {
      'Content-Type': 'application/json',
      // A scan result is derived entirely from the uploaded body + live CVE
      // data; never cache it (and the body is a POST anyway).
      'Cache-Control': 'no-store',
    },
  });
};
