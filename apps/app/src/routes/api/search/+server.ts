import { errorResponse } from '$lib/server/errorResponse';
import { searchCves } from '$lib/server/queries/searchCves';
import { validateSearchRequest } from '$lib/server/validate/index';
import type { RequestHandler } from './$types';

export const POST: RequestHandler = async ({ request, platform, locals }) => {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return errorResponse('VALIDATION_ERROR', 'Request body must be valid JSON.', locals.cfRay, 400);
  }

  const validation = validateSearchRequest(body);
  if (!validation.ok) {
    return errorResponse('VALIDATION_ERROR', 'Invalid search request.', locals.cfRay, 400, {
      details: validation.details,
    });
  }

  const { response, quotaError } = await searchCves(validation.value, platform!, locals.clientIp);

  if (quotaError === 'GLOBAL_QUOTA_EXHAUSTED') {
    platform!.context.waitUntil(
      platform!.env.DB.prepare(
        `INSERT INTO audit_log (occurred_at, client_ip, cf_ray, route, action, detail_json)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
        .bind(
          Date.now(),
          locals.clientIp,
          locals.cfRay,
          '/api/search',
          'RATE_LIMITED:GLOBAL_QUOTA_EXHAUSTED',
          null,
        )
        .run(),
    );
    return errorResponse(
      'GLOBAL_QUOTA_EXHAUSTED',
      'Daily search quota exceeded. Try again tomorrow.',
      locals.cfRay,
      429,
      { retryAfterSeconds: 3600 },
    );
  }

  if (quotaError === 'RATE_LIMITED') {
    platform!.context.waitUntil(
      platform!.env.DB.prepare(
        `INSERT INTO audit_log (occurred_at, client_ip, cf_ray, route, action, detail_json)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
        .bind(
          Date.now(),
          locals.clientIp,
          locals.cfRay,
          '/api/search',
          'RATE_LIMITED:IP_HOURLY',
          null,
        )
        .run(),
    );
    return errorResponse(
      'RATE_LIMITED',
      'Per-IP hourly limit reached. Try again in an hour.',
      locals.cfRay,
      429,
      { retryAfterSeconds: 3600 },
    );
  }

  return new Response(JSON.stringify(response), {
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
    },
  });
};
