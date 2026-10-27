import type { Handle } from '@sveltejs/kit';

const CACHE_CONTROL: Record<string, string> = {
  '/api/cve/': 'public, max-age=300',
  '/api/search': 'no-store',
  '/api/affected-products': 'public, max-age=300',
  '/api/threat-intel/kev': 'public, max-age=3600',
  '/api/threat-intel/epss': 'public, max-age=3600',
  '/api/metrics/': 'public, max-age=300',
  '/api/admin/health': 'no-store',
};

function getCacheControl(pathname: string): string | null {
  for (const [prefix, value] of Object.entries(CACHE_CONTROL)) {
    if (pathname === prefix || pathname.startsWith(prefix)) return value;
  }
  return null;
}

export const handle: Handle = async ({ event, resolve }) => {
  event.locals.clientIp = event.request.headers.get('cf-connecting-ip') ?? '0.0.0.0';
  event.locals.cfRay = event.request.headers.get('cf-ray') ?? '';

  const response = await resolve(event);

  // Set Cache-Control for API routes.
  const cc = getCacheControl(new URL(event.request.url).pathname);
  if (cc) {
    const modified = new Response(response.body, response);
    modified.headers.set('Cache-Control', cc);
    return modified;
  }

  return response;
};
