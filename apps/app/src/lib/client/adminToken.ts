// Client-side admin-token holder for watchlist mutations. Mirrors the
// /admin/health stopgap: the ADMIN_BEARER secret is entered by the operator
// and kept in sessionStorage (not localStorage — cleared when the tab closes,
// never written to disk), then sent as the Authorization header on
// admin-gated mutation requests. This is a stopgap, same as admin/health —
// the eventual replacement is Cloudflare Access (see the roadmap).

const KEY = 'tl_admin_token';

export function getAdminToken(): string {
  if (typeof sessionStorage === 'undefined') return '';
  return sessionStorage.getItem(KEY) ?? '';
}

export function setAdminToken(token: string): void {
  if (typeof sessionStorage === 'undefined') return;
  if (token) sessionStorage.setItem(KEY, token);
  else sessionStorage.removeItem(KEY);
}

export function hasAdminToken(): boolean {
  return getAdminToken().length > 0;
}

/** Issue an admin-gated mutation. Returns the parsed JSON body on success, or
 *  throws an Error with the server's message (so callers can toast it). */
export async function adminFetch(
  path: string,
  method: 'POST' | 'PUT' | 'PATCH' | 'DELETE',
  body?: unknown,
): Promise<unknown> {
  const token = getAdminToken();
  const res = await fetch(path, {
    method,
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    ...(body !== undefined && { body: JSON.stringify(body) }),
  });

  let parsed: unknown = null;
  try {
    parsed = await res.json();
  } catch {
    /* some responses may be empty */
  }

  if (!res.ok) {
    const envelope = parsed as { error?: { message?: string; code?: string } } | null;
    const msg = envelope?.error?.message ?? `Request failed (${res.status})`;
    const err = new Error(msg) as Error & { code?: string; status?: number };
    if (envelope?.error?.code !== undefined) err.code = envelope.error.code;
    err.status = res.status;
    throw err;
  }

  return parsed;
}
