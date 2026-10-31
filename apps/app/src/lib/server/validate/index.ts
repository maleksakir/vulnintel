import type {
  AffectedProductsRequest,
  MetricsWindow,
  SearchFilters,
  SearchRequest,
} from '@threat-lens/contracts';

// ── SearchRequest ─────────────────────────────────────────────────────────────

export function validateSearchRequest(body: unknown):
  | {
      ok: true;
      value: SearchRequest;
    }
  | {
      ok: false;
      details: Record<string, string>;
    } {
  if (typeof body !== 'object' || body === null) {
    return { ok: false, details: { _root: 'Request body must be a JSON object' } };
  }

  const b = body as Record<string, unknown>;
  const errors: Record<string, string> = {};

  const hasQuery = b['query'] !== undefined;
  const hasSimilarTo = b['similarTo'] !== undefined;

  if (!hasQuery && !hasSimilarTo) {
    errors['_root'] = 'One of "query" or "similarTo" is required';
  }

  if (hasQuery && hasSimilarTo) {
    errors['_root'] = '"query" and "similarTo" are mutually exclusive';
  }

  if (hasQuery) {
    const q = b['query'];
    if (typeof q !== 'string' || q.length < 1 || q.length > 256) {
      errors['query'] = 'Must be a string of 1–256 characters';
    }
  }

  if (hasSimilarTo) {
    const s = b['similarTo'];
    if (typeof s !== 'string' || !/^CVE-\d{4}-\d+$/i.test(s)) {
      errors['similarTo'] = 'Must be a valid CVE ID (CVE-YYYY-NNNNN)';
    }
  }

  if (b['limit'] !== undefined) {
    const lim = Number(b['limit']);
    if (!Number.isInteger(lim) || lim < 1 || lim > 50) {
      errors['limit'] = 'Must be an integer 1–50';
    }
  }

  if (b['filters'] !== undefined) {
    const fErr = validateFilters(b['filters']);
    Object.assign(errors, fErr);
  }

  if (Object.keys(errors).length > 0) return { ok: false, details: errors };

  return {
    ok: true,
    value: {
      ...(hasQuery && { query: b['query'] as string }),
      ...(hasSimilarTo && { similarTo: b['similarTo'] as string }),
      ...(b['filters'] !== undefined && { filters: b['filters'] as SearchFilters }),
      ...(b['limit'] !== undefined && { limit: Number(b['limit']) }),
    },
  };
}

function validateFilters(f: unknown): Record<string, string> {
  const errors: Record<string, string> = {};
  if (typeof f !== 'object' || f === null) {
    errors['filters'] = 'Must be an object';
    return errors;
  }

  const filters = f as Record<string, unknown>;
  const validSeverities = new Set(['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);

  if (filters['severity'] !== undefined) {
    if (
      !Array.isArray(filters['severity']) ||
      !filters['severity'].every((s: unknown) => typeof s === 'string' && validSeverities.has(s))
    ) {
      errors['filters.severity'] = 'Must be an array of severity strings';
    }
  }

  if (filters['minCvss'] !== undefined) {
    const v = Number(filters['minCvss']);
    if (isNaN(v) || v < 0 || v > 10) {
      errors['filters.minCvss'] = 'Must be a number 0–10';
    }
  }

  if (filters['publishedSince'] !== undefined) {
    if (
      typeof filters['publishedSince'] !== 'string' ||
      isNaN(Date.parse(filters['publishedSince']))
    ) {
      errors['filters.publishedSince'] = 'Must be a valid ISO date string';
    }
  }

  return errors;
}

// ── CVE ID ────────────────────────────────────────────────────────────────────

export function isValidCveId(id: string): boolean {
  return /^CVE-\d{4}-\d+$/i.test(id);
}

// ── AffectedProductsRequest ───────────────────────────────────────────────────

export function validateAffectedProductsParams(params: URLSearchParams):
  | {
      ok: true;
      value: AffectedProductsRequest;
    }
  | {
      ok: false;
      details: Record<string, string>;
    } {
  const errors: Record<string, string> = {};

  const limitStr = params.get('limit');
  const limit = limitStr !== null ? Number(limitStr) : 50;
  if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
    errors['limit'] = 'Must be an integer 1–100';
  }

  const minCvssStr = params.get('minCvss');
  if (minCvssStr !== null) {
    const v = Number(minCvssStr);
    if (isNaN(v) || v < 0 || v > 10) {
      errors['minCvss'] = 'Must be a number 0–10';
    }
  }

  if (Object.keys(errors).length > 0) return { ok: false, details: errors };

  const vendor = params.get('vendor');
  const product = params.get('product');
  const cursor = params.get('cursor');
  return {
    ok: true,
    value: {
      ...(vendor !== null && { vendor }),
      ...(product !== null && { product }),
      ...(minCvssStr !== null && { minCvss: Number(minCvssStr) }),
      ...(cursor !== null && { cursor }),
      limit,
    },
  };
}

// ── MetricsWindow ─────────────────────────────────────────────────────────────

const VALID_WINDOWS = new Set<MetricsWindow>(['1h', '24h', '7d', '30d', '90d']);

export function isValidMetricsWindow(w: string): w is MetricsWindow {
  return VALID_WINDOWS.has(w as MetricsWindow);
}

// ── Watchlists ────────────────────────────────────────────────────────────────

const WATCHLIST_STATUSES = new Set(['NEW', 'TRIAGING', 'ACKNOWLEDGED', 'RESOLVED', 'IGNORED']);

const NAME_MAX = 120;
const DESC_MAX = 500;
const NOTE_MAX = 2000;
const VENDOR_MAX = 200;
const PRODUCT_MAX = 200;

type Validated<T> = { ok: true; value: T } | { ok: false; details: Record<string, string> };

export function validateCreateWatchlist(
  body: unknown,
): Validated<{ name: string; description?: string }> {
  if (typeof body !== 'object' || body === null) {
    return { ok: false, details: { _root: 'Request body must be a JSON object' } };
  }
  const b = body as Record<string, unknown>;
  const errors: Record<string, string> = {};

  const name = typeof b.name === 'string' ? b.name.trim() : '';
  if (name.length < 1 || name.length > NAME_MAX) {
    errors.name = `Must be a string of 1–${NAME_MAX} characters`;
  }

  let description: string | undefined;
  if (b.description !== undefined && b.description !== null) {
    if (typeof b.description !== 'string' || b.description.length > DESC_MAX) {
      errors.description = `Must be a string of at most ${DESC_MAX} characters`;
    } else {
      description = b.description;
    }
  }

  if (Object.keys(errors).length > 0) return { ok: false, details: errors };
  return { ok: true, value: { name, ...(description !== undefined && { description }) } };
}

export function validateUpdateWatchlist(
  body: unknown,
): Validated<{ name?: string; description?: string | null }> {
  if (typeof body !== 'object' || body === null) {
    return { ok: false, details: { _root: 'Request body must be a JSON object' } };
  }
  const b = body as Record<string, unknown>;
  const errors: Record<string, string> = {};
  const value: { name?: string; description?: string | null } = {};

  if (b.name !== undefined) {
    const name = typeof b.name === 'string' ? b.name.trim() : '';
    if (name.length < 1 || name.length > NAME_MAX) {
      errors.name = `Must be a string of 1–${NAME_MAX} characters`;
    } else {
      value.name = name;
    }
  }
  if (b.description !== undefined) {
    if (b.description === null) {
      value.description = null;
    } else if (typeof b.description !== 'string' || b.description.length > DESC_MAX) {
      errors.description = `Must be a string of at most ${DESC_MAX} characters, or null`;
    } else {
      value.description = b.description;
    }
  }

  if (Object.keys(errors).length > 0) return { ok: false, details: errors };
  if (value.name === undefined && value.description === undefined) {
    return { ok: false, details: { _root: 'At least one of name or description is required' } };
  }
  return { ok: true, value };
}

export function validateCreateSubscription(
  body: unknown,
): Validated<{ vendor: string; product: string | null }> {
  if (typeof body !== 'object' || body === null) {
    return { ok: false, details: { _root: 'Request body must be a JSON object' } };
  }
  const b = body as Record<string, unknown>;
  const errors: Record<string, string> = {};

  // NVD normalizes vendor/product to lowercase in cpe; lowercase user input
  // so a subscription actually matches (the reconciliation engine compares
  // case-sensitively against cpe.vendor/product).
  const vendor = typeof b.vendor === 'string' ? b.vendor.trim().toLowerCase() : '';
  if (vendor.length < 1 || vendor.length > VENDOR_MAX) {
    errors.vendor = `Must be a string of 1–${VENDOR_MAX} characters`;
  }

  let product: string | null = null;
  if (b.product !== undefined && b.product !== null) {
    if (typeof b.product !== 'string' || b.product.length > PRODUCT_MAX) {
      errors.product = `Must be a string of at most ${PRODUCT_MAX} characters, or null/omitted for all products`;
    } else {
      const trimmed = b.product.trim().toLowerCase();
      product = trimmed.length > 0 ? trimmed : null;
    }
  }

  if (Object.keys(errors).length > 0) return { ok: false, details: errors };
  return { ok: true, value: { vendor, product } };
}

const WEBHOOK_KINDS = new Set(['generic', 'slack']);
const URL_MAX = 2048;

export function validateCreateWebhook(
  body: unknown,
): Validated<{ url: string; kind: 'generic' | 'slack' }> {
  if (typeof body !== 'object' || body === null) {
    return { ok: false, details: { _root: 'Request body must be a JSON object' } };
  }
  const b = body as Record<string, unknown>;
  const errors: Record<string, string> = {};

  const url = typeof b.url === 'string' ? b.url.trim() : '';
  // Require an absolute https URL — a webhook is an outbound POST of internal
  // data, so http (cleartext) and relative/other schemes are rejected.
  let parsed: URL | null = null;
  try {
    parsed = new URL(url);
  } catch {
    parsed = null;
  }
  if (url.length < 1 || url.length > URL_MAX || parsed === null || parsed.protocol !== 'https:') {
    errors.url = `Must be an absolute https:// URL of at most ${URL_MAX} characters`;
  }

  let kind: 'generic' | 'slack' = 'generic';
  if (b.kind !== undefined) {
    if (typeof b.kind !== 'string' || !WEBHOOK_KINDS.has(b.kind)) {
      errors.kind = "Must be 'generic' or 'slack'";
    } else {
      kind = b.kind as 'generic' | 'slack';
    }
  }

  if (Object.keys(errors).length > 0) return { ok: false, details: errors };
  return { ok: true, value: { url, kind } };
}

export function validateUpdateMatch(
  body: unknown,
): Validated<{ status?: string; note?: string | null }> {
  if (typeof body !== 'object' || body === null) {
    return { ok: false, details: { _root: 'Request body must be a JSON object' } };
  }
  const b = body as Record<string, unknown>;
  const errors: Record<string, string> = {};
  const value: { status?: string; note?: string | null } = {};

  if (b.status !== undefined) {
    if (typeof b.status !== 'string' || !WATCHLIST_STATUSES.has(b.status)) {
      errors.status = `Must be one of: ${[...WATCHLIST_STATUSES].join(', ')}`;
    } else {
      value.status = b.status;
    }
  }
  if (b.note !== undefined) {
    if (b.note === null) {
      value.note = null;
    } else if (typeof b.note !== 'string' || b.note.length > NOTE_MAX) {
      errors.note = `Must be a string of at most ${NOTE_MAX} characters, or null`;
    } else {
      value.note = b.note;
    }
  }

  if (Object.keys(errors).length > 0) return { ok: false, details: errors };
  if (value.status === undefined && value.note === undefined) {
    return { ok: false, details: { _root: 'At least one of status or note is required' } };
  }
  return { ok: true, value };
}
