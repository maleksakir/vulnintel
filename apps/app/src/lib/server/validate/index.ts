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
