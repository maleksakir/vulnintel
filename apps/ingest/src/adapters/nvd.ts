import type {
  NormalizedCpe,
  NormalizedCveRecord,
  Severity,
  SsvcDecision,
} from '@threat-lens/contracts';

const NVD_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const RESULTS_PER_PAGE = 2000;
const REQUEST_DELAY_MS = 600; // respect 50 req/30s with API key

// --- NVD 2.0 response types (internal to this module) ---

interface NvdCveResponse {
  resultsPerPage: number;
  startIndex: number;
  totalResults: number;
  vulnerabilities: Array<{ cve: NvdCve }>;
}

interface NvdCve {
  id: string;
  published: string;
  lastModified: string;
  vulnStatus: string;
  descriptions: Array<{ lang: string; value: string }>;
  metrics?: NvdMetrics;
  weaknesses?: Array<{
    source: string;
    type: string;
    description: Array<{ lang: string; value: string }>;
  }>;
  configurations?: NvdConfiguration[];
  references?: Array<{ url: string; source?: string; tags?: string[] }>;
}

interface NvdCvssMetric {
  source: string;
  type: string;
  cvssData: {
    version: string;
    vectorString: string;
    baseScore: number;
    baseSeverity: string;
    exploitabilityScore?: number;
    impactScore?: number;
  };
  exploitabilityScore?: number;
  impactScore?: number;
}

interface NvdCvssV4Metric {
  source: string;
  type: string;
  cvssData: {
    version: string;
    vectorString: string;
    baseScore: number;
    baseSeverity: string;
  };
}

/** `metrics` carries `cvssMetricV31`/`cvssMetricV40` plus zero or more
 *  `ssvcV\d+` keys (e.g. `ssvcV203` today) — matched by pattern in
 *  `extractSsvcDecision` below, not hardcoded here, so a future SSVC tree
 *  version shows up under the index signature without a type change. */
interface NvdMetrics {
  cvssMetricV31?: NvdCvssMetric[];
  cvssMetricV40?: NvdCvssV4Metric[];
  [key: string]: unknown;
}

/** One `metrics.ssvcV203[]`-shaped entry. Multiple entries can appear for
 *  the same CVE (role "CNA", "Supplier", "CISA Coordinator", …) — only the
 *  one whose `source` is CISA-ADP's org id is the CISA decision this
 *  codebase cares about; see CISA_ADP_SOURCE_ID. */
interface NvdSsvcEntry {
  source?: unknown;
  ssvcData?: {
    timestamp?: unknown;
    options?: unknown;
  };
}

interface NvdConfiguration {
  operator?: string;
  negate?: boolean;
  nodes?: NvdNode[];
}

interface NvdNode {
  operator: string;
  negate: boolean;
  cpeMatch?: NvdCpeMatch[];
  nodes?: NvdNode[];
}

interface NvdCpeMatch {
  vulnerable: boolean;
  criteria: string;
  versionStartIncluding?: string;
  versionStartExcluding?: string;
  versionEndIncluding?: string;
  versionEndExcluding?: string;
}

// --- Public API ---

/**
 * Fetches CVEs from NVD modified in [startDate, endDate].
 * Paginates transparently; honours Retry-After on 429.
 * Yields NormalizedCveRecord values as they're parsed.
 */
export async function* fetchNvdDelta(
  apiKey: string,
  startDate: Date,
  endDate: Date,
): AsyncGenerator<NormalizedCveRecord> {
  const fmt = (d: Date) => d.toISOString().replace(/\.\d{3}Z$/, '.000');
  let startIndex = 0;
  let total = Infinity;

  while (startIndex < total) {
    const url = new URL(NVD_BASE);
    url.searchParams.set('lastModStartDate', fmt(startDate));
    url.searchParams.set('lastModEndDate', fmt(endDate));
    url.searchParams.set('startIndex', String(startIndex));
    url.searchParams.set('resultsPerPage', String(RESULTS_PER_PAGE));

    const res = await fetchWithRetry(url.toString(), apiKey);
    const body = await res.json<NvdCveResponse>();

    total = body.totalResults;

    for (const { cve } of body.vulnerabilities) {
      const record = normalizeNvdCve(cve);
      if (record) yield record;
    }

    startIndex += body.resultsPerPage;
    if (startIndex < total) await sleep(REQUEST_DELAY_MS);
  }
}

async function fetchWithRetry(url: string, apiKey: string, maxAttempts = 5): Promise<Response> {
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const res = await fetch(url, {
      headers: {
        apiKey,
        Accept: 'application/json',
      },
    });

    if (res.status === 429 || res.status === 503) {
      const retryAfter = parseInt(res.headers.get('Retry-After') ?? '30', 10);
      await sleep(retryAfter * 1000);
      continue;
    }

    if (!res.ok) throw new Error(`NVD API ${res.status}: ${url}`);
    return res;
  }
  throw new Error(`NVD API failed after ${maxAttempts} attempts: ${url}`);
}

function normalizeNvdCve(cve: NvdCve): NormalizedCveRecord | null {
  const enDesc = cve.descriptions.find((d) => d.lang === 'en');
  if (!enDesc) return null;

  // CVSS — prefer v4.0, fall back to v3.1
  let cvss: NormalizedCveRecord['cvss'] = null;
  const m4 = cve.metrics?.cvssMetricV40?.[0];
  const m31 =
    cve.metrics?.cvssMetricV31?.find((m) => m.type === 'Primary') ??
    cve.metrics?.cvssMetricV31?.[0];

  if (m4) {
    cvss = {
      version: '4.0',
      vector: m4.cvssData.vectorString,
      base: m4.cvssData.baseScore,
      exploitability: null,
      impact: null,
    };
  } else if (m31) {
    cvss = {
      version: '3.1',
      vector: m31.cvssData.vectorString,
      base: m31.cvssData.baseScore,
      exploitability: m31.exploitabilityScore ?? m31.cvssData.exploitabilityScore ?? null,
      impact: m31.impactScore ?? m31.cvssData.impactScore ?? null,
    };
  }

  const severity = cvssToSeverity(cvss?.base ?? null, cvss?.version ?? null);

  // CWEs
  const cwes: string[] = [];
  for (const weakness of cve.weaknesses ?? []) {
    for (const d of weakness.description) {
      if (d.lang === 'en' && d.value.startsWith('CWE-')) {
        cwes.push(d.value);
      }
    }
  }

  // CPEs (flatten all nodes recursively)
  const cpeMatches: NvdCpeMatch[] = [];
  for (const config of cve.configurations ?? []) {
    extractCpeMatches(config.nodes ?? [], cpeMatches);
  }
  const cpes = cpeMatches.map(parseCpeMatch).filter((c): c is NormalizedCpe => c !== null);

  // References
  const references = (cve.references ?? []).map((r) => ({
    url: r.url,
    tags: r.tags ?? [],
  }));

  return {
    cveId: cve.id,
    publishedAt: new Date(cve.published).getTime(),
    lastModifiedAt: new Date(cve.lastModified).getTime(),
    description: enDesc.value,
    cvss,
    severity,
    source: 'NVD',
    cwes: [...new Set(cwes)],
    cpes,
    references,
    ssvc: extractSsvcDecision(cve.metrics),
  };
}

// --- SSVC extraction ---

/** CISA-ADP's orgId. The same `metrics.ssvcV203[]` array can carry entries
 *  from other roles ("CNA", "Supplier") — this is the only one Threat-Lens
 *  treats as "the" SSVC decision (verified live against CVE-2024-3400). */
const CISA_ADP_SOURCE_ID = '134c704f-9b21-4f2e-91b3-4a467353bcc0';

/** Matches `ssvcV203`, a future `ssvcV204`, etc. — never hardcode the
 *  version string, since NVD can ship a new SSVC tree revision under a new
 *  key without warning. */
const SSVC_METRIC_KEY_PATTERN = /^ssvcV\d+$/;

const SSVC_EXPLOITATION_VALUES = ['none', 'poc', 'active'] as const;
const SSVC_AUTOMATABLE_VALUES = ['yes', 'no'] as const;
const SSVC_TECHNICAL_IMPACT_VALUES = ['partial', 'total'] as const;

/**
 * Parses NVD API 2.0's `metrics.ssvcV\d+[]` into Threat-Lens's SsvcDecision
 * shape. Exported so `scripts/backfill.ts` (which maintains its own
 * separate NVD normalization, see its top-of-file comment) can call the
 * same logic instead of re-implementing it and drifting out of sync.
 *
 * Returns null when no CISA-ADP entry exists at all (most CVEs — SSVC
 * CISA-ADP decisions are the minority). Returns an SsvcDecision with
 * individually-null fields when a CISA-ADP entry exists but a given
 * decision point is missing or carries a value this codebase doesn't
 * recognize — never throws on malformed/unexpected upstream shapes.
 *
 * Typed as a bare `Record<string, unknown>` (not the local `NvdMetrics`
 * interface) so `scripts/backfill.ts` — which maintains its own separate,
 * differently-shaped local NVD response types (see that file's top-of-file
 * comment) — can call this without needing to import or restructure around
 * this module's internal types.
 */
export function extractSsvcDecision(
  metrics: Record<string, unknown> | undefined,
): SsvcDecision | null {
  if (!metrics || typeof metrics !== 'object') return null;

  for (const key of Object.keys(metrics)) {
    if (!SSVC_METRIC_KEY_PATTERN.test(key)) continue;

    const entries = metrics[key];
    if (!Array.isArray(entries)) continue;

    const cisaEntry = entries.find(
      (e): e is NvdSsvcEntry =>
        !!e && typeof e === 'object' && (e as NvdSsvcEntry).source === CISA_ADP_SOURCE_ID,
    );
    if (!cisaEntry?.ssvcData) continue;

    return {
      exploitation: pickSsvcOption(
        cisaEntry.ssvcData.options,
        'exploitation',
        SSVC_EXPLOITATION_VALUES,
      ),
      automatable: pickSsvcOption(
        cisaEntry.ssvcData.options,
        'automatable',
        SSVC_AUTOMATABLE_VALUES,
      ),
      technicalImpact: pickSsvcOption(
        cisaEntry.ssvcData.options,
        'technicalImpact',
        SSVC_TECHNICAL_IMPACT_VALUES,
      ),
      decidedAt: parseSsvcTimestamp(cisaEntry.ssvcData.timestamp),
    };
  }

  return null;
}

/**
 * `options` is an array of single-key objects (e.g.
 * `[{"exploitation":"active"}, {"automatable":"yes"}, ...]`) — found by key,
 * never by array position, since non-CISA entries elsewhere in the same
 * response can order/omit options differently. A present-but-unrecognized
 * value (future SSVC enum addition) becomes null, not a thrown error.
 */
function pickSsvcOption<T extends string>(
  options: unknown,
  key: string,
  allowed: readonly T[],
): T | null {
  if (!Array.isArray(options)) return null;
  for (const opt of options) {
    if (!opt || typeof opt !== 'object' || !(key in opt)) continue;
    const value = (opt as Record<string, unknown>)[key];
    return typeof value === 'string' && (allowed as readonly string[]).includes(value)
      ? (value as T)
      : null;
  }
  return null;
}

/**
 * CISA's `ssvcData.timestamp` has been observed in two shapes: microsecond
 * precision ("2024-04-17T04:00:13.543064Z") and offset-based with no
 * sub-second component ("2024-04-17T04:00:13+00:00"). `Date.parse`'s
 * handling of more-than-3-digit fractional seconds is not guaranteed by the
 * ISO 8601 grammar it's specified against and varies by engine, so this
 * truncates any fractional-seconds component to exactly 3 digits before
 * parsing rather than relying on runtime-specific leniency. A failed parse
 * (missing/malformed timestamp) yields null, never NaN.
 */
function parseSsvcTimestamp(raw: unknown): number | null {
  if (typeof raw !== 'string' || raw.length === 0) return null;
  const normalized = raw.replace(/(\.\d{3})\d+(Z|[+-]\d{2}:?\d{2})?$/, '$1$2');
  const ms = Date.parse(normalized);
  return Number.isNaN(ms) ? null : ms;
}

function extractCpeMatches(nodes: NvdNode[], acc: NvdCpeMatch[]): void {
  for (const node of nodes) {
    if (node.cpeMatch) acc.push(...node.cpeMatch);
    if (node.nodes) extractCpeMatches(node.nodes, acc);
  }
}

function parseCpeMatch(match: NvdCpeMatch): NormalizedCpe | null {
  const parts = match.criteria.split(':');
  // cpe:2.3:part:vendor:product:version:...
  if (parts.length < 6 || parts[0] !== 'cpe' || parts[1] !== '2.3') return null;

  const rawPart = parts[2] ?? '*';
  const vendor = decodeCpeComp(parts[3] ?? '*');
  const product = decodeCpeComp(parts[4] ?? '*');
  const version = parts[5] === '*' || parts[5] === '-' ? null : decodeCpeComp(parts[5] ?? '');

  return {
    cpeUri: match.criteria,
    part: rawPart === 'a' || rawPart === 'o' || rawPart === 'h' ? rawPart : null,
    vendor,
    product,
    version,
    ...(match.versionStartIncluding !== undefined && {
      versionStartIncluding: match.versionStartIncluding,
    }),
    ...(match.versionStartExcluding !== undefined && {
      versionStartExcluding: match.versionStartExcluding,
    }),
    ...(match.versionEndIncluding !== undefined && {
      versionEndIncluding: match.versionEndIncluding,
    }),
    ...(match.versionEndExcluding !== undefined && {
      versionEndExcluding: match.versionEndExcluding,
    }),
    vulnerable: match.vulnerable,
    extras: {},
  };
}

function decodeCpeComp(s: string): string {
  return s.replace(/%([0-9A-Fa-f]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
}

function cvssToSeverity(base: number | null, version: string | null): Severity {
  if (base === null) return 'NONE';
  if (version === '4.0') {
    if (base === 0) return 'NONE';
    if (base < 4.0) return 'LOW';
    if (base < 7.0) return 'MEDIUM';
    if (base < 9.0) return 'HIGH';
    return 'CRITICAL';
  }
  // v3.x and fallback
  if (base === 0) return 'NONE';
  if (base < 4.0) return 'LOW';
  if (base < 7.0) return 'MEDIUM';
  if (base < 9.0) return 'HIGH';
  return 'CRITICAL';
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
