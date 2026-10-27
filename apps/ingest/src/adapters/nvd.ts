import type { NormalizedCpe, NormalizedCveRecord, Severity } from '@threat-lens/contracts';

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
  metrics?: {
    cvssMetricV31?: NvdCvssMetric[];
    cvssMetricV40?: NvdCvssV4Metric[];
  };
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
  };
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
