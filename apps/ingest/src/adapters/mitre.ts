import type { NormalizedCveRecord, Severity } from '@threat-lens/contracts';

const MITRE_API_BASE = 'https://cveawg.mitre.org/api/cve';
const PAGE_SIZE = 500;

// --- MITRE CVE JSON 5.0 types (internal) ---

interface MitreListResponse {
  format: string;
  numberOfCVEs: number;
  currentPage: number;
  itemsPerPage: number;
  nextPage: number | null;
  cveRecords: MitreCveRecord[];
}

interface MitreCveRecord {
  cveId: string;
  cveMetadata: {
    cveId: string;
    state: string;
    datePublished?: string;
    dateUpdated?: string;
  };
  containers?: {
    cna?: MitreCna;
  };
}

interface MitreCna {
  title?: string;
  descriptions?: Array<{ lang: string; value: string }>;
  affected?: MitreAffected[];
  problemTypes?: Array<{
    descriptions: Array<{
      lang?: string;
      description?: string;
      type?: string;
      cweId?: string;
    }>;
  }>;
  references?: Array<{ url: string; tags?: string[] }>;
  metrics?: MitreMetric[];
}

interface MitreAffected {
  vendor?: string;
  product?: string;
  versions?: Array<{ version: string; status: string; lessThan?: string; versionType?: string }>;
}

interface MitreMetric {
  cvssV3_1?: {
    vectorString: string;
    baseScore: number;
    baseSeverity: string;
    exploitabilityScore?: number;
    impactScore?: number;
  };
  cvssV4_0?: {
    vectorString: string;
    baseScore: number;
    baseSeverity: string;
  };
}

// --- Public API ---

/**
 * Fetches CVEs from MITRE modified in [startDate, endDate].
 * Yields NormalizedCveRecord — primarily used for CWE supplementation.
 */
export async function* fetchMitreDelta(
  startDate: Date,
  endDate: Date,
): AsyncGenerator<NormalizedCveRecord> {
  let page = 0;
  let hasMore = true;

  while (hasMore) {
    const url = new URL(MITRE_API_BASE);
    url.searchParams.set('time_modified.start', startDate.toISOString());
    url.searchParams.set('time_modified.end', endDate.toISOString());
    url.searchParams.set('pageSize', String(PAGE_SIZE));
    url.searchParams.set('pageNumber', String(page));

    const res = await fetch(url.toString(), {
      headers: { Accept: 'application/json' },
    });

    if (res.status === 429) {
      const retryAfter = parseInt(res.headers.get('Retry-After') ?? '10', 10);
      await sleep(retryAfter * 1000);
      continue;
    }

    if (!res.ok) throw new Error(`MITRE API ${res.status}: ${url.toString()}`);

    const body = await res.json<MitreListResponse>();

    for (const rec of body.cveRecords) {
      const normalized = normalizeMitreRecord(rec);
      if (normalized) yield normalized;
    }

    hasMore = body.nextPage !== null;
    page++;
  }
}

function normalizeMitreRecord(rec: MitreCveRecord): NormalizedCveRecord | null {
  if (rec.cveMetadata.state !== 'PUBLISHED') return null;

  const cna = rec.containers?.cna;
  if (!cna) return null;

  const enDesc = cna.descriptions?.find(d => d.lang === 'en');
  if (!enDesc) return null;

  const publishedAt = rec.cveMetadata.datePublished
    ? new Date(rec.cveMetadata.datePublished).getTime()
    : Date.now();
  const lastModifiedAt = rec.cveMetadata.dateUpdated
    ? new Date(rec.cveMetadata.dateUpdated).getTime()
    : publishedAt;

  // CVSS from CNA metrics
  let cvss: NormalizedCveRecord['cvss'] = null;
  const m = cna.metrics?.[0];
  if (m?.cvssV4_0) {
    cvss = {
      version: '4.0',
      vector: m.cvssV4_0.vectorString,
      base: m.cvssV4_0.baseScore,
      exploitability: null,
      impact: null,
    };
  } else if (m?.cvssV3_1) {
    cvss = {
      version: '3.1',
      vector: m.cvssV3_1.vectorString,
      base: m.cvssV3_1.baseScore,
      exploitability: m.cvssV3_1.exploitabilityScore ?? null,
      impact: m.cvssV3_1.impactScore ?? null,
    };
  }

  const severity = cvssToSeverity(cvss?.base ?? null);

  // CWEs
  const cwes: string[] = [];
  for (const pt of cna.problemTypes ?? []) {
    for (const d of pt.descriptions) {
      const id = d.cweId ?? (d.description?.startsWith('CWE-') ? d.description : null);
      if (id) cwes.push(id);
    }
  }

  // Build synthetic CPE entries from affected[]
  const cpes = buildCpesFromAffected(cna.affected ?? []);

  const references = (cna.references ?? []).map(r => ({
    url: r.url,
    tags: r.tags ?? [],
  }));

  return {
    cveId: rec.cveId,
    publishedAt,
    lastModifiedAt,
    description: enDesc.value,
    cvss,
    severity,
    source: 'MITRE',
    cwes: [...new Set(cwes)],
    cpes,
    references,
  };
}

function buildCpesFromAffected(affected: MitreAffected[]) {
  return affected
    .filter(a => a.vendor && a.product)
    .map(a => ({
      cpeUri: `cpe:2.3:a:${slug(a.vendor!)}:${slug(a.product!)}:*:*:*:*:*:*:*:*`,
      part: 'a' as const,
      vendor: a.vendor!,
      product: a.product!,
      version: null,
      vulnerable: true,
      extras: {},
    }));
}

function slug(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]/g, '_');
}

function cvssToSeverity(base: number | null): Severity {
  if (base === null) return 'NONE';
  if (base === 0) return 'NONE';
  if (base < 4.0) return 'LOW';
  if (base < 7.0) return 'MEDIUM';
  if (base < 9.0) return 'HIGH';
  return 'CRITICAL';
}

function sleep(ms: number): Promise<void> {
  return new Promise(r => setTimeout(r, ms));
}
