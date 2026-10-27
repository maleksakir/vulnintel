import type { SearchRequest, SearchResponse, SearchResultItem, SearchFilters } from '@threat-lens/contracts';
import { embed } from '../embed';
import { checkAndIncrementQuota } from '../quota';

interface CveMetaRow {
  cve_id: string;
  severity: string;
  cvss_base: number | null;
  published_at: number;
  description: string;
  kev_listed: number;
  epss_percentile: number | null;
}

interface VendorRow {
  cve_id: string;
  vendors: string;
}

interface FtsRow {
  cve_id: string;
}

type VecFilter = Record<string, { $in?: string[]; $eq?: number; $gte?: number }>;

export async function searchCves(
  req: SearchRequest,
  platform: App.Platform,
  clientIp: string,
): Promise<{ response: SearchResponse; quotaError?: 'RATE_LIMITED' | 'GLOBAL_QUOTA_EXHAUSTED' }> {
  const env = platform.env;
  const limit = Math.min(req.limit ?? 25, 50);

  // Quota check
  const quota = await checkAndIncrementQuota(env.DB, clientIp);
  if (!quota.allowed) {
    return { response: { results: [], truncated: false }, ...(quota.reason !== undefined && { quotaError: quota.reason }) };
  }

  const ftsRanks = new Map<string, number>(); // cveId → 1-based rank
  const vecRanks = new Map<string, number>(); // cveId → 1-based rank
  const snippetMap = new Map<string, string>();

  // ── Exact CVE ID shortcut ─────────────────────────────────────────────────
  const isExactId = req.query && /^CVE-\d{4}-\d+$/i.test(req.query.trim());
  if (isExactId && req.query) {
    const id = req.query.trim().toUpperCase();
    ftsRanks.set(id, 1);
  }

  // ── FTS5 search ───────────────────────────────────────────────────────────
  if (req.query && !isExactId) {
    const fts = sanitizeFts5(req.query);
    if (fts) {
      const rows = await env.DB.prepare(
        `SELECT cve_id FROM cve_search WHERE cve_search MATCH ? ORDER BY rank LIMIT 200`,
      ).bind(fts).all<FtsRow>();
      rows.results.forEach((r, i) => ftsRanks.set(r.cve_id, i + 1));
    }
  }

  // ── Vectorize semantic search ─────────────────────────────────────────────
  let queryVec: number[] | null = null;
  if (req.similarTo) {
    try {
      const [existing] = await env.VECTORIZE.getByIds([req.similarTo]);
      queryVec = existing?.values ? Array.from(existing.values) : null;
    } catch {
      queryVec = null;
    }
  } else if (req.query && !isExactId) {
    try {
      queryVec = await embed(env.AI, req.query);
    } catch {
      queryVec = null;
    }
  }

  if (queryVec) {
    try {
      const vecFilter = buildVecFilter(req.filters);
      const vecRes = await env.VECTORIZE.query(queryVec, {
        topK: 200,
        returnMetadata: 'indexed',
        ...(vecFilter && { filter: vecFilter }),
      });
      vecRes.matches.forEach((m, i) => vecRanks.set(m.id, i + 1));
    } catch {
      // Vectorize unavailable in local dev — search continues with FTS results only
    }
  }

  // ── RRF fusion ────────────────────────────────────────────────────────────
  const allIds = new Set([...ftsRanks.keys(), ...vecRanks.keys()]);
  const K = 60;
  const rrfScores: Array<[string, number]> = [];

  for (const id of allIds) {
    const score =
      (ftsRanks.has(id) ? 1 / (K + ftsRanks.get(id)!) : 0) +
      (vecRanks.has(id) ? 1 / (K + vecRanks.get(id)!) : 0);
    rrfScores.push([id, score]);
  }
  rrfScores.sort((a, b) => b[1] - a[1]);

  if (rrfScores.length === 0) {
    return { response: { results: [], truncated: false } };
  }

  // Take up to 200 candidates for D1 post-filter.
  const candidateIds = rrfScores.slice(0, 200).map(([id]) => id);

  // ── D1 post-filter ────────────────────────────────────────────────────────
  const metaMap = await fetchCveMeta(candidateIds, env.DB);
  const vendorMap = await fetchVendors(candidateIds, env.DB);

  // Apply D1-level filters (vendor, publishedSince)
  const filtered = rrfScores.filter(([id, _score]) => {
    const row = metaMap.get(id);
    if (!row) return false;
    if (req.filters?.vendor?.length) {
      const v = vendorMap.get(id) ?? [];
      if (!req.filters.vendor.some(fv => v.includes(fv))) return false;
    }
    if (req.filters?.publishedSince) {
      const since = new Date(req.filters.publishedSince).getTime();
      if (row.published_at < since) return false;
    }
    if (req.filters?.kev === true && row.kev_listed !== 1) return false;
    if (req.filters?.severity?.length && !req.filters.severity.includes(row.severity as SearchResultItem['severity'])) return false;
    if (req.filters?.minCvss !== undefined && (row.cvss_base ?? 0) < req.filters.minCvss) return false;
    return true;
  });

  const truncated = filtered.length > limit;
  const page = filtered.slice(0, limit);

  const results: SearchResultItem[] = page.map(([id, score]) => {
    const row = metaMap.get(id)!;
    const vendors = (vendorMap.get(id) ?? []).slice(0, 3);
    return {
      cveId: id,
      score,
      severity: row.severity as SearchResultItem['severity'],
      cvssBase: row.cvss_base,
      kevListed: row.kev_listed === 1,
      epssPercentile: row.epss_percentile,
      publishedAt: new Date(row.published_at).toISOString(),
      vendors,
      snippet: snippetMap.get(id) ?? row.description.slice(0, 200),
    };
  });

  return { response: { results, truncated } };
}

// ── Helpers ────────────────────────────────────────────────────────────────

async function fetchCveMeta(ids: string[], db: D1Database): Promise<Map<string, CveMetaRow>> {
  const map = new Map<string, CveMetaRow>();
  for (let i = 0; i < ids.length; i += 100) {
    const chunk = ids.slice(i, i + 100);
    const ph = chunk.map(() => '?').join(',');
    const rows = await db.prepare(
      `SELECT c.cve_id, c.severity, c.cvss_base, c.published_at, c.description,
              COALESCE(s.kev_listed, 0) AS kev_listed,
              s.epss_percentile
       FROM cve c LEFT JOIN cve_state s USING (cve_id)
       WHERE c.cve_id IN (${ph})`,
    ).bind(...chunk).all<CveMetaRow>();
    for (const row of rows.results) map.set(row.cve_id, row);
  }
  return map;
}

async function fetchVendors(ids: string[], db: D1Database): Promise<Map<string, string[]>> {
  const map = new Map<string, string[]>();
  for (let i = 0; i < ids.length; i += 100) {
    const chunk = ids.slice(i, i + 100);
    const ph = chunk.map(() => '?').join(',');
    const rows = await db.prepare(
      `SELECT cve_id, GROUP_CONCAT(DISTINCT vendor) AS vendors
       FROM cpe WHERE cve_id IN (${ph})
       GROUP BY cve_id`,
    ).bind(...chunk).all<VendorRow>();
    for (const row of rows.results) {
      map.set(row.cve_id, row.vendors ? row.vendors.split(',').filter(Boolean) : []);
    }
  }
  return map;
}

function buildVecFilter(filters?: SearchFilters): VecFilter | undefined {
  if (!filters) return undefined;
  const f: VecFilter = {};
  if (filters.severity?.length) f['severity'] = { $in: filters.severity };
  if (filters.kev === true) f['kev_listed'] = { $eq: 1 };
  if (filters.minCvss !== undefined) f['cvss_base'] = { $gte: filters.minCvss };
  return Object.keys(f).length > 0 ? f : undefined;
}

function sanitizeFts5(input: string): string {
  return input
    .replace(/['"*^()[\]{}!,]/g, ' ')
    .trim()
    .split(/\s+/)
    .filter(Boolean)
    .join(' ');
}
