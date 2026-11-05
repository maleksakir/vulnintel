import type {
  SearchFilters,
  SearchRequest,
  SearchResponse,
  SearchResultItem,
} from '@threat-lens/contracts';
import { embed } from '../embed';
import { looksNaturalLanguage, parseNlQuery } from '../nlQuery';
import { checkAndIncrementQuota } from '../quota';
import {
  fuseRerank,
  logRerankAttempt,
  RERANK_DAILY_SEARCH_CAP,
  RERANK_DOC_MAX_CHARS,
  RERANK_WEIGHT,
  rerank,
  rerankWindowSize,
} from '../rerank';

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
  const quota = await checkAndIncrementQuota(env.DB, env.RATE_LIMITER, clientIp);
  if (!quota.allowed) {
    return {
      response: { results: [], truncated: false },
      ...(quota.reason !== undefined && { quotaError: quota.reason }),
    };
  }

  // ── Natural-language query parse (AI, budget-gated) ───────────────────────
  // "critical apache rce from 2024" → cleaned query + structured filters.
  // Only when the query looks natural-language AND we're under the same shared
  // daily AI budget rerank uses (reusing quota's pre-increment count — no new
  // counter). Parsed filters MERGE with explicit UI filters (UI wins on
  // conflict). Degrades silently: on skip/failure the raw query is used.
  let effectiveQuery = req.query;
  let effectiveFilters: SearchFilters | undefined = req.filters;
  let interpretation: SearchResponse['interpretation'];
  const dailyCount = quota.dailyCount ?? 0;
  if (
    req.query &&
    !req.similarTo &&
    looksNaturalLanguage(req.query) &&
    dailyCount < RERANK_DAILY_SEARCH_CAP
  ) {
    const parsed = await parseNlQuery(env.AI, req.query);
    if (parsed) {
      // Merge: UI-supplied filters take precedence; NL fills the gaps.
      const merged: SearchFilters = { ...req.filters };
      if (merged.severity === undefined && parsed.severity.length > 0)
        merged.severity = parsed.severity;
      if (merged.vendor === undefined && parsed.vendor.length > 0) merged.vendor = parsed.vendor;
      if (merged.kev === undefined && parsed.kev === true) merged.kev = true;
      if (merged.minCvss === undefined && parsed.minCvss !== null) merged.minCvss = parsed.minCvss;
      if (merged.publishedSince === undefined && parsed.publishedSince !== null)
        merged.publishedSince = parsed.publishedSince;
      effectiveFilters = merged;
      // Use the cleaned query for retrieval when the model returned one.
      if (parsed.query && parsed.query.length > 0) effectiveQuery = parsed.query;
      interpretation = {
        query: effectiveQuery ?? req.query,
        severity: merged.severity ?? [],
        vendor: merged.vendor ?? [],
        kev: merged.kev ?? false,
        minCvss: merged.minCvss ?? null,
        publishedSince: merged.publishedSince ?? null,
      };
    }
  }

  const ftsRanks = new Map<string, number>(); // cveId → 1-based rank
  const vecRanks = new Map<string, number>(); // cveId → 1-based rank
  const snippetMap = new Map<string, string>();

  // ── Exact CVE ID shortcut ─────────────────────────────────────────────────
  const isExactId = effectiveQuery && /^CVE-\d{4}-\d+$/i.test(effectiveQuery.trim());
  if (isExactId && effectiveQuery) {
    const id = effectiveQuery.trim().toUpperCase();
    ftsRanks.set(id, 1);
  }

  // ── FTS5 search ───────────────────────────────────────────────────────────
  if (effectiveQuery && !isExactId) {
    const fts = sanitizeFts5(effectiveQuery);
    if (fts) {
      const rows = await env.DB.prepare(
        `SELECT cve_id FROM cve_search WHERE cve_search MATCH ? ORDER BY rank LIMIT 200`,
      )
        .bind(fts)
        .all<FtsRow>();
      rows.results.forEach((r, i) => {
        ftsRanks.set(r.cve_id, i + 1);
      });
    }
  }

  // ── Vectorize semantic search ─────────────────────────────────────────────
  let queryVec: number[] | null = null;
  // Tracked so the rerank stage below can skip entirely when the earlier
  // embed() call already signalled trouble with the shared Workers AI
  // neuron pool — a second AI call would just add latency for nothing.
  let embedFailed = false;
  if (req.similarTo) {
    try {
      const [existing] = await env.VECTORIZE.getByIds([req.similarTo]);
      queryVec = existing?.values ? Array.from(existing.values) : null;
    } catch {
      queryVec = null;
    }
  } else if (effectiveQuery && !isExactId) {
    try {
      queryVec = await embed(env.AI, effectiveQuery);
    } catch {
      queryVec = null;
      embedFailed = true;
    }
  }

  if (queryVec) {
    try {
      const vecFilter = buildVecFilter(effectiveFilters);
      const vecRes = await env.VECTORIZE.query(queryVec, {
        topK: 200,
        returnMetadata: 'indexed',
        ...(vecFilter && { filter: vecFilter }),
      });
      vecRes.matches.forEach((m, i) => {
        vecRanks.set(m.id, i + 1);
      });
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
    return {
      response: { results: [], truncated: false, ...(interpretation && { interpretation }) },
    };
  }

  // Take up to 200 candidates for D1 post-filter.
  const candidateIds = rrfScores.slice(0, 200).map(([id]) => id);

  // ── D1 post-filter ────────────────────────────────────────────────────────
  const metaMap = await fetchCveMeta(candidateIds, env.DB);
  const vendorMap = await fetchVendors(candidateIds, env.DB);

  // Apply D1-level filters (vendor, publishedSince) — using the effective
  // filters (explicit UI filters merged with any NL-parsed ones).
  const filtered = rrfScores.filter(([id, _score]) => {
    const row = metaMap.get(id);
    if (!row) return false;
    if (effectiveFilters?.vendor?.length) {
      const v = vendorMap.get(id) ?? [];
      if (!effectiveFilters.vendor.some((fv) => v.includes(fv))) return false;
    }
    if (effectiveFilters?.publishedSince) {
      const since = new Date(effectiveFilters.publishedSince).getTime();
      if (row.published_at < since) return false;
    }
    if (effectiveFilters?.kev === true && row.kev_listed !== 1) return false;
    if (
      effectiveFilters?.severity?.length &&
      !effectiveFilters.severity.includes(row.severity as SearchResultItem['severity'])
    )
      return false;
    if (effectiveFilters?.minCvss !== undefined && (row.cvss_base ?? 0) < effectiveFilters.minCvss)
      return false;
    return true;
  });

  // ── Reranking (quality pass, budget-gated, never blocks search) ──────────
  // Operates on `filtered` — already D1-post-filtered — so no neurons are
  // spent on candidates vendor/severity/kev/cvss filters already dropped,
  // and fetchCveMeta's descriptions (metaMap) are reused for free. Fused in
  // as a third RRF-style term (see fuseRerank) rather than replacing RRF
  // order outright, so exact lexical/CVE-ID matches stay protected.
  let rankedFiltered = filtered;
  const rerankQuery = effectiveQuery;
  const canAttemptRerank =
    typeof rerankQuery === 'string' &&
    rerankQuery.trim().length > 0 &&
    !isExactId &&
    filtered.length >= 2 &&
    !embedFailed;

  if (canAttemptRerank) {
    // Budget gate: piggybacks on the pre-increment count checkAndIncrementQuota
    // already read for the org-wide quota check above — zero extra D1/KV
    // operations, no new counter (see quota.ts and CLAUDE.md's KV-quota
    // incident). Once the daily cap is hit, every search for the rest of
    // the UTC day silently falls back to plain RRF ordering. (dailyCount was
    // read once above for the NL-parse gate; reused here.)
    if (dailyCount >= RERANK_DAILY_SEARCH_CAP) {
      logRerankAttempt('budget-skip', 0, 0);
    } else {
      const windowSize = rerankWindowSize(limit);
      const window = filtered.slice(0, windowSize);
      const docs = window.map(([id]) => {
        const row = metaMap.get(id)!;
        const vendors = (vendorMap.get(id) ?? []).slice(0, 3).join(' ');
        const text = vendors ? `${vendors}: ${row.description}` : row.description;
        return text.slice(0, RERANK_DOC_MAX_CHARS);
      });

      const order = await rerank(env.AI, rerankQuery, docs);
      if (order) {
        const fusedWindow = fuseRerank(window, order, K, RERANK_WEIGHT);
        rankedFiltered = [...fusedWindow, ...filtered.slice(windowSize)];
      }
    }
  }

  const truncated = rankedFiltered.length > limit;
  const page = rankedFiltered.slice(0, limit);

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

  return { response: { results, truncated, ...(interpretation && { interpretation }) } };
}

// ── Helpers ────────────────────────────────────────────────────────────────

async function fetchCveMeta(ids: string[], db: D1Database): Promise<Map<string, CveMetaRow>> {
  const map = new Map<string, CveMetaRow>();
  for (let i = 0; i < ids.length; i += 100) {
    const chunk = ids.slice(i, i + 100);
    const ph = chunk.map(() => '?').join(',');
    const rows = await db
      .prepare(
        `SELECT c.cve_id, c.severity, c.cvss_base, c.published_at, c.description,
              COALESCE(s.kev_listed, 0) AS kev_listed,
              s.epss_percentile
       FROM cve c LEFT JOIN cve_state s USING (cve_id)
       WHERE c.cve_id IN (${ph})`,
      )
      .bind(...chunk)
      .all<CveMetaRow>();
    for (const row of rows.results) map.set(row.cve_id, row);
  }
  return map;
}

async function fetchVendors(ids: string[], db: D1Database): Promise<Map<string, string[]>> {
  const map = new Map<string, string[]>();
  for (let i = 0; i < ids.length; i += 100) {
    const chunk = ids.slice(i, i + 100);
    const ph = chunk.map(() => '?').join(',');
    const rows = await db
      .prepare(
        `SELECT cve_id, GROUP_CONCAT(DISTINCT vendor) AS vendors
       FROM cpe WHERE cve_id IN (${ph})
       GROUP BY cve_id`,
      )
      .bind(...chunk)
      .all<VendorRow>();
    for (const row of rows.results) {
      map.set(row.cve_id, row.vendors ? row.vendors.split(',').filter(Boolean) : []);
    }
  }
  return map;
}

function buildVecFilter(filters?: SearchFilters): VecFilter | undefined {
  if (!filters) return undefined;
  const f: VecFilter = {};
  if (filters.severity?.length) f.severity = { $in: filters.severity };
  if (filters.kev === true) f.kev_listed = { $eq: 1 };
  if (filters.minCvss !== undefined) f.cvss_base = { $gte: filters.minCvss };
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
