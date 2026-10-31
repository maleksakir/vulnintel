import type {
  AssetComponentRow,
  AssetCveRow,
  AssetDetailResponse,
  AssetListResponse,
  AssetMatchVia,
  AssetSummary,
} from '@threat-lens/contracts';

// Asset read-side queries. Reads materialized asset_component_match rows
// (populated at import time) joined to cve/cve_state — cheap indexed reads,
// never the matching scan (that cost is at import time, by design).

const CVE_PAGE_SIZE = 100;

// Matches MAX_SBOM_COMPONENTS in lib/server/sbom.ts — an import can't store
// more than this, so the LIMIT only ever bites if that cap is raised without
// revisiting the read side. Without it, the component aggregate below is an
// unbounded per-pageview scan (security review 2026-10-31, finding #4).
const COMPONENT_LIMIT = 500;

const SEVERITY_BY_RANK = ['NONE', 'NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;

// Rank severities numerically in SQL. `MAX(c.severity)` sorts
// lexicographically, so a component with CRITICAL and NONE CVEs reported
// "NONE" (review finding #5) — 'NONE' > 'CRITICAL' as text.
const SEVERITY_RANK_SQL = `CASE c.severity
           WHEN 'CRITICAL' THEN 5 WHEN 'HIGH' THEN 4 WHEN 'MEDIUM' THEN 3
           WHEN 'LOW' THEN 2 WHEN 'NONE' THEN 1 ELSE 0 END`;

/**
 * Cursors are an opaque base64 offset. A hand-edited or truncated `?cursor=`
 * makes `atob` throw, which on an SSR route is a 500 — decode defensively and
 * fall back to the first page (review finding #11).
 */
function decodeCursor(cursor: string | undefined): number {
  if (!cursor) return 0;
  try {
    return Math.max(0, Number.parseInt(atob(cursor), 10) || 0);
  } catch {
    return 0;
  }
}

interface AssetRow {
  asset_id: number;
  name: string;
  description: string | null;
  created_at: number;
  updated_at: number;
  last_import_at: number | null;
  last_component_count: number;
}

interface ComponentRow {
  component_id: number;
  name: string;
  version: string | null;
  purl: string | null;
  ecosystem: string | null;
  cve_count: number;
  max_severity_rank: number | null;
  has_kev: number;
}

interface CveMatchRow {
  cve_id: string;
  match_via: AssetMatchVia;
  severity: string | null;
  cvss_base: number | null;
  kev_listed: number | null;
  epss_percentile: number | null;
  component_name: string;
  component_version: string | null;
  risk_accepted: number;
}

/**
 * KV-cached list response. The second statement in getAssets() is an
 * unfiltered GROUP BY over the whole asset_component_match join — the exact
 * uncached-aggregate-per-pageview shape that burned the 5M/day D1 read quota
 * in ~7 hours on 2026-10-29 (CLAUDE.md, `d7033cf`). Asset matches only change
 * when an operator imports or deletes, so every mutation route deletes this
 * key explicitly (`invalidateAssetsList`) and the TTL is just a backstop —
 * long enough that a key hammered continuously still costs ~1.4k KV writes/day
 * against the 1k/day cap only in the absurd case, and realistically a handful.
 */
export const ASSETS_LIST_CACHE_KEY = 'assets:list';
export const ASSETS_LIST_TTL = 60;

/** Drop the cached asset list after any import/create/delete. */
export async function invalidateAssetsList(cache: KVNamespace | undefined): Promise<void> {
  if (!cache) return;
  await cache.delete(ASSETS_LIST_CACHE_KEY);
}

/** GET /api/assets — all assets with component + vulnerability counts. */
export async function getAssets(db: D1Database): Promise<AssetListResponse> {
  const [assetRes, matchRes] = await db.batch([
    db.prepare(
      `SELECT asset_id, name, description, created_at, updated_at,
              last_import_at, last_component_count
       FROM asset ORDER BY created_at ASC`,
    ),
    // Per asset: distinct vulnerable CVEs + distinct vulnerable components.
    db.prepare(
      `SELECT ac.asset_id,
              COUNT(DISTINCT m.cve_id)       AS vuln_cves,
              COUNT(DISTINCT m.component_id) AS vuln_components
       FROM asset_component_match m
       JOIN asset_component ac ON ac.component_id = m.component_id
       GROUP BY ac.asset_id`,
    ),
  ]);

  const vulnByAsset = new Map<number, { cves: number; components: number }>();
  for (const r of (
    matchRes as D1Result<{ asset_id: number; vuln_cves: number; vuln_components: number }>
  ).results) {
    vulnByAsset.set(r.asset_id, { cves: r.vuln_cves, components: r.vuln_components });
  }

  const assets: AssetSummary[] = (assetRes as D1Result<AssetRow>).results.map((a) => {
    const v = vulnByAsset.get(a.asset_id);
    return {
      assetId: a.asset_id,
      name: a.name,
      description: a.description,
      createdAt: new Date(a.created_at).toISOString(),
      updatedAt: new Date(a.updated_at).toISOString(),
      lastImportAt: a.last_import_at !== null ? new Date(a.last_import_at).toISOString() : null,
      componentCount: a.last_component_count,
      vulnerableCveCount: v?.cves ?? 0,
      vulnerableComponentCount: v?.components ?? 0,
    };
  });

  return { assets };
}

/** GET /api/assets/[id] — components + a page of matched CVEs (highest
 *  severity first, then CVSS). Returns null if the asset doesn't exist. */
export async function getAssetDetail(
  db: D1Database,
  assetId: number,
  opts: { cveCursor?: string; limit?: number } = {},
): Promise<AssetDetailResponse | null> {
  const limit = Math.min(opts.limit ?? CVE_PAGE_SIZE, CVE_PAGE_SIZE);

  const asset = await db
    .prepare(
      `SELECT asset_id, name, description, created_at, updated_at,
              last_import_at, last_component_count
       FROM asset WHERE asset_id = ?`,
    )
    .bind(assetId)
    .first<AssetRow>();
  if (!asset) return null;

  // Components with per-component CVE match summary.
  const compRes = await db
    .prepare(
      `SELECT ac.component_id, ac.name, ac.version, ac.purl, ac.ecosystem,
              COUNT(DISTINCT m.cve_id)                         AS cve_count,
              MAX(${SEVERITY_RANK_SQL})                        AS max_severity_rank,
              MAX(COALESCE(s.kev_listed, 0))                   AS has_kev
       FROM asset_component ac
       LEFT JOIN asset_component_match m ON m.component_id = ac.component_id
       LEFT JOIN cve c ON c.cve_id = m.cve_id
       LEFT JOIN cve_state s ON s.cve_id = m.cve_id
       WHERE ac.asset_id = ?
       GROUP BY ac.component_id
       ORDER BY cve_count DESC, ac.name ASC
       LIMIT ${COMPONENT_LIMIT}`,
    )
    .bind(assetId)
    .all<ComponentRow>();

  const components: AssetComponentRow[] = compRes.results.map((c) => ({
    componentId: c.component_id,
    name: c.name,
    version: c.version,
    purl: c.purl,
    ecosystem: c.ecosystem,
    cveCount: c.cve_count,
    // Rank 0 means "matched a CVE whose severity we don't know" and null/no
    // matches means no severity at all — both render as null, not 'NONE'.
    maxSeverity:
      c.cve_count > 0 && c.max_severity_rank !== null && c.max_severity_rank > 0
        ? (SEVERITY_BY_RANK[c.max_severity_rank] as AssetComponentRow['maxSeverity'])
        : null,
    hasKev: c.has_kev === 1,
  }));

  // Matched CVEs across all components, deduped to the highest-signal row per
  // CVE, severity-ranked. Cursor = offset (simple + stable for a bounded set).
  const offset = decodeCursor(opts.cveCursor);

  // Risk-accepted CVEs sort LAST, not just render dimmed. Accepting a risk is
  // a decision to stop looking at something; if a CRITICAL under an active
  // acceptance still occupies the top of page 1, the acceptance changed a
  // label and nothing else, and the list stays as noisy as it was (review
  // finding #12). The join makes the demotion part of the ordering, so it
  // survives pagination — sorting the page in memory could not.
  const cveRes = await db
    .prepare(
      `SELECT m.cve_id, m.match_via, c.severity, c.cvss_base,
              s.kev_listed, s.epss_percentile,
              ac.name AS component_name, ac.version AS component_version,
              CASE WHEN ra.cve_id IS NULL THEN 0 ELSE 1 END AS risk_accepted
       FROM asset_component_match m
       JOIN asset_component ac ON ac.component_id = m.component_id
       LEFT JOIN cve c ON c.cve_id = m.cve_id
       LEFT JOIN cve_state s ON s.cve_id = m.cve_id
       LEFT JOIN cve_risk_acceptance ra
              ON ra.cve_id = m.cve_id AND ra.expires_at > ?
       WHERE ac.asset_id = ?
       GROUP BY m.cve_id
       ORDER BY
         risk_accepted ASC,
         ${SEVERITY_RANK_SQL} DESC,
         c.cvss_base DESC,
         m.cve_id ASC
       LIMIT ? OFFSET ?`,
    )
    .bind(Date.now(), assetId, limit + 1, offset)
    .all<CveMatchRow>();

  const rows = cveRes.results;
  const hasMore = rows.length > limit;
  const page = hasMore ? rows.slice(0, limit) : rows;

  const cves: AssetCveRow[] = page.map((r) => ({
    cveId: r.cve_id,
    matchVia: r.match_via,
    severity: (r.severity as AssetCveRow['severity']) ?? null,
    cvssBase: r.cvss_base,
    kevListed: r.kev_listed === 1,
    epssPercentile: r.epss_percentile,
    componentName: r.component_name,
    componentVersion: r.component_version,
    // From the ordering join above — no separate acceptance read needed.
    riskAccepted: r.risk_accepted === 1,
  }));

  const cveCursor = hasMore ? btoa(String(offset + limit)) : null;

  return {
    assetId: asset.asset_id,
    name: asset.name,
    description: asset.description,
    createdAt: new Date(asset.created_at).toISOString(),
    updatedAt: new Date(asset.updated_at).toISOString(),
    lastImportAt:
      asset.last_import_at !== null ? new Date(asset.last_import_at).toISOString() : null,
    componentCount: asset.last_component_count,
    components,
    cves,
    cveCursor,
  };
}
