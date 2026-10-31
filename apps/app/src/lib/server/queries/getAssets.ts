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
  max_severity: string | null;
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
              MAX(c.severity)                                  AS max_severity,
              MAX(COALESCE(s.kev_listed, 0))                   AS has_kev
       FROM asset_component ac
       LEFT JOIN asset_component_match m ON m.component_id = ac.component_id
       LEFT JOIN cve c ON c.cve_id = m.cve_id
       LEFT JOIN cve_state s ON s.cve_id = m.cve_id
       WHERE ac.asset_id = ?
       GROUP BY ac.component_id
       ORDER BY cve_count DESC, ac.name ASC`,
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
    maxSeverity: (c.max_severity as AssetComponentRow['maxSeverity']) ?? null,
    hasKev: c.has_kev === 1,
  }));

  // Matched CVEs across all components, deduped to the highest-signal row per
  // CVE, severity-ranked. Cursor = offset (simple + stable for a bounded set).
  const offset = opts.cveCursor ? Math.max(0, Number.parseInt(atob(opts.cveCursor), 10) || 0) : 0;

  const cveRes = await db
    .prepare(
      `SELECT m.cve_id, m.match_via, c.severity, c.cvss_base,
              s.kev_listed, s.epss_percentile,
              ac.name AS component_name, ac.version AS component_version
       FROM asset_component_match m
       JOIN asset_component ac ON ac.component_id = m.component_id
       LEFT JOIN cve c ON c.cve_id = m.cve_id
       LEFT JOIN cve_state s ON s.cve_id = m.cve_id
       WHERE ac.asset_id = ?
       GROUP BY m.cve_id
       ORDER BY
         CASE c.severity
           WHEN 'CRITICAL' THEN 5 WHEN 'HIGH' THEN 4 WHEN 'MEDIUM' THEN 3
           WHEN 'LOW' THEN 2 WHEN 'NONE' THEN 1 ELSE 0 END DESC,
         c.cvss_base DESC,
         m.cve_id ASC
       LIMIT ? OFFSET ?`,
    )
    .bind(assetId, limit + 1, offset)
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
