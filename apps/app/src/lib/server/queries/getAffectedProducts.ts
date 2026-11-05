import type {
  AffectedProductRow,
  AffectedProductsRequest,
  AffectedProductsResponse,
} from '@threat-lens/contracts';

interface DbRow {
  vendor: string;
  product: string;
  cve_count: number;
  affected_version_count: number;
  kev_count: number;
  latest_cve_id: string;
  latest_published_at: number;
  max_cvss_base: number | null;
  max_severity_rank: number;
}

export async function getAffectedProducts(
  req: AffectedProductsRequest,
  db: D1Database,
): Promise<AffectedProductsResponse> {
  const limit = req.limit ?? 50;

  // Decode cursor: base64("vendor\x00product")
  let cursorVendor: string | null = null;
  let cursorProduct: string | null = null;
  if (req.cursor) {
    try {
      const decoded = atob(req.cursor);
      const sep = decoded.indexOf('\x00');
      if (sep >= 0) {
        cursorVendor = decoded.slice(0, sep);
        cursorProduct = decoded.slice(sep + 1);
      }
    } catch {
      // Invalid cursor — treat as no cursor.
    }
  }

  const whereFragments: string[] = [];
  const bindings: unknown[] = [];

  if (req.vendor) {
    whereFragments.push('p.vendor = ?');
    bindings.push(req.vendor);
  }
  if (req.product) {
    whereFragments.push('p.product = ?');
    bindings.push(req.product);
  }
  if (req.minCvss !== undefined) {
    whereFragments.push('c.cvss_base >= ?');
    bindings.push(req.minCvss);
  }
  if (cursorVendor !== null && cursorProduct !== null) {
    whereFragments.push('(p.vendor > ? OR (p.vendor = ? AND p.product > ?))');
    bindings.push(cursorVendor, cursorVendor, cursorProduct);
  }

  const whereClause = whereFragments.length > 0 ? `WHERE ${whereFragments.join(' AND ')}` : '';

  // Fetch limit+1 to detect if there's a next page.
  bindings.push(limit + 1);

  // Accuracy fixes over the old query:
  //  - latest_cve_id: SQLite's "bare column alongside a MAX() aggregate"
  //    returns the value from the row that held the max — so `c.cve_id`
  //    paired with `MAX(c.published_at)` is the most-recently-PUBLISHED CVE,
  //    not MAX(c.cve_id)'s lexicographically-greatest id (the old bug).
  //  - max severity: ranked numerically (CRITICAL=5 … NONE=1) then mapped
  //    back, instead of MAX(text) where 'NONE' > 'CRITICAL' lexicographically.
  //  - affected_version_count: distinct explicit CPE versions.
  //  - kev_count: distinct KEV-listed CVEs (LEFT JOIN cve_state; counted via
  //    COUNT(DISTINCT CASE …) so the join fan-out doesn't inflate it).
  const result = await db
    .prepare(
      `SELECT p.vendor, p.product,
            COUNT(DISTINCT p.cve_id)                                              AS cve_count,
            COUNT(DISTINCT CASE WHEN p.version IS NOT NULL
                                 AND p.version != '*' THEN p.version END)         AS affected_version_count,
            COUNT(DISTINCT CASE WHEN s.kev_listed = 1 THEN p.cve_id END)          AS kev_count,
            c.cve_id                                                              AS latest_cve_id,
            MAX(c.published_at)                                                   AS latest_published_at,
            MAX(c.cvss_base)                                                      AS max_cvss_base,
            MAX(CASE c.severity
                  WHEN 'CRITICAL' THEN 5 WHEN 'HIGH' THEN 4 WHEN 'MEDIUM' THEN 3
                  WHEN 'LOW' THEN 2 WHEN 'NONE' THEN 1 ELSE 0 END)                AS max_severity_rank
     FROM cpe p
     JOIN cve c USING (cve_id)
     LEFT JOIN cve_state s ON s.cve_id = p.cve_id
     ${whereClause}
     GROUP BY p.vendor, p.product
     ORDER BY p.vendor ASC, p.product ASC
     LIMIT ?`,
    )
    .bind(...bindings)
    .all<DbRow>();

  const rows = result.results;
  const hasMore = rows.length > limit;
  const pageRows = hasMore ? rows.slice(0, limit) : rows;

  const RANK_TO_SEVERITY: Record<number, AffectedProductRow['maxSeverity']> = {
    5: 'CRITICAL',
    4: 'HIGH',
    3: 'MEDIUM',
    2: 'LOW',
    1: 'NONE',
  };

  const mapped: AffectedProductRow[] = pageRows.map((row) => ({
    vendor: row.vendor,
    product: row.product,
    cveCount: row.cve_count,
    affectedVersionCount: row.affected_version_count,
    kevCount: row.kev_count,
    latestCveId: row.latest_cve_id,
    latestPublishedAt: new Date(row.latest_published_at).toISOString(),
    maxCvssBase: row.max_cvss_base,
    maxSeverity: RANK_TO_SEVERITY[row.max_severity_rank] ?? null,
  }));

  let nextCursor: string | null = null;
  if (hasMore) {
    const last = pageRows[pageRows.length - 1];
    if (last) nextCursor = btoa(`${last.vendor}\x00${last.product}`);
  }

  return { rows: mapped, nextCursor };
}
