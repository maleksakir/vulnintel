import type {
  AffectedProductRow,
  AffectedProductsRequest,
  AffectedProductsResponse,
} from '@threat-lens/contracts';

interface DbRow {
  vendor: string;
  product: string;
  cve_count: number;
  latest_cve_id: string;
  latest_published_at: number;
  max_cvss_base: number | null;
  max_severity: string;
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

  const whereClause = whereFragments.length > 0 ? 'WHERE ' + whereFragments.join(' AND ') : '';

  // Fetch limit+1 to detect if there's a next page.
  bindings.push(limit + 1);

  const result = await db
    .prepare(
      `SELECT p.vendor, p.product,
            COUNT(DISTINCT p.cve_id)           AS cve_count,
            MAX(c.cve_id)                      AS latest_cve_id,
            MAX(c.published_at)                AS latest_published_at,
            MAX(c.cvss_base)                   AS max_cvss_base,
            MAX(c.severity)                    AS max_severity
     FROM cpe p
     JOIN cve c USING (cve_id)
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

  const mapped: AffectedProductRow[] = pageRows.map((row) => ({
    vendor: row.vendor,
    product: row.product,
    versionRange: '*',
    cveCount: row.cve_count,
    latestCveId: row.latest_cve_id,
    latestPublishedAt: new Date(row.latest_published_at).toISOString(),
    maxSeverity: row.max_severity as AffectedProductRow['maxSeverity'],
  }));

  let nextCursor: string | null = null;
  if (hasMore) {
    const last = pageRows[pageRows.length - 1];
    if (last) nextCursor = btoa(`${last.vendor}\x00${last.product}`);
  }

  return { rows: mapped, nextCursor };
}
