import type {
  EpssListResponse,
  EpssListRow,
  KevListResponse,
  KevListRow,
} from '@threat-lens/contracts';

interface KevDbRow {
  cve_id: string;
  severity: string;
  vendor: string | null;
  kev_date_added: number;
  kev_due_date: number | null;
  kev_required_action: string;
}

interface EpssDbRow {
  cve_id: string;
  severity: string;
  vendor: string | null;
  epss_score: number;
  epss_percentile: number;
  cvss_base: number | null;
}

export async function getKevList(
  db: D1Database,
  cursor?: string,
  limit = 100,
): Promise<KevListResponse> {
  let cursorMs: number | null = null;
  if (cursor) {
    try {
      cursorMs = parseInt(atob(cursor), 10);
    } catch {
      /* ignore */
    }
  }

  const bindings: unknown[] = [];
  let cursorFragment = '';
  if (cursorMs !== null) {
    cursorFragment = 'AND s.kev_date_added < ?';
    bindings.push(cursorMs);
  }
  bindings.push(limit + 1);

  const result = await db
    .prepare(
      `SELECT c.cve_id, c.severity,
            (SELECT vendor FROM cpe WHERE cve_id = c.cve_id LIMIT 1) AS vendor,
            s.kev_date_added, s.kev_due_date, s.kev_required_action
     FROM cve c
     JOIN cve_state s USING (cve_id)
     WHERE s.kev_listed = 1 ${cursorFragment}
     ORDER BY s.kev_date_added DESC
     LIMIT ?`,
    )
    .bind(...bindings)
    .all<KevDbRow>();

  const rows = result.results;
  const hasMore = rows.length > limit;
  const page = hasMore ? rows.slice(0, limit) : rows;

  const mapped: KevListRow[] = page.map((row) => ({
    cveId: row.cve_id,
    severity: row.severity as KevListRow['severity'],
    vendor: row.vendor ?? 'Unknown',
    kevDateAdded: new Date(row.kev_date_added).toISOString(),
    kevDueDate: row.kev_due_date !== null ? new Date(row.kev_due_date).toISOString() : null,
    kevRequiredAction: row.kev_required_action,
  }));

  let nextCursor: string | null = null;
  if (hasMore) {
    const last = page[page.length - 1];
    if (last) nextCursor = btoa(String(last.kev_date_added));
  }

  return { rows: mapped, nextCursor };
}

export async function getEpssList(
  db: D1Database,
  cursor?: string,
  limit = 200,
): Promise<EpssListResponse> {
  let cursorScore: number | null = null;
  if (cursor) {
    try {
      cursorScore = parseFloat(atob(cursor));
    } catch {
      /* ignore */
    }
  }

  const bindings: unknown[] = [];
  let cursorFragment = '';
  if (cursorScore !== null) {
    cursorFragment = 'AND s.epss_score < ?';
    bindings.push(cursorScore);
  }
  bindings.push(limit + 1);

  const result = await db
    .prepare(
      `SELECT c.cve_id, c.severity,
            (SELECT vendor FROM cpe WHERE cve_id = c.cve_id LIMIT 1) AS vendor,
            s.epss_score, s.epss_percentile, c.cvss_base
     FROM cve c
     JOIN cve_state s USING (cve_id)
     WHERE s.epss_score IS NOT NULL ${cursorFragment}
     ORDER BY s.epss_score DESC
     LIMIT ?`,
    )
    .bind(...bindings)
    .all<EpssDbRow>();

  const rows = result.results;
  const hasMore = rows.length > limit;
  const page = hasMore ? rows.slice(0, limit) : rows;

  const mapped: EpssListRow[] = page.map((row) => ({
    cveId: row.cve_id,
    severity: row.severity as EpssListRow['severity'],
    vendor: row.vendor ?? 'Unknown',
    epssScore: row.epss_score,
    epssPercentile: row.epss_percentile,
    cvssBase: row.cvss_base,
  }));

  let nextCursor: string | null = null;
  if (hasMore) {
    const last = page[page.length - 1];
    if (last) nextCursor = btoa(String(last.epss_score));
  }

  return { rows: mapped, nextCursor };
}
