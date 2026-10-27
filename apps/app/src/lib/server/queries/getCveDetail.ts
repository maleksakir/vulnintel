import type { CpeRow, CveDetailResponse } from '@threat-lens/contracts';

interface CveRow {
  cve_id: string;
  published_at: number;
  last_modified_at: number;
  description: string;
  severity: string;
  cvss_version: string | null;
  cvss_vector: string | null;
  cvss_base: number | null;
  cvss_exploitability: number | null;
  cvss_impact: number | null;
  kev_listed: number | null;
  kev_date_added: number | null;
  kev_due_date: number | null;
  kev_required_action: string | null;
  epss_score: number | null;
  epss_percentile: number | null;
  epss_updated_at: number | null;
}

interface CweRow {
  id: string;
  name: string | null;
  category: string | null;
}

interface CpeDbRow {
  cpe_uri: string;
  part: string | null;
  vendor: string;
  product: string;
  version: string | null;
  version_start_including: string | null;
  version_start_excluding: string | null;
  version_end_including: string | null;
  version_end_excluding: string | null;
  vulnerable: number;
}

interface RefRow {
  url: string;
  tags: string | null;
}

export async function getCveDetail(
  cveId: string,
  db: D1Database,
): Promise<CveDetailResponse | null> {
  const [cveResult, cweResult, cpeResult, refResult] = await db.batch([
    db
      .prepare(
        `SELECT c.cve_id, c.published_at, c.last_modified_at, c.description,
              c.severity, c.cvss_version, c.cvss_vector, c.cvss_base,
              c.cvss_exploitability, c.cvss_impact,
              s.kev_listed, s.kev_date_added, s.kev_due_date, s.kev_required_action,
              s.epss_score, s.epss_percentile, s.epss_updated_at
       FROM cve c LEFT JOIN cve_state s USING (cve_id)
       WHERE c.cve_id = ?`,
      )
      .bind(cveId),
    db
      .prepare(
        `SELECT w.cwe_id AS id, w.name, w.category
       FROM cve_cwe cc JOIN cwe w ON cc.cwe_id = w.cwe_id
       WHERE cc.cve_id = ?`,
      )
      .bind(cveId),
    db
      .prepare(
        `SELECT cpe_uri, part, vendor, product, version,
              version_start_including, version_start_excluding,
              version_end_including, version_end_excluding, vulnerable
       FROM cpe WHERE cve_id = ? ORDER BY cpe_row_id LIMIT 500`,
      )
      .bind(cveId),
    db.prepare(`SELECT url, tags FROM cve_reference WHERE cve_id = ? LIMIT 200`).bind(cveId),
  ]);

  const row = (cveResult as D1Result<CveRow>).results[0];
  if (!row) return null;

  const cwes = (cweResult as D1Result<CweRow>).results.map((w) => ({
    id: w.id,
    name: w.name ?? w.id,
    category: w.category,
  }));

  const cpes: CpeRow[] = (cpeResult as D1Result<CpeDbRow>).results.map((p) => ({
    cpeUri: p.cpe_uri,
    part: (p.part as CpeRow['part']) ?? null,
    vendor: p.vendor,
    product: p.product,
    version: p.version,
    versionStartIncluding: p.version_start_including,
    versionStartExcluding: p.version_start_excluding,
    versionEndIncluding: p.version_end_including,
    versionEndExcluding: p.version_end_excluding,
    vulnerable: p.vulnerable === 1,
  }));

  const refs = (refResult as D1Result<RefRow>).results.map((r) => ({
    url: r.url,
    tags: r.tags ? r.tags.split(',').filter(Boolean) : [],
  }));

  return {
    cveId: row.cve_id,
    publishedAt: new Date(row.published_at).toISOString(),
    lastModifiedAt: new Date(row.last_modified_at).toISOString(),
    description: row.description,
    severity: row.severity as CveDetailResponse['severity'],
    cvss:
      row.cvss_version && row.cvss_vector && row.cvss_base !== null
        ? {
            version: row.cvss_version as '3.1' | '4.0',
            vector: row.cvss_vector,
            base: row.cvss_base,
            exploitability: row.cvss_exploitability,
            impact: row.cvss_impact,
          }
        : null,
    state: {
      kevListed: row.kev_listed === 1,
      kevDateAdded: row.kev_date_added !== null ? new Date(row.kev_date_added).toISOString() : null,
      kevDueDate: row.kev_due_date !== null ? new Date(row.kev_due_date).toISOString() : null,
      kevRequiredAction: row.kev_required_action,
      epssScore: row.epss_score,
      epssPercentile: row.epss_percentile,
      epssUpdatedAt:
        row.epss_updated_at !== null ? new Date(row.epss_updated_at).toISOString() : null,
    },
    cwes,
    cpes,
    references: refs,
  };
}
