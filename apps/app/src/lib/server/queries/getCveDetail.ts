import type {
  CpeRow,
  CveDetailResponse,
  ExploitMaturity,
  ExploitReference,
  OsvAffectedPackageRow,
  SsvcBlock,
} from '@threat-lens/contracts';

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
  ssvc_exploitation: string | null;
  ssvc_automatable: string | null;
  ssvc_technical_impact: string | null;
  ssvc_updated_at: number | null;
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
  const [cveResult, cweResult, cpeResult, refResult, osvResult, srcResult] = await db.batch([
    db
      .prepare(
        `SELECT c.cve_id, c.published_at, c.last_modified_at, c.description,
              c.severity, c.cvss_version, c.cvss_vector, c.cvss_base,
              c.cvss_exploitability, c.cvss_impact,
              s.kev_listed, s.kev_date_added, s.kev_due_date, s.kev_required_action,
              s.epss_score, s.epss_percentile, s.epss_updated_at,
              s.ssvc_exploitation, s.ssvc_automatable, s.ssvc_technical_impact, s.ssvc_updated_at
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
    db
      .prepare(
        `SELECT ecosystem, package_name, purl, ranges_json, fixed_versions
       FROM cve_osv_affected WHERE cve_id = ? ORDER BY ecosystem, package_name LIMIT 100`,
      )
      .bind(cveId),
    db
      .prepare(
        `SELECT source, last_seen_at FROM cve_source_provenance
       WHERE cve_id = ? ORDER BY last_seen_at DESC`,
      )
      .bind(cveId),
  ]);

  const row = (cveResult as D1Result<CveRow>).results[0];
  if (!row) return null;

  // Exploit references (migration 0015). Read separately, not in the batch
  // above, so a database where 0015 hasn't applied yet still returns the CVE
  // detail instead of failing the whole batch on a missing table.
  const { exploits, exploitMaturity } = await getExploitRefs(db, cveId);

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

  const osvPackages: OsvAffectedPackageRow[] = (osvResult as D1Result<OsvDbRow>).results.map(
    (o) => ({
      ecosystem: o.ecosystem,
      packageName: o.package_name,
      purl: o.purl,
      fixedVersions: o.fixed_versions,
      rangeSummary: summarizeOsvRanges(o.ranges_json),
    }),
  );

  const sources = (srcResult as D1Result<ProvenanceDbRow>).results.map((s) => ({
    source: s.source,
    lastSeenAt: new Date(s.last_seen_at).toISOString(),
  }));

  // SSVC: present only when NVD's CISA-ADP decision was parsed (any of the
  // three points non-null). ssvc_updated_at alone doesn't count as "has SSVC".
  const ssvc: SsvcBlock | null =
    row.ssvc_exploitation !== null ||
    row.ssvc_automatable !== null ||
    row.ssvc_technical_impact !== null
      ? {
          exploitation: (row.ssvc_exploitation as SsvcBlock['exploitation']) ?? null,
          automatable: (row.ssvc_automatable as SsvcBlock['automatable']) ?? null,
          technicalImpact: (row.ssvc_technical_impact as SsvcBlock['technicalImpact']) ?? null,
          decidedAt:
            row.ssvc_updated_at !== null ? new Date(row.ssvc_updated_at).toISOString() : null,
        }
      : null;

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
    ssvc,
    cwes,
    cpes,
    osvPackages,
    references: refs,
    sources,
    exploits,
    exploitMaturity,
  };
}

interface OsvDbRow {
  ecosystem: string;
  package_name: string;
  purl: string | null;
  ranges_json: string;
  fixed_versions: string | null;
}

interface ProvenanceDbRow {
  source: string;
  last_seen_at: number;
}

/**
 * Turn OSV's `ranges_json` into a short human range summary like
 * ">=1.0.0 <1.4.2" (or ">=1.0.0" / "<1.4.2"). OSV stores an array of range
 * objects, each with `events` (introduced/fixed/last_affected). We render the
 * FIRST range's introduced→fixed/last_affected bound, which covers the common
 * single-range case; multi-range records fall back to showing the first.
 * Returns null when nothing expressible is found (parse-tolerant).
 */
function summarizeOsvRanges(rangesJson: string): string | null {
  try {
    const ranges = JSON.parse(rangesJson) as Array<{
      events?: Array<Record<string, string>>;
    }>;
    if (!Array.isArray(ranges) || ranges.length === 0) return null;
    const events = ranges[0]?.events;
    if (!Array.isArray(events)) return null;
    let introduced: string | null = null;
    let fixed: string | null = null;
    let lastAffected: string | null = null;
    for (const e of events) {
      if (typeof e.introduced === 'string' && e.introduced !== '0') introduced = e.introduced;
      if (typeof e.fixed === 'string') fixed = e.fixed;
      if (typeof e.last_affected === 'string') lastAffected = e.last_affected;
    }
    const parts: string[] = [];
    if (introduced) parts.push(`>=${introduced}`);
    if (fixed) parts.push(`<${fixed}`);
    else if (lastAffected) parts.push(`<=${lastAffected}`);
    return parts.length > 0 ? parts.join(' ') : null;
  } catch {
    return null;
  }
}

interface ExploitRefDbRow {
  source: string;
  external_id: string;
  title: string | null;
  url: string | null;
  maturity: string;
  published_at: number | null;
}

const EXPLOIT_MATURITY_RANK: Record<ExploitMaturity, number> = {
  weaponized: 3,
  poc: 2,
  detection: 1,
};

/**
 * Fetch a CVE's public exploit references + the single highest-maturity level.
 * Degrades to empty if migration 0015's table doesn't exist yet (so a
 * deploy-ahead-of-migration serves CVE detail without the exploit panel rather
 * than 500ing) — same tolerance as the app's other read paths.
 */
async function getExploitRefs(
  db: D1Database,
  cveId: string,
): Promise<{ exploits: ExploitReference[]; exploitMaturity: ExploitMaturity | null }> {
  try {
    const res = await db
      .prepare(
        `SELECT source, external_id, title, url, maturity, published_at
         FROM cve_exploit_reference WHERE cve_id = ?
         ORDER BY CASE maturity WHEN 'weaponized' THEN 0 WHEN 'poc' THEN 1 ELSE 2 END,
                  published_at DESC
         LIMIT 50`,
      )
      .bind(cveId)
      .all<ExploitRefDbRow>();

    const exploits: ExploitReference[] = res.results.map((r) => ({
      cveId,
      source: r.source as ExploitReference['source'],
      externalId: r.external_id,
      title: r.title,
      url: r.url,
      maturity: r.maturity as ExploitMaturity,
      publishedAt: r.published_at,
    }));

    let maturity: ExploitMaturity | null = null;
    for (const e of exploits) {
      if (
        maturity === null ||
        EXPLOIT_MATURITY_RANK[e.maturity] > EXPLOIT_MATURITY_RANK[maturity]
      ) {
        maturity = e.maturity;
      }
    }
    return { exploits, exploitMaturity: maturity };
  } catch {
    return { exploits: [], exploitMaturity: null };
  }
}
