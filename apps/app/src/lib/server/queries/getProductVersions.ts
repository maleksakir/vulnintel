import type {
  AffectedVersionRow,
  AffectedVersionsResponse,
  Severity,
} from '@threat-lens/contracts';

// Vendor → Product → Version drill-down. Given a vendor+product, group that
// product's CPE rows into distinct affected "versions", where a version is
// either a discrete `version` string OR a reconstructed range from the four
// version_start/end bound columns (NVD expresses many affected sets as ranges
// with version NULL/'*'). Each group aggregates its CVE count, KEV count, max
// severity/CVSS, and a few sample CVE ids — the accurate
// vendor/product/version/CVE structure a researcher needs.

interface CpeVersionRow {
  version: string | null;
  vsi: string | null; // version_start_including
  vse: string | null; // version_start_excluding
  vei: string | null; // version_end_including
  vee: string | null; // version_end_excluding
  part: string | null;
  cve_id: string;
  severity: string;
  cvss_base: number | null;
  published_at: number;
  kev_listed: number | null;
}

const SEVERITY_RANK: Record<string, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  NONE: 1,
};
const RANK_TO_SEVERITY: Record<number, Severity | null> = {
  5: 'CRITICAL',
  4: 'HIGH',
  3: 'MEDIUM',
  2: 'LOW',
  1: 'NONE',
};

/** Reconstruct a human range summary from the four bound columns. Returns null
 *  when no bounds are present (a bare version row). */
function rangeSummary(r: CpeVersionRow): string | null {
  const parts: string[] = [];
  if (r.vsi) parts.push(`>=${r.vsi}`);
  if (r.vse) parts.push(`>${r.vse}`);
  if (r.vei) parts.push(`<=${r.vei}`);
  if (r.vee) parts.push(`<${r.vee}`);
  return parts.length > 0 ? parts.join(' ') : null;
}

interface Group {
  version: string | null;
  rangeSummary: string | null;
  part: 'a' | 'o' | 'h' | null;
  cves: Set<string>;
  kevCves: Set<string>;
  maxRank: number;
  maxCvss: number | null;
  // cveId → published_at, for picking the most-recent samples.
  sample: Map<string, number>;
}

const MAX_CPE_ROWS = 20_000; // hard ceiling for one product's CPE scan
const MAX_SAMPLE = 5;

export async function getProductVersions(
  db: D1Database,
  vendor: string,
  product: string,
): Promise<AffectedVersionsResponse> {
  const { results } = await db
    .prepare(
      `SELECT p.version, p.version_start_including AS vsi, p.version_start_excluding AS vse,
              p.version_end_including AS vei, p.version_end_excluding AS vee, p.part,
              p.cve_id, c.severity, c.cvss_base, c.published_at,
              COALESCE(s.kev_listed, 0) AS kev_listed
       FROM cpe p
       JOIN cve c ON c.cve_id = p.cve_id
       LEFT JOIN cve_state s ON s.cve_id = p.cve_id
       WHERE p.vendor = ? AND p.product = ?
       LIMIT ?`,
    )
    .bind(vendor, product, MAX_CPE_ROWS)
    .all<CpeVersionRow>();

  // Group key: discrete version, else the range summary, else '*' (any).
  const groups = new Map<string, Group>();
  for (const r of results) {
    const range = rangeSummary(r);
    const discrete = r.version && r.version !== '*' ? r.version : null;
    // A row with neither a discrete version nor bounds affects all versions.
    const key = discrete ?? range ?? '*';

    let g = groups.get(key);
    if (!g) {
      g = {
        version: discrete,
        rangeSummary: range,
        part: (r.part as Group['part']) ?? null,
        cves: new Set(),
        kevCves: new Set(),
        maxRank: 0,
        maxCvss: null,
        sample: new Map(),
      };
      groups.set(key, g);
    }
    g.cves.add(r.cve_id);
    if (r.kev_listed === 1) g.kevCves.add(r.cve_id);
    const rank = SEVERITY_RANK[r.severity] ?? 0;
    if (rank > g.maxRank) g.maxRank = rank;
    if (r.cvss_base !== null && (g.maxCvss === null || r.cvss_base > g.maxCvss)) {
      g.maxCvss = r.cvss_base;
    }
    if (!g.sample.has(r.cve_id)) g.sample.set(r.cve_id, r.published_at);
  }

  const versions: AffectedVersionRow[] = [...groups.values()]
    .map((g) => {
      const sampleCveIds = [...g.sample.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, MAX_SAMPLE)
        .map(([id]) => id);
      return {
        version: g.version,
        rangeSummary: g.rangeSummary,
        part: g.part,
        cveCount: g.cves.size,
        kevCount: g.kevCves.size,
        maxCvssBase: g.maxCvss,
        maxSeverity: RANK_TO_SEVERITY[g.maxRank] ?? null,
        sampleCveIds,
      };
    })
    // Most severe first, then most CVEs, then version/range label.
    .sort((a, b) => {
      const ar = a.maxSeverity ? (SEVERITY_RANK[a.maxSeverity] ?? 0) : 0;
      const br = b.maxSeverity ? (SEVERITY_RANK[b.maxSeverity] ?? 0) : 0;
      if (ar !== br) return br - ar;
      if (a.cveCount !== b.cveCount) return b.cveCount - a.cveCount;
      return (a.version ?? a.rangeSummary ?? '*').localeCompare(b.version ?? b.rangeSummary ?? '*');
    });

  return { vendor, product, versions };
}
