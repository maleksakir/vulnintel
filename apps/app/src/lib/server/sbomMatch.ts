import type {
  SbomComponentInput,
  SbomComponentResult,
  SbomCveMatch,
  SbomScanResponse,
} from '@threat-lens/contracts';
import { osvPackageName, parsePurl } from './sbom';

/**
 * Stateless SBOM → CVE matcher. Takes parsed CycloneDX components and matches
 * each against already-ingested vulnerability data, then enriches every
 * matched CVE with severity / CVSS / KEV / EPSS / exploit-maturity. NOTHING is
 * written — this is the read-only engine behind the public SBOM-scan tool
 * (POST /api/sbom/scan), with no asset ownership or persistence.
 *
 * Matching mirrors the (removed) asset-import engine:
 *   - PURL-primary: (ecosystem, OSV-shaped package name) against cve_osv_affected,
 *     excluding components already on a version OSV lists as fixed.
 *   - CPE fallback: (vendor, product) against the cpe table, ONLY for
 *     components that carried an explicit cpe and matched nothing via PURL.
 *
 * D1 query budget (bounded, set-based — never per-component):
 *   ≤5  reads  — PURL matching, chunked at 100 OSV package names per query
 *   ≤10 reads  — CPE fallback, chunked at 50 components (vendor+product sets)
 *   ≤5  reads  — CVE enrichment, chunked at 100 cve_ids per query
 *   ───────────────────────────────────────────────────────────────────────
 *   ~20 reads worst case at MAX_SBOM_COMPONENTS=500, independent of the
 *   component distribution — comfortably under the 50-query/invocation cap.
 */

// D1 binds at most 100 params per query.
const PARAM_CHUNK = 100;
// Half that for the CPE query, which binds a vendor set AND a product set.
const CPE_PAIR_CHUNK = 50;
// Per-component and whole-scan match ceilings — bound response size and work.
const MAX_MATCHES_PER_COMPONENT = 50;
const MAX_TOTAL_MATCHES = 5000;
// Bound the CPE fallback's result set per chunk.
const CPE_ROW_LIMIT = 5000;

const SEVERITY_RANK: Record<string, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  NONE: 1,
};

interface OsvAffectedRow {
  cve_id: string;
  ecosystem: string;
  package_name: string;
  fixed_versions: string | null;
}

interface CveEnrichRow {
  cve_id: string;
  severity: string | null;
  cvss_base: number | null;
  kev_listed: number | null;
  epss_percentile: number | null;
  exploit_maturity: string | null;
}

interface Candidate {
  /** Index into the input `components` array — the component's stable id here. */
  idx: number;
  version: string | null;
  osvEcosystem: string | null;
  osvName: string | null;
  cpeVendor: string | null;
  cpeProduct: string | null;
}

/** True when the component's exact version appears in OSV's comma-joined
 *  fixed_versions list. The cheap, correct-direction half of version
 *  awareness; full range evaluation (ranges_json) is not implemented, so a
 *  match means "this package is affected by this CVE", not "this exact
 *  version is" — the UI labels matches accordingly. */
function isFixedVersion(version: string | null, fixedVersions: string | null): boolean {
  if (version === null || fixedVersions === null) return false;
  return fixedVersions
    .split(',')
    .map((v) => v.trim())
    .some((v) => v.length > 0 && v === version);
}

export async function scanSbom(
  db: D1Database,
  components: SbomComponentInput[],
  skipped: number,
): Promise<SbomScanResponse> {
  // Derive each component's OSV match key from its purl at scan time.
  const candidates: Candidate[] = components.map((c, idx) => {
    const p = c.purl ? parsePurl(c.purl) : null;
    return {
      idx,
      version: c.version,
      osvEcosystem: c.ecosystem,
      osvName: p ? osvPackageName(p.ecosystem, p.namespace, p.name) : null,
      cpeVendor: c.cpeVendor,
      cpeProduct: c.cpeProduct,
    };
  });

  // matches: componentIdx → (cveId → matchVia)
  const perComponent = new Map<number, Map<string, 'PURL' | 'CPE'>>();
  let totalMatches = 0;
  let truncated = false;

  const take = (idx: number, cveId: string, via: 'PURL' | 'CPE'): void => {
    if (totalMatches >= MAX_TOTAL_MATCHES) {
      truncated = true;
      return;
    }
    let seen = perComponent.get(idx);
    if (!seen) {
      seen = new Map();
      perComponent.set(idx, seen);
    }
    if (seen.has(cveId)) return;
    if (seen.size >= MAX_MATCHES_PER_COMPONENT) {
      truncated = true;
      return;
    }
    seen.set(cveId, via);
    totalMatches++;
  };

  // ── 1. PURL-primary matching (set-based) ─────────────────────────────────
  const purlCandidates = candidates.filter((c) => c.osvName !== null && c.osvEcosystem !== null);
  const byOsvKey = new Map<string, Candidate[]>();
  for (const c of purlCandidates) {
    const key = `${c.osvEcosystem}\u0000${c.osvName}`;
    const list = byOsvKey.get(key);
    if (list) list.push(c);
    else byOsvKey.set(key, [c]);
  }
  const osvNames = [...new Set(purlCandidates.map((c) => c.osvName as string))];

  for (let i = 0; i < osvNames.length; i += PARAM_CHUNK) {
    const chunk = osvNames.slice(i, i + PARAM_CHUNK);
    const placeholders = chunk.map(() => '?').join(',');
    const res = await db
      .prepare(
        `SELECT cve_id, ecosystem, package_name, fixed_versions
         FROM cve_osv_affected WHERE package_name IN (${placeholders})`,
      )
      .bind(...chunk)
      .all<OsvAffectedRow>();

    for (const r of res.results) {
      const targets = byOsvKey.get(`${r.ecosystem}\u0000${r.package_name}`);
      if (!targets) continue; // name matched, different ecosystem
      for (const c of targets) {
        if (isFixedVersion(c.version, r.fixed_versions)) continue;
        take(c.idx, r.cve_id, 'PURL');
      }
    }
  }

  // ── 2. CPE fallback (set-based) ──────────────────────────────────────────
  // Only for components with an explicit cpe that matched nothing via PURL.
  const cpeCandidates = candidates.filter(
    (c) =>
      c.cpeVendor !== null && c.cpeProduct !== null && (perComponent.get(c.idx)?.size ?? 0) === 0,
  );
  const byCpePair = new Map<string, Candidate[]>();
  for (const c of cpeCandidates) {
    const key = `${c.cpeVendor}\u0000${c.cpeProduct}`;
    const list = byCpePair.get(key);
    if (list) list.push(c);
    else byCpePair.set(key, [c]);
  }

  for (let i = 0; i < cpeCandidates.length; i += CPE_PAIR_CHUNK) {
    const chunk = cpeCandidates.slice(i, i + CPE_PAIR_CHUNK);
    const vendors = [...new Set(chunk.map((c) => c.cpeVendor as string))];
    const products = [...new Set(chunk.map((c) => c.cpeProduct as string))];
    const vPlace = vendors.map(() => '?').join(',');
    const pPlace = products.map(() => '?').join(',');
    const res = await db
      .prepare(
        `SELECT DISTINCT cve_id, vendor, product FROM cpe
         WHERE vendor IN (${vPlace}) AND product IN (${pPlace})
         LIMIT ?`,
      )
      .bind(...vendors, ...products, CPE_ROW_LIMIT)
      .all<{ cve_id: string; vendor: string; product: string }>();

    for (const r of res.results) {
      const targets = byCpePair.get(`${r.vendor}\u0000${r.product}`);
      if (!targets) continue;
      for (const c of targets) take(c.idx, r.cve_id, 'CPE');
    }
  }

  // ── 3. Enrich every matched CVE (set-based, chunked) ─────────────────────
  const allCveIds = [...new Set([...perComponent.values()].flatMap((m) => [...m.keys()]))];
  const enrich = new Map<string, CveEnrichRow>();
  for (let i = 0; i < allCveIds.length; i += PARAM_CHUNK) {
    const chunk = allCveIds.slice(i, i + PARAM_CHUNK);
    const placeholders = chunk.map(() => '?').join(',');
    const res = await db
      .prepare(
        `SELECT c.cve_id, c.severity, c.cvss_base,
                s.kev_listed, s.epss_percentile, s.exploit_maturity
         FROM cve c LEFT JOIN cve_state s USING (cve_id)
         WHERE c.cve_id IN (${placeholders})`,
      )
      .bind(...chunk)
      .all<CveEnrichRow>();
    for (const r of res.results) enrich.set(r.cve_id, r);
  }

  // ── 4. Assemble per-component results, vulnerable first ──────────────────
  const results: SbomComponentResult[] = components.map((c, idx) => {
    const matched = perComponent.get(idx);
    const cves: SbomCveMatch[] = [];
    let maxRank = 0;
    let maxSeverity: SbomComponentResult['maxSeverity'] = null;
    let hasKev = false;

    if (matched) {
      for (const [cveId, via] of matched) {
        const e = enrich.get(cveId);
        const severity = (e?.severity as SbomCveMatch['severity']) ?? null;
        const kevListed = e?.kev_listed === 1;
        if (kevListed) hasKev = true;
        if (severity && (SEVERITY_RANK[severity] ?? 0) > maxRank) {
          maxRank = SEVERITY_RANK[severity] ?? 0;
          maxSeverity = severity;
        }
        cves.push({
          cveId,
          matchVia: via,
          severity,
          cvssBase: e?.cvss_base ?? null,
          kevListed,
          epssPercentile: e?.epss_percentile ?? null,
          exploitMaturity: (e?.exploit_maturity as SbomCveMatch['exploitMaturity']) ?? null,
        });
      }
      // Highest-severity CVE first within a component.
      cves.sort(
        (a, b) =>
          (SEVERITY_RANK[b.severity ?? 'NONE'] ?? 0) - (SEVERITY_RANK[a.severity ?? 'NONE'] ?? 0),
      );
    }

    return {
      name: c.name,
      version: c.version,
      purl: c.purl,
      ecosystem: c.ecosystem,
      maxSeverity,
      hasKev,
      cves,
    };
  });

  // Vulnerable components first, then by highest severity, then by name.
  results.sort((a, b) => {
    const av = a.cves.length > 0 ? 1 : 0;
    const bv = b.cves.length > 0 ? 1 : 0;
    if (av !== bv) return bv - av;
    const ar = a.maxSeverity ? (SEVERITY_RANK[a.maxSeverity] ?? 0) : 0;
    const br = b.maxSeverity ? (SEVERITY_RANK[b.maxSeverity] ?? 0) : 0;
    if (ar !== br) return br - ar;
    return a.name.localeCompare(b.name);
  });

  return {
    componentsScanned: components.length,
    componentsSkipped: skipped,
    vulnerableComponents: results.filter((r) => r.cves.length > 0).length,
    totalCves: allCveIds.length,
    components: results,
    truncated,
  };
}
