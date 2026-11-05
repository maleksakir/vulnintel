/**
 * Standalone SBOM-scan contracts. Shared between the app worker (API + UI).
 *
 * The scan is STATELESS: a user uploads a CycloneDX SBOM, the server parses it
 * and matches each component against already-ingested vulnerability data
 * (OSV/GHSA package ranges via `cve_osv_affected`, and NVD CPE vendor/product
 * via `cpe`), and returns the affected components + their CVEs in the
 * response. Nothing is persisted — no asset ownership, no inventory, no login.
 *
 * TYPE-ONLY — no runtime code.
 */

/** How a component was linked to a CVE. */
export type SbomMatchVia = 'PURL' | 'CPE';

/** A parsed SBOM component ready to match. */
export interface SbomComponentInput {
  name: string;
  version: string | null;
  purl: string | null;
  ecosystem: string | null;
  cpeVendor: string | null;
  cpeProduct: string | null;
}

/** One CVE matched to a component in a scan. */
export interface SbomCveMatch {
  cveId: string;
  matchVia: SbomMatchVia;
  severity: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | null;
  cvssBase: number | null;
  kevListed: boolean;
  epssPercentile: number | null;
  /** Public exploit maturity if any, from cve_exploit_reference rollup. */
  exploitMaturity: 'weaponized' | 'poc' | 'detection' | null;
}

/** A single SBOM component with the CVEs it matched. */
export interface SbomComponentResult {
  name: string;
  version: string | null;
  purl: string | null;
  ecosystem: string | null;
  /** Highest severity across matched CVEs (null if none / no data). */
  maxSeverity: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | null;
  /** Whether any matched CVE is KEV-listed. */
  hasKev: boolean;
  cves: SbomCveMatch[];
}

/** POST /api/sbom/scan — the full scan result. */
export interface SbomScanResponse {
  /** Components parsed from the SBOM (capped). */
  componentsScanned: number;
  /** Components present but unusable (no name), or beyond the cap. */
  componentsSkipped: number;
  /** Components that matched at least one CVE. */
  vulnerableComponents: number;
  /** Distinct CVEs across all components. */
  totalCves: number;
  /** Per-component results, vulnerable components first. */
  components: SbomComponentResult[];
  /** True when the match set hit the per-request cap (results truncated). */
  truncated: boolean;
}
