/**
 * Asset inventory + SBOM import contracts (Phase 4). Shared between the app
 * worker (API + UI). Backed by migrations/0011_assets.sql.
 *
 * TYPE-ONLY — no runtime code.
 *
 * Single-tenant by design (same as watchlists — see 0011's header).
 */

/** How a component was linked to a CVE. */
export type AssetMatchVia = 'PURL' | 'CPE';

/** A parsed SBOM component ready to store. */
export interface AssetComponentInput {
  name: string;
  version: string | null;
  purl: string | null;
  ecosystem: string | null;
  cpeVendor: string | null;
  cpeProduct: string | null;
}

/** A tracked asset in the inventory list (summary form). */
export interface AssetSummary {
  assetId: number;
  name: string;
  description: string | null;
  createdAt: string; // ISO 8601
  updatedAt: string; // ISO 8601
  lastImportAt: string | null; // ISO 8601
  componentCount: number;
  /** Number of distinct CVEs affecting this asset's components. */
  vulnerableCveCount: number;
  /** Number of components with at least one CVE match. */
  vulnerableComponentCount: number;
}

/** GET /api/assets */
export interface AssetListResponse {
  assets: AssetSummary[];
}

/** One component of an asset, with its CVE match summary. */
export interface AssetComponentRow {
  componentId: number;
  name: string;
  version: string | null;
  purl: string | null;
  ecosystem: string | null;
  /** Distinct CVEs matched to this component. */
  cveCount: number;
  /** Highest severity across matched CVEs (null if none / no data). */
  maxSeverity: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | null;
  /** Whether any matched CVE is KEV-listed. */
  hasKev: boolean;
}

/** One CVE matched to a component. */
export interface AssetCveRow {
  cveId: string;
  matchVia: AssetMatchVia;
  severity: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | null;
  cvssBase: number | null;
  kevListed: boolean;
  epssPercentile: number | null;
  componentName: string;
  componentVersion: string | null;
}

/** GET /api/assets/[id] — asset detail: components + a page of matched CVEs. */
export interface AssetDetailResponse {
  assetId: number;
  name: string;
  description: string | null;
  createdAt: string; // ISO 8601
  updatedAt: string; // ISO 8601
  lastImportAt: string | null; // ISO 8601
  componentCount: number;
  components: AssetComponentRow[];
  /** Distinct CVEs across all components, highest-priority first, paginated. */
  cves: AssetCveRow[];
  cveCursor: string | null;
}

/** POST /api/assets */
export interface CreateAssetRequest {
  name: string;
  description?: string;
}

/** Result of a POST /api/assets/[id]/import (CycloneDX SBOM upload). */
export interface SbomImportResult {
  componentsImported: number;
  componentsSkipped: number;
  matchesFound: number;
}
