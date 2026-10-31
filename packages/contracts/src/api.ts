/**
 * API gateway request/response contracts shared between the app worker
 * and any external integrations. TYPE-ONLY — no runtime code.
 * Sections 5.2.1 – 5.2.7.
 */

import type { Severity } from './cve.js';

// ── Error envelope ────────────────────────────────────────────────────────────
// Canonical error shape returned by both the WAF custom responses (Section 4.2.2)
// and the SvelteKit API endpoints. Clients never need to branch on origin.

export type ErrorCode =
  | 'VALIDATION_ERROR'
  | 'CVE_NOT_FOUND'
  | 'WATCHLIST_NOT_FOUND'
  | 'ASSET_NOT_FOUND'
  | 'UNAUTHORIZED'
  | 'RATE_LIMITED'
  | 'GLOBAL_QUOTA_EXHAUSTED'
  | 'FORBIDDEN_NETWORK'
  | 'METHOD_NOT_ALLOWED'
  | 'UPSTREAM_FAILURE'
  | 'INTERNAL_ERROR';

export interface ErrorEnvelope {
  error: {
    code: ErrorCode;
    message: string;
    retryAfterSeconds: number | null;
    requestId: string; // CF-Ray
    details?: Record<string, unknown>; // Field map for VALIDATION_ERROR
  };
}

// ── CVSS block ────────────────────────────────────────────────────────────────

export interface CvssBlock {
  version: '3.1' | '4.0';
  vector: string;
  base: number;
  exploitability: number | null;
  impact: number | null;
}

// ── CPE row (returned in API responses) ──────────────────────────────────────

export interface CpeRow {
  cpeUri: string;
  part: 'a' | 'o' | 'h' | null;
  vendor: string;
  product: string;
  version: string | null;
  versionStartIncluding: string | null;
  versionStartExcluding: string | null;
  versionEndIncluding: string | null;
  versionEndExcluding: string | null;
  vulnerable: boolean;
}

// ── GET /api/cve/:id  (Section 5.2.2) ────────────────────────────────────────

export interface CveDetailResponse {
  cveId: string;
  publishedAt: string; // ISO 8601 (converted from unix ms at API boundary)
  lastModifiedAt: string; // ISO 8601
  description: string;
  severity: Severity;
  cvss: CvssBlock | null;
  state: {
    kevListed: boolean;
    kevDateAdded: string | null;
    kevDueDate: string | null;
    kevRequiredAction: string | null;
    epssScore: number | null;
    epssPercentile: number | null;
    epssUpdatedAt: string | null;
  };
  cwes: { id: string; name: string; category: string | null }[];
  cpes: CpeRow[];
  references: { url: string; tags: string[] }[];
}

// ── POST /api/search  (Section 5.2.3) ────────────────────────────────────────

export interface SearchFilters {
  severity?: Severity[];
  kev?: boolean;
  minCvss?: number;
  vendor?: string[];
  publishedSince?: string; // ISO date string
}

export interface SearchRequest {
  /** Free-text or CVE ID. Exactly one of query or similarTo is required. */
  query?: string; // 1–256 chars
  /** "More like this" — uses existing vector for the given CVE ID. */
  similarTo?: string; // CVE-YYYY-NNNNN
  filters?: SearchFilters;
  limit?: number; // 1–50, default 25
}

export interface SearchResultItem {
  cveId: string;
  score: number; // Fused RRF score
  severity: Severity;
  cvssBase: number | null;
  kevListed: boolean;
  epssPercentile: number | null;
  publishedAt: string; // ISO 8601
  vendors: string[]; // Top-3 distinct vendors from cpe
  snippet: string; // FTS5-highlighted or first 200 chars of description
}

export interface SearchResponse {
  results: SearchResultItem[];
  truncated: boolean; // true when more than `limit` candidates were available
}

// ── GET /api/affected-products  (Section 5.2.4) ──────────────────────────────

export interface AffectedProductsRequest {
  vendor?: string;
  product?: string;
  minCvss?: number;
  cursor?: string; // base64 of last row_id
  limit?: number; // 1–100, default 50
}

export interface AffectedProductRow {
  vendor: string;
  product: string;
  versionRange: string; // Pretty-formatted range string
  cveCount: number;
  latestCveId: string;
  latestPublishedAt: string; // ISO 8601
  maxSeverity: Severity;
}

export interface AffectedProductsResponse {
  rows: AffectedProductRow[];
  nextCursor: string | null;
}

// ── GET /api/threat-intel/kev  (Section 5.2.5) ───────────────────────────────

export interface KevListRow {
  cveId: string;
  severity: Severity;
  vendor: string;
  kevDateAdded: string; // ISO 8601
  kevDueDate: string | null; // ISO 8601
  kevRequiredAction: string;
}

export interface KevListResponse {
  rows: KevListRow[];
  nextCursor: string | null;
}

// ── GET /api/threat-intel/epss  (Section 5.2.5) ──────────────────────────────

export interface EpssListRow {
  cveId: string;
  severity: Severity;
  vendor: string;
  epssScore: number;
  epssPercentile: number;
  cvssBase: number | null;
}

export interface EpssListResponse {
  rows: EpssListRow[];
  nextCursor: string | null;
}

// ── GET /api/metrics/:window  (Section 5.2.6) ────────────────────────────────

export type MetricsWindow = '1h' | '24h' | '7d' | '30d' | '90d';

export interface MetricsKpis {
  totalCves: number;
  criticalCount: number;
  kevCount: number;
  meanEpssPercentile7d: number;
}

export interface MetricsSeries {
  severityDistribution: { severity: Severity; count: number }[];
  publicationVelocity: { date: string; count: number }[];
  topVendors: { vendor: string; cveCount: number; kevCount: number }[];
  kevInflow: { date: string; count: number }[];
}

export interface MetricsResponse {
  window: MetricsWindow;
  generatedAt: string; // ISO 8601
  kpis: MetricsKpis;
  series: MetricsSeries;
}

// ── GET /api/admin/health  (Section 5.2.7) ───────────────────────────────────

export type IngestSource = 'NVD' | 'MITRE' | 'KEV' | 'EPSS' | 'AGING';

export type IngestStaleness = 'green' | 'amber' | 'red';

export interface IngestSourceStatus {
  lastStartedAt: string | null; // ISO 8601
  lastFinishedAt: string | null; // ISO 8601
  lastStatus: 'OK' | 'PARTIAL' | 'FAILED' | null;
  recordsProcessed: number | null;
  recordsFailed: number | null;
  /** green < 26h, amber 26–48h, red > 48h since last successful finish */
  staleness: IngestStaleness;
}

export interface HealthResponse {
  generatedAt: string; // ISO 8601
  ingest: Record<IngestSource, IngestSourceStatus>;
  counts: {
    cve: number;
    cpe: number;
    cveState: number;
    cveQuarantine: number;
    auditLog: number;
  };
  queues: {
    retryDepth: number; // -1 if Cloudflare API unreachable
    dlqDepth: number; // -1 if Cloudflare API unreachable
  };
  rateLimits: {
    lastHourBlocks: number;
    topIps: { ip: string; blocks: number }[];
  };
}
