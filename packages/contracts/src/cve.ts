/**
 * Canonical CVE data shapes shared between the app and ingest workers.
 * This file is TYPE-ONLY — no runtime code.
 * Section 5.1.3 — NormalizedCveRecord and related types.
 */

export type Severity = 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type IngestSource = 'NVD' | 'MITRE' | 'KEV' | 'EPSS' | 'AGING';

/** Full CPE 2.3 record with version bounds. */
export interface NormalizedCpe {
  cpeUri: string;
  part: 'a' | 'o' | 'h' | null;
  vendor: string;
  product: string;
  version: string | null;
  versionStartIncluding?: string;
  versionStartExcluding?: string;
  versionEndIncluding?: string;
  versionEndExcluding?: string;
  vulnerable: boolean;
  /** Less-used CPE attributes: update, edition, sw_edition, target_sw, target_hw, other */
  extras: Record<string, string>;
}

/** Canonical shape produced by the NVD and MITRE adapters. */
export interface NormalizedCveRecord {
  cveId: string;          // 'CVE-YYYY-NNNNN'
  publishedAt: number;    // unix ms
  lastModifiedAt: number; // unix ms
  description: string;
  cvss: {
    version: '3.1' | '4.0' | null;
    vector: string | null;
    base: number | null;
    exploitability: number | null;
    impact: number | null;
  } | null;
  severity: Severity;
  source: 'NVD' | 'MITRE';
  cwes: string[];                           // ['CWE-79', 'CWE-89', …]
  cpes: NormalizedCpe[];
  references: { url: string; tags: string[] }[];
}

/** Patch shape produced by the CISA KEV adapter.
 *  Applies only to cve_state; no cve row is written. */
export interface KevPatch {
  cveId: string;
  kevDateAdded: number;       // unix ms
  kevDueDate: number | null;  // unix ms
  kevRequiredAction: string;
}

/** Patch shape produced by the FIRST EPSS adapter.
 *  Applies only to cve_state; no cve row is written. */
export interface EpssPatch {
  cveId: string;
  epssScore: number;      // 0–1
  epssPercentile: number; // 0–1
  epssUpdatedAt: number;  // unix ms
}

/** Retry queue message shape (Section 3.5.1). */
export interface RetryMessage {
  attempt: number;          // 1-based, incremented by the queue on retry
  source: IngestSource;
  cveId: string;
  normalizedRecord: NormalizedCveRecord;
  /** UPSERT_ALL: D1 write failed, retry everything.
   *  VECTORIZE_ONLY: D1 succeeded but Vectorize/AI failed. */
  opType: 'UPSERT_ALL' | 'VECTORIZE_ONLY';
  /** Pre-computed embedding; if present, skip Workers AI on retry. */
  vector?: number[];
  lastError: {
    code: 'D1_WRITE_FAILED' | 'VECTORIZE_UPSERT_FAILED' | 'AI_EMBED_FAILED';
    message: string;
    occurredAt: number; // unix ms
  };
}
