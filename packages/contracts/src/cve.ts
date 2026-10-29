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
  cveId: string; // 'CVE-YYYY-NNNNN'
  publishedAt: number; // unix ms
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
  cwes: string[]; // ['CWE-79', 'CWE-89', …]
  cpes: NormalizedCpe[];
  references: { url: string; tags: string[] }[];
}

/** Patch shape produced by the CISA KEV adapter.
 *  Applies only to cve_state; no cve row is written. */
export interface KevPatch {
  cveId: string;
  kevDateAdded: number; // unix ms
  kevDueDate: number | null; // unix ms
  kevRequiredAction: string;
}

/** Patch shape produced by the FIRST EPSS adapter.
 *  Applies only to cve_state; no cve row is written. */
export interface EpssPatch {
  cveId: string;
  epssScore: number; // 0–1
  epssPercentile: number; // 0–1
  epssUpdatedAt: number; // unix ms
}

/** EPSS queue message shape — one chunk of a day's FIRST EPSS CSV snapshot,
 *  produced by `pipelines/daily.ts` and consumed by `pipelines/epssQueue.ts`.
 *  Kept to a chunk size whose JSON stays comfortably under Cloudflare
 *  Queues' 128KB per-message cap (see EPSS_MESSAGE_CHUNK_SIZE in daily.ts). */
export interface EpssQueueMessage {
  patches: EpssPatch[];
}

// ── OSV (GHSA) ───────────────────────────────────────────────────────────
// GHSA-scoped, CVE-linked-only. See apps/ingest/src/adapters/osv.ts and
// apps/ingest/src/pipelines/osv.ts for the producer/consumer that fill
// these shapes, and migrations/0007_osv.sql for where they land in D1.

/** One version-range + fix-event entry from an OSV record's affected[].ranges[]. */
export interface OsvRangeEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
  limit?: string;
}

export interface OsvRange {
  type: 'SEMVER' | 'ECOSYSTEM' | 'GIT';
  repo?: string;
  events: OsvRangeEvent[];
}

/** One affected-package entry, trimmed to what Threat-Lens stores. Drops
 *  OSV's `versions[]` enumeration field — `ranges` captures what's needed
 *  (same reasoning NormalizedCveRecord's cpes cap at 500 / references cap at
 *  200 in processRecord.ts: bound row/write size against a pathological
 *  upstream record). */
export interface OsvAffectedPackage {
  ecosystem: string;
  name: string;
  purl: string | null;
  ranges: OsvRange[];
  fixedVersions: string[];
}

/** Normalized OSV advisory. Produced by
 *  apps/ingest/src/adapters/osv.ts's normalizeOsvRecord (raw OSV JSON →
 *  OsvPatch | null — null only for a genuinely malformed/unparseable
 *  record, not for "no CVE alias", which is a valid OsvPatch with an empty
 *  `cveIds`). */
export interface OsvPatch {
  osvId: string; // 'GHSA-xxxx-xxxx-xxxx'
  /** OSV's `modified` field, verbatim (nanosecond-precision ISO string).
   *  Compared as string equality for skip-if-unchanged — see
   *  osv_record_state.modified_at. */
  modified: string;
  published: string | null;
  withdrawn: boolean;
  /** Deduped + sorted. Empty when no CVE-shaped alias exists — callers must
   *  track these (osv_record_state.status = 'NO_CVE_ALIAS') without giving
   *  them a first-class non-CVE route. */
  cveIds: string[];
  /** Capped at 50 entries. */
  affected: OsvAffectedPackage[];
}

/** One item of discovered (or re-link-candidate) work handed from the
 *  OSV_DISCOVER producer to the OSV_FETCH consumer — just enough to refetch
 *  + re-check the record; the full OsvPatch is reconstructed in the
 *  consumer, not carried in the queue message. */
export interface OsvFetchItem {
  osvId: string;
  ecosystemDir: string;
  /** The candidate's `modified` value as last observed (CSV scan or
   *  osv_record_state, for a re-link candidate) — NOT necessarily what the
   *  record's current `modified` is; the consumer refetches to find out. */
  modified: string;
}

/** osv-ingest queue message shape. A single queue carries both the
 *  lightweight daily kick-off (OSV can't get its own Cron Trigger — all 5
 *  Workers Free slots are already used, see wrangler.toml) and the actual
 *  per-record fetch work, dispatched by `kind` in index.ts's queue()
 *  handler. */
export type OsvQueueMessage =
  | { kind: 'OSV_DISCOVER' }
  | { kind: 'OSV_FETCH'; items: OsvFetchItem[] };

/** Retry queue message shape (Section 3.5.1). */
export interface RetryMessage {
  attempt: number; // 1-based, incremented by the queue on retry
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
