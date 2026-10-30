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

/** CISA ADP's SSVC decision for a CVE, parsed from NVD API 2.0's
 *  `metrics.ssvcV203[]` (or a future `ssvcV\d+` tree version — see
 *  apps/ingest/src/adapters/nvd.ts's extractSsvcDecision, matched by key
 *  pattern rather than a hardcoded version string).
 *
 *  Each enum field is independently nullable: NVD's `options[]` array can
 *  omit a decision point, or carry a value this type doesn't recognize yet
 *  (future SSVC tree revisions can add options) — an unknown/unexpected
 *  value becomes null rather than throwing. `decidedAt` is CISA's own
 *  `ssvcData.timestamp` (parsed to unix ms, or null on a failed parse);
 *  it is intentionally NEVER part of processRecord.ts's change-detection —
 *  see that file's `ssvcChanged` comment. */
export interface SsvcDecision {
  exploitation: 'none' | 'poc' | 'active' | null;
  automatable: 'yes' | 'no' | null;
  technicalImpact: 'partial' | 'total' | null;
  decidedAt: number | null; // unix ms
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
  /** NVD-only (MITRE's adapter does not populate this — see
   *  apps/ingest/src/adapters/mitre.ts, independently unfixed, out of
   *  scope). Optional — not just nullable — because messages already
   *  enqueued onto cve-ingest-retry before this field existed won't carry
   *  it; processRecord.ts treats an absent field identically to an explicit
   *  `null` (both mean "no new SSVC info," never "clear the stored
   *  value"). */
  ssvc?: SsvcDecision | null;
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

/** mitre-ingest queue message shape — one bounded chunk of CVE IDs that an
 *  NVD record was seen with zero CWEs (`record.cwes.length === 0`),
 *  collected by `pipelines/daily.ts`'s NVD producer loop and consumed by
 *  `pipelines/mitreQueue.ts`, which re-checks each one against MITRE's
 *  public single-record endpoint for a free-text-only CWE NVD's own
 *  parsing can't recover (see adapters/mitre.ts). Deliberately NOT a
 *  NormalizedCveRecord-shaped message — this path only ever writes CWE
 *  rows (cwe/cve_cwe/cve_source_provenance), never cve/cve_state, see
 *  pipelines/mitreQueue.ts. */
export interface MitreCweQueueMessage {
  cveIds: string[];
}

/** NVD queue message shape — one bounded batch of NormalizedCveRecords from
 *  a day's 48h NVD delta window, produced by `pipelines/daily.ts` and
 *  consumed by `pipelines/nvdQueue.ts`.
 *
 *  Unlike EpssQueueMessage, this batch is NOT sized by a fixed record count
 *  alone: a single NormalizedCveRecord can carry up to 500 CPEs / 200
 *  references (processRecord.ts's writeD1 caps) and measures ~200KB on its
 *  own in that worst case — already over Cloudflare Queues' 128KB
 *  per-message cap by itself. `daily.ts`'s producer tracks actual
 *  serialized bytes per batch (not just a record-count cap) for this
 *  reason; see NVD_QUEUE_MAX_RECORDS / NVD_QUEUE_MAX_BYTES there. */
export interface NvdQueueMessage {
  records: NormalizedCveRecord[];
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
