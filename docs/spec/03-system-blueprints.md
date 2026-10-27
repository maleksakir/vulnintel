# Section 3 — System Blueprint Specifications (v2)

This section defines the persistent stores and their schemas: D1 relational
tables and FTS5 virtual tables, the Vectorize index, the Analytics Engine
dataset, the KV `CACHE` namespace key catalog, and the retry / DLQ queue
contracts. It assumes the 24-month rolling window with hard-delete aging.

---

## 3.1 D1 Relational Schema

### 3.1.1 Core tables

All timestamps are stored as **unix milliseconds (INTEGER)** for index
efficiency and stable sort behaviour. API-layer conversion to ISO 8601 is
defined in Section 5.

#### `cve`

```sql
CREATE TABLE cve (
  cve_id              TEXT PRIMARY KEY,                        -- 'CVE-YYYY-NNNNN'
  published_at        INTEGER NOT NULL,                        -- unix ms
  last_modified_at    INTEGER NOT NULL,                        -- unix ms
  description         TEXT NOT NULL,
  cvss_version        TEXT,                                    -- '3.1' | '4.0'
  cvss_vector         TEXT,
  cvss_base           REAL,
  cvss_exploitability REAL,
  cvss_impact         REAL,
  severity            TEXT CHECK (severity IN
                        ('NONE','LOW','MEDIUM','HIGH','CRITICAL')),
  source              TEXT NOT NULL,                           -- 'NVD' | 'MITRE'
  text_hash           TEXT NOT NULL,                           -- sha256 of embedded-fields subset
  state_hash          TEXT NOT NULL,                           -- sha256 of metadata-only subset
  ingested_at         INTEGER NOT NULL                         -- unix ms (first seen)
) STRICT;
```

#### `cwe`

```sql
CREATE TABLE cwe (
  cwe_id   TEXT PRIMARY KEY,                                   -- 'CWE-NNN'
  name     TEXT,                                               -- Nullable (fallback to ID)
  category TEXT
) STRICT;
```

#### `cve_cwe` (m:n bridge)

```sql
CREATE TABLE cve_cwe (
  cve_id TEXT NOT NULL REFERENCES cve(cve_id) ON DELETE CASCADE,
  cwe_id TEXT NOT NULL REFERENCES cwe(cwe_id),
  PRIMARY KEY (cve_id, cwe_id)
) STRICT, WITHOUT ROWID;
```

#### `cpe`

A CPE 2.3 URI has 11 attribute fields. We index the four that drive 99% of
filter queries and retain the canonical URI for exact matching. Less-used
fields (update, edition, sw_edition, target_sw, target_hw, other) are
preserved inside `extras_json` as a serialised object.

```sql
CREATE TABLE cpe (
  cpe_row_id              INTEGER PRIMARY KEY AUTOINCREMENT,
  cve_id                  TEXT NOT NULL
                            REFERENCES cve(cve_id) ON DELETE CASCADE,
  cpe_uri                 TEXT NOT NULL,                       -- canonical CPE 2.3 string
  part                    TEXT CHECK (part IN ('a','o','h')),
  vendor                  TEXT NOT NULL,
  product                 TEXT NOT NULL,
  version                 TEXT,                                -- '*' for wildcard
  version_start_including TEXT,
  version_start_excluding TEXT,
  version_end_including   TEXT,
  version_end_excluding   TEXT,
  vulnerable              INTEGER NOT NULL DEFAULT 1,          -- boolean (0/1)
  extras_json             TEXT                                 -- {update, edition, …}
) STRICT;
```

#### `cve_reference`

```sql
CREATE TABLE cve_reference (
  cve_id TEXT NOT NULL REFERENCES cve(cve_id) ON DELETE CASCADE,
  url    TEXT NOT NULL,
  tags   TEXT,                                                 -- comma-separated
  PRIMARY KEY (cve_id, url)
) STRICT, WITHOUT ROWID;
```

#### `cve_state` (1:1 operational flags)

```sql
CREATE TABLE cve_state (
  cve_id            TEXT PRIMARY KEY
                      REFERENCES cve(cve_id) ON DELETE CASCADE,
  kev_listed        INTEGER NOT NULL DEFAULT 0,                -- boolean
  kev_date_added    INTEGER,                                   -- unix ms
  kev_due_date      INTEGER,                                   -- unix ms
  kev_required_action TEXT,
  epss_score        REAL,
  epss_percentile   REAL,
  epss_updated_at   INTEGER,                                   -- unix ms
  state_updated_at  INTEGER NOT NULL
) STRICT, WITHOUT ROWID;
```

#### `cve_quarantine`

Records that fail normalization land here for human review instead of
disappearing silently.

```sql
CREATE TABLE cve_quarantine (
  quarantine_id INTEGER PRIMARY KEY AUTOINCREMENT,
  source        TEXT NOT NULL,                                 -- 'NVD' | 'MITRE' | 'KEV' | 'EPSS'
  cve_id        TEXT,                                          -- NULL if unparseable
  payload       TEXT NOT NULL,                                 -- raw source JSON
  error_code    TEXT NOT NULL,
  error_message TEXT NOT NULL,
  quarantined_at INTEGER NOT NULL
) STRICT;
```

#### `cve_metrics_daily`

Daily rollup that survives Analytics Engine's 90-day retention. Populated by
a tail of the aging-sweep cron.

```sql
CREATE TABLE cve_metrics_daily (
  metric_date INTEGER NOT NULL,                                -- epoch day (UTC)
  metric_key  TEXT NOT NULL,                                   -- 'severity.critical.count', etc.
  value       REAL NOT NULL,
  PRIMARY KEY (metric_date, metric_key)
) STRICT, WITHOUT ROWID;
```

#### `audit_log` (IP-only auth audit trail)

```sql
CREATE TABLE audit_log (
  audit_id     INTEGER PRIMARY KEY AUTOINCREMENT,
  occurred_at  INTEGER NOT NULL,                               -- unix ms
  client_ip    TEXT NOT NULL,                                  -- cf-connecting-ip
  cf_ray       TEXT NOT NULL,
  route        TEXT NOT NULL,                                  -- '/api/search', etc.
  action       TEXT NOT NULL,                                  -- 'SEARCH','VIEW','ADMIN_HEALTH'
  detail_json  TEXT                                            -- {"query":"…","cveId":"…"}
) STRICT;
```

Audit log retention is 90 days. A weekly job purges rows older than that.

#### `ingest_run`

Per-source last-run markers consumed by `/admin/health`.

```sql
CREATE TABLE ingest_run (
  source            TEXT PRIMARY KEY,                          -- 'NVD','MITRE','KEV','EPSS','AGING'
  last_started_at   INTEGER,
  last_finished_at  INTEGER,
  last_status       TEXT CHECK (last_status IN ('OK','PARTIAL','FAILED')),
  records_processed INTEGER,
  records_failed    INTEGER,
  last_error        TEXT
) STRICT, WITHOUT ROWID;
```

#### `cve_source_provenance`

Ingestion timestamps per source, backing the detail page Provenance tab.

```sql
CREATE TABLE cve_source_provenance (
  cve_id       TEXT NOT NULL REFERENCES cve(cve_id) ON DELETE CASCADE,
  source       TEXT NOT NULL,                                  -- 'NVD' | 'MITRE'
  last_seen_at INTEGER NOT NULL,                               -- unix ms
  PRIMARY KEY (cve_id, source)
) STRICT, WITHOUT ROWID;
```

#### `search_quota_ledger`

Atomic daily transaction ledger to enforce the org-wide 50k/day search
quota. See Section 5.3.7 for the increment-and-check protocol.

```sql
CREATE TABLE search_quota_ledger (
  day         TEXT PRIMARY KEY,                                -- 'YYYY-MM-DD'
  query_count INTEGER NOT NULL DEFAULT 0
) STRICT, WITHOUT ROWID;
```

#### `search_quota_ip_ledger`

Atomic hourly per-IP ledger to enforce the 500/hour AI cost cap. Uses
an hour-bucket key (`YYYY-MM-DD-HH`) so the same purge cron that prunes
`search_quota_ledger` can prune this table with the same comparator.

```sql
CREATE TABLE search_quota_ip_ledger (
  bucket      TEXT NOT NULL,                                   -- 'YYYY-MM-DD-HH' (UTC)
  client_ip   TEXT NOT NULL,                                   -- cf-connecting-ip
  query_count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (bucket, client_ip)
) STRICT, WITHOUT ROWID;
```

### 3.1.2 FTS5 virtual tables (hybrid search)

Two FTS5 tables back the lexical layer of `/search` and the vendor / product
combobox on `/affected-products`.

#### `cve_search` — CVE description full-text

```sql
CREATE VIRTUAL TABLE cve_search USING fts5(
  cve_id UNINDEXED,
  description,
  tokenize = 'porter unicode61 remove_diacritics 2'
);
```

Populated and kept in sync with `cve` via three triggers (insert, update,
delete) defined in the migration. FTS5 does not support `STRICT`.

#### `cpe_search` — vendor + product lexical search

```sql
CREATE VIRTUAL TABLE cpe_search USING fts5(
  vendor,
  product,
  tokenize = 'porter unicode61 remove_diacritics 2'
);
```

Sourced from a deduplicated projection of `cpe(vendor, product)`. Rebuilt by
the aging sweep so it does not drift.

### 3.1.3 Indices

| Index name                         | Definition                                                        | Used by                                |
|------------------------------------|-------------------------------------------------------------------|----------------------------------------|
| `idx_cve_severity_published`       | `cve(severity, published_at DESC)`                                | Dashboard severity facet, Threat Intel |
| `idx_cve_last_modified`            | `cve(last_modified_at DESC)`                                      | Delta polling, recently-changed view   |
| `idx_cve_published_at`             | `cve(published_at DESC)`                                          | Aging sweep, "recent CVEs" panels      |
| `idx_cpe_vendor_product`           | `cpe(vendor, product)`                                            | Affected Products matrix               |
| `idx_cpe_cve`                      | `cpe(cve_id)`                                                     | CVE Detail join                        |
| `idx_state_kev_partial`            | `cve_state(kev_date_added) WHERE kev_listed = 1`                  | KEV listing                            |
| `idx_state_epss_desc`              | `cve_state(epss_score DESC) WHERE epss_score IS NOT NULL`         | EPSS leaderboard                       |
| `idx_reference_cve`                | `cve_reference(cve_id)`                                           | CVE Detail join                        |
| `idx_quarantine_source_time`       | `cve_quarantine(source, quarantined_at DESC)`                     | Admin health view                      |
| `idx_audit_time`                   | `audit_log(occurred_at DESC)`                                     | Audit log purge, admin view            |
| `idx_audit_ip_time`                | `audit_log(client_ip, occurred_at DESC)`                          | Per-IP incident correlation            |
| `idx_quota_ip_bucket`              | `search_quota_ip_ledger(bucket)`                                  | Hourly bucket purge                    |

### 3.1.4 Migration discipline

- Migration files live in `/migrations/` at repo root and follow the
  `NNNN_description.sql` naming convention.
- Migrations are **forward-only**. A schema change in error is fixed by a
  new migration, never by editing a prior file.
- The migration runner is `wrangler d1 migrations apply` invoked from each
  worker (both reference the same `migrations_dir`). The runner is
  idempotent; both workers can safely call it but production deploys only
  invoke it from the ingest worker's CI step.
- Initial migration set, in order:
  1. `0001_core_tables.sql` — cve, cwe, cve_cwe, cpe, cve_reference, cve_state.
  2. `0002_operational_tables.sql` — cve_quarantine, ingest_run, audit_log,
      cve_source_provenance, search_quota_ledger, search_quota_ip_ledger.
  3. `0003_indices.sql` — all entries from 3.1.3.
  4. `0004_fts5.sql` — cve_search, cpe_search, triggers.
  5. `0005_metrics_daily.sql` — cve_metrics_daily.
  6. `0006_cwe_catalog_seed.sql` — seeds standard CWE data into the `cwe` table from `packages/contracts/src/cwe_catalog.json`.

### 3.1.5 Steady-state size projection (24-month window)

- `cve`: ~70k–80k rows × ~1 KB = ~75 MB
- `cpe`: ~350k rows × ~400 B (URI dominates) = ~140 MB
- `cve_cwe`, `cve_reference`: ~50 MB combined
- `cve_state`: ~70k × ~200 B = ~14 MB
- FTS5 virtual tables: ~60 MB
- Audit log (90 days × ~25k queries/day estimate): ~25 MB
- **Total D1 footprint:** ~350–450 MB steady state. Comfortably inside the
  10 GB ceiling and the Workers Paid daily op budget.

---

## 3.2 Vectorize Index Specification

### 3.2.1 Index parameters

| Parameter            | Value                                          |
|----------------------|------------------------------------------------|
| Index name           | `cve-vector-index` (prod), `cve-vector-index-staging` |
| Dimensionality       | 768                                            |
| Distance metric      | `cosine`                                       |
| Vector ID            | The CVE identifier (`CVE-YYYY-NNNNN`)          |
| Embedding model      | `@cf/baai/bge-base-en-v1.5` via Workers AI     |
| Steady-state count   | ~70k–80k vectors                               |

### 3.2.2 Embedding source text

Concatenation in this exact order, separated by single newlines:

1. `description` (truncated to 1500 characters)
2. Comma-joined CWE names (e.g. `Cross-site Scripting, Improper Input Validation`)
3. Comma-joined top-3 distinct `vendor: product` strings from `cpe`

Total kept under the BGE-base 512-token limit. Truncation happens before
tokenization to keep behaviour reproducible.

**Severity, CVSS, KEV, EPSS are intentionally excluded from the embedding
source.** They live only in metadata (3.2.4) so that score recalculations
do not invalidate the embedding and trigger a wasteful re-embed.

### 3.2.3 Two-hash re-embedding rule

- `text_hash = sha256(embedding_source_text)` — stored on the `cve` row.
- `state_hash = sha256(severity | cvss_base | kev_listed | epss_score |
  epss_percentile | top_vendor)` — also on the `cve` row. Covers every
  field that appears in Vectorize metadata.
- The ingest worker recomputes both hashes on every record visit.
  - If `text_hash` changed → re-embed (Workers AI) and `VECTORIZE.upsert`
    with refreshed metadata.
  - If only `state_hash` changed → `VECTORIZE.upsert` with the existing
    vector and refreshed metadata (no embedding call).
  - If neither changed → no Vectorize write at all.

This cuts steady-state Workers AI invocations by an estimated 80%, because
KEV / EPSS shifts (the most frequent updates) do not touch the description.

### 3.2.4 Metadata payload (filterable scalars on each vector)

| Key                 | Type    | Source                                  | Used by                          |
|---------------------|---------|-----------------------------------------|----------------------------------|
| `severity`          | string  | `cve.severity`                          | Severity filter                  |
| `cvss_base`         | number  | `cve.cvss_base`                         | Min-CVSS filter                  |
| `published_ms`      | number  | `cve.published_at`                      | Both "since" date and year-range filters (year filtering is range over ms) |
| `kev_listed`        | boolean | `cve_state.kev_listed`                  | KEV-only toggle                  |
| `epss_percentile`   | number  | `cve_state.epss_percentile`             | EPSS threshold filter            |
| `top_vendor`        | string  | First distinct vendor from `cpe`        | Cheap vendor pre-filter          |

**Vendor filtering strategy:** `top_vendor` supports `$eq` pre-filter only
(the canonical primary vendor). For multi-vendor or "vendor membership"
queries the search pipeline retrieves top-200 from Vectorize, then joins
against `cpe` in D1 to apply the full vendor filter before trimming to the
final 50 results. Vectorize metadata is not the right place for set
membership.

Metadata is updated on every state-hash change. Vectors stay in place when
only metadata changes.

> [!IMPORTANT]
> Cloudflare Vectorize requires metadata indexes to be explicitly created before you can run queries that filter on those metadata fields. The following metadata indexes must be provisioned via Wrangler for both staging and production indexes before inserting any vectors:
> - `severity` (type: `string`)
> - `cvss_base` (type: `number`)
> - `published_ms` (type: `number`)
> - `kev_listed` (type: `boolean`)
> - `epss_percentile` (type: `number`)
> - `top_vendor` (type: `string`)
>
> Command format:
> ```bash
> wrangler vectorize create-metadata-index <index-name> --property-name=<property> --type=<type>
> ```

### 3.2.5 Aging interaction

The aging sweep (Section 5) lists CVE IDs to delete from Vectorize in
batches of 1000 via `VECTORIZE.deleteByIds`. KEV-listed CVEs are exempt and
retained even when older than 24 months.

---

## 3.3 Analytics Engine Specification

### 3.3.1 Dataset

- Production: `cve_analytics_dataset`
- Staging: `cve_analytics_dataset_staging`
- Retention: **90 days** (platform default; cannot be extended).

### 3.3.2 Event schema (uniform across all writes)

Each `writeDataPoint` call carries:

**`indexes` (max 1):**

- For per-CVE events: `cve_id`.
- For per-request events: `cf_ray` (request identifier).

**`blobs` (categorical, max 20; we use 7):**

| Slot   | Field          | Allowed values                                      |
|--------|----------------|-----------------------------------------------------|
| `blob1`| event_type     | `INGEST`, `EMBED`, `VIEW`, `SEARCH`, `KEV_FLIP`, `EPSS_SHIFT`, `RATE_LIMIT`, `ERROR` |
| `blob2`| severity       | `NONE`/`LOW`/`MEDIUM`/`HIGH`/`CRITICAL` or empty    |
| `blob3`| source         | `NVD`/`MITRE`/`KEV`/`EPSS`/`USER`                   |
| `blob4`| top_vendor     | Lowercased vendor string or empty                   |
| `blob5`| route          | `/`, `/search`, `/cve/[id]`, etc.                   |
| `blob6`| country        | CF geo two-letter code                              |
| `blob7`| colo           | CF data centre code                                 |

**`doubles` (numeric, max 20; we use 5):**

| Slot      | Field                 |
|-----------|-----------------------|
| `double1` | cvss_base             |
| `double2` | epss_score            |
| `double3` | response_ms           |
| `double4` | result_count (search) |
| `double5` | payload_bytes (ingest)|

### 3.3.3 Query patterns

Read access is via the Analytics Engine SQL HTTP API using the
`ANALYTICS_QUERY_TOKEN` secret. The app worker proxies queries through
`/api/metrics/:window` (Section 5) and never exposes the SQL API directly.

Common pre-aggregations:

- 24h severity histogram: `SELECT blob2, count() FROM cve_analytics_dataset WHERE blob1='VIEW' AND timestamp > now() - INTERVAL '1' DAY GROUP BY blob2`.
- KEV inflow 30d: `SELECT toStartOfDay(timestamp) day, count() FROM cve_analytics_dataset WHERE blob1='KEV_FLIP' AND timestamp > now() - INTERVAL '30' DAY GROUP BY day`.
- p95 search latency: `SELECT quantile(0.95)(double3) FROM cve_analytics_dataset WHERE blob1='SEARCH' AND timestamp > now() - INTERVAL '1' HOUR`.

### 3.3.4 Daily rollup into `cve_metrics_daily`

A nightly job (part of the aging sweep cron `30 2 * * *`) issues fixed
Analytics queries for the prior UTC day and writes the results into
`cve_metrics_daily` so the dashboard can render windows longer than 90 days
without depending on Analytics Engine retention.

Rolled-up metric keys (initial set):

- `severity.<level>.count`
- `kev.flips.count`
- `epss.mean_shift`
- `search.requests.count`
- `search.p95_latency_ms`
- `rate_limit.blocks.count`
- `ingest.records_processed`
- `ingest.records_failed`

---

## 3.4 KV `CACHE` Namespace Catalog

### 3.4.1 Key conventions

- Lowercase, colon-separated, fixed-arity per pattern.
- Values are JSON strings produced and consumed only by the workers (never
  edited by hand).
- `metadata` field on each entry carries `{writtenAt: number, source:
  'app'|'ingest'}` for debug visibility.

### 3.4.2 Key catalog

| Key pattern                       | TTL    | Producer | Consumer | Invalidator             |
|-----------------------------------|--------|----------|----------|-------------------------|
| `dash:kpi:24h`                    | 5 min  | app      | app      | TTL only                |
| `dash:kpi:7d`                     | 1 hr   | app      | app      | TTL only                |
| `dash:chart:severity:90d`         | 30 min | app      | app      | TTL only                |
| `dash:chart:velocity:90d`         | 30 min | app      | app      | TTL only                |
| `cve:<id>`                        | 1 hr   | app      | app      | ingest deletes on update|
| `threat:kev:list`                 | 15 min | app      | app      | ingest deletes on KEV cron |
| `threat:epss:top:200`             | 15 min | app      | app      | ingest deletes on EPSS cron|
| `vendor:suggest:<prefix>`         | 1 hr   | app      | app      | TTL only                |
| `health:last_ingest:<source>`     | none   | ingest   | app      | overwritten on run end  |
| `health:counts`                   | 5 min  | app      | app      | TTL only                |

### 3.4.3 Invalidation rules (ingest worker)

On any successful record write the ingest worker performs:

1. `CACHE.delete("cve:<id>")` for the touched CVE.
2. `CACHE.delete("threat:kev:list")` if `cve_state.kev_listed` changed.
3. `CACHE.delete("threat:epss:top:200")` if EPSS score for any top-200 CVE
   was updated.
4. `CACHE.put("health:last_ingest:<source>", JSON.stringify({…}))` at the
   end of the run.

Dashboard chart keys are not actively invalidated — TTL is acceptable
because the dashboard data is summary-of-summary.

---

## 3.5 Queue `cve-ingest-retry` Specification

### 3.5.1 Message shape

```ts
type RetryMessage = {
  attempt: number;                  // 1-based, incremented on each retry
  source: 'NVD'|'MITRE'|'KEV'|'EPSS';
  cveId: string;
  normalizedRecord: NormalizedCveRecord;
  opType: 'UPSERT_ALL' | 'VECTORIZE_ONLY'; // Operation to perform/retry
  vector?: number[];                // optional computed embedding vector
  lastError: {
    code: 'D1_WRITE_FAILED' | 'VECTORIZE_UPSERT_FAILED' | 'AI_EMBED_FAILED';
    message: string;
    occurredAt: number;             // unix ms
  };
};
```

`NormalizedCveRecord` lives in `packages/contracts` and is the canonical
shape both the cron path and the retry consumer accept.

### 3.5.2 Producer semantics

- The cron path writes to the queue on any per-record failure after the
  in-process attempt fails. It does not retry in-process.
- One message per failing record; batched cron-side via
  `RETRY_QUEUE.sendBatch` of up to 100.

### 3.5.3 Consumer semantics

- `max_batch_size = 25`, `max_batch_timeout = 30` seconds.
- The consumer reuses the same `processRecord(record)` function as the
  cron path, ensuring identical behaviour.
- On success: ack the message (Queues default).
- On failure: throw — Cloudflare Queues will retry up to `max_retries = 5`,
  then route to `cve-ingest-dlq`.

### 3.5.4 DLQ `cve-ingest-dlq`

- No consumer is wired up. Messages accumulate for human review.
- `/admin/health` surfaces the depth via the Queues REST API (read-only
  call from the app worker using `ADMIN_BEARER` to gate the view).
- An alarm threshold of `> 100 messages` is documented for operator
  attention; alerting integration is out of scope for v2.

---

## 3.6 Cross-Store Consistency Notes

- D1 and Vectorize are not transactional with respect to one another. The
  ingest worker uses this order of operations on a successful re-embed:
  1. Write to D1 (transaction over cve + cpe + cve_cwe + cve_reference +
     cve_state).
  2. Upsert vector to Vectorize.
  3. Delete relevant `CACHE` keys.
  4. Mark the run successful in `ingest_run`.

  If step 2 fails after step 1 succeeds, the record is enqueued to
  `cve-ingest-retry` with `opType: 'VECTORIZE_ONLY'` as the operation to retry; D1
  is correct and will not be re-written on retry.

- Out-of-window deletes follow the reverse order:
  1. Delete from Vectorize.
  2. Delete from D1 (cascade handles cpe / cwe bridge / reference / state).
  3. Delete `cve:<id>` from CACHE.

  If step 1 fails the record stays in both stores; the next aging-sweep run
  retries.

- Quarantined records are written **only** to `cve_quarantine` and never to
  the primary tables, so no inconsistent partial record can be observed
  through the API.

---

## 3.7 Section 3 Deliverable Order

These steps execute during Phase 2 of the master plan.

1. Author migrations `0001` through `0006` in `/migrations/`.
2. Apply migrations to the staging D1 database via the ingest worker's
   Wrangler config.
3. Verify schema with `PRAGMA table_info` and `PRAGMA index_list` for each
   table and `SELECT name FROM sqlite_master WHERE type='table'`.
4. Seed 100 representative CVEs via a one-off script that exercises every
   column including the quarantine path.
5. Verify FTS5 round-trip: insert a CVE, search for a description fragment,
   confirm the row returns and the snippet highlights the matched span.
6. Provision the production Vectorize index with the parameters in 3.2.1.
   Create the six metadata indexes (severity, cvss_base, published_ms, kev_listed, epss_percentile, top_vendor) via Wrangler commands.
   Confirm the index accepts a 768-dim test vector and returns it on query.
7. Provision the production Analytics Engine dataset. Write one canary data
   point per `event_type` and confirm via the SQL HTTP API.
8. Provision the KV namespace. Write and read one entry per key pattern in
   3.4.2 to confirm permissions on both workers.
9. Create queues `cve-ingest-retry` and `cve-ingest-dlq`. Send a test
   message from the ingest worker and confirm receipt.
10. Capture all resource IDs into `docs/spec/RESOURCES.md`.
