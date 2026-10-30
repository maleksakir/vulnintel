# Section 5 — Component Interaction Definitions (v2)

This section defines the protocols and contracts between the moving parts:
the ingest pipeline, the API gateway exposed by the app worker, and the
SvelteKit edge loading interface that consumes that gateway. All shared
TypeScript shapes live in `packages/contracts/src/` and are imported
identically by both workers.

---

## 5.1 Pipeline Ingestion Protocol (`threat-lens-ingest`)

### 5.1.1 Cron trigger dispatch

The ingest worker exports one `scheduled(event, env, ctx)` handler. The
handler branches on `event.cron` to route to the correct pipeline:

| `event.cron`     | Pipeline                              | Purpose                                              |
|------------------|---------------------------------------|------------------------------------------------------|
| `0 1 * * *`      | `runDailyFullDelta`                   | NVD + MITRE + EPSS daily delta                       |
| `0 */6 * * *`    | `runKevFastLane`                      | KEV-only refresh, 6-hourly                           |
| `0 3 * * 0`      | `runWeeklyReconciliation`             | Re-pull last 30 days, catch back-dated edits         |
| `30 2 * * *`     | `runAgingSweep`                       | Hard-delete records older than 24 months (KEV exempt)|
| `0 4 * * *`      | `runIpListPrune`                      | Prune expired entries from `corp_authorized_sources` |

Each pipeline writes a row into `ingest_run` with start, finish, status,
and counts. `ctx.waitUntil` is used for the analytics emit so the cron
finishes promptly.

### 5.1.2 Source adapters

Each adapter is a pure function `(rawPayload) => NormalizedCveRecord[]` or
`(rawPayload) => StatePatch[]`. They live in
`apps/ingest/src/adapters/<source>.ts`.

| Adapter | Input                                      | Output                | Notes                                       |
|---------|--------------------------------------------|-----------------------|---------------------------------------------|
| `nvd`   | NVD CVE 2.0 API delta JSON                 | `NormalizedCveRecord[]`| Conditional `If-Modified-Since`; honour rate-limit header |
| `mitre` | CVE ID (string) — one per lookup, not a payload fetch | `{ outcome, cwes: string[] }` per ID | CWE-only gap-fill supplement, **not** a record source — see the note below |
| `kev`   | CISA KEV catalog JSON                      | `KevPatch[]`           | Patches `cve_state.kev_*` fields            |
| `epss`  | FIRST EPSS daily CSV                       | `EpssPatch[]`          | Patches `cve_state.epss_*` fields           |

A record that fails normalization is written to `cve_quarantine` with the
raw payload and the parser error. The adapter does **not** throw on a
single bad record; it returns the good records and the quarantine list.
(This applies to `nvd`/`kev`/`epss`; `mitre` is not payload-shaped the same
way — see below.)

> **Spec updated (2026-10-30, `docs-writer`, per `planner`'s design
> decision):** this section previously described the `mitre` adapter as
> reading "MITRE CVE List v5 commit diff, GitHub raw content" and
> deduplicating against NVD when both produced the same id. That was never
> what the code did — see `docs/EXECUTION_PLAN.md`'s Phase 0 "MITRE adapter"
> row for the investigation: the old code called MITRE's Secretariat/
> Bulk-Download-only LIST endpoint (`cveawg.mitre.org/api/cve` with
> `time_modified.start`/`.end`/`pageSize`/`pageNumber` query params), which
> returns HTTP 400 for ordinary public callers and never actually worked in
> production, and it fabricated synthetic CPEs that would have corrupted
> NVD's data had the endpoint bug alone been fixed without a redesign.
>
> As of 2026-10-30 the `mitre` adapter is a narrow CWE gap-fill, not a
> record source: `apps/ingest/src/pipelines/daily.ts`'s NVD producer loop
> collects the CVE IDs of any NVD record it sees with zero CWEs; a new
> `mitre-ingest` queue (`apps/ingest/src/pipelines/mitreQueue.ts`)
> re-verifies each one still qualifies, then calls
> `fetchMitreCweSupplement(cveId)` against MITRE's **public** single-record
> endpoint (`GET cveawg.mitre.org/api/cve/{id}`, no auth needed) and
> extracts CWE ids — the structured `problemTypes[].descriptions[].cweId`
> field when present, or a free-text `/^CWE-(\d+)\b/` regex fallback for a
> CNA that only wrote the CWE as prose. It never produces a
> `NormalizedCveRecord` and never touches `cve`/`cpe`/`cve_reference`/
> `text_hash`/`state_hash`/Vectorize/Workers AI/KV — only `cwe`/`cve_cwe`/
> `cve_source_provenance`. This also means the "pure function
> `(rawPayload) => NormalizedCveRecord[] | StatePatch[]`" framing in the
> paragraph above the table no longer holds for `mitre` specifically; it
> still holds for `nvd`/`kev`/`epss`. Code + tests (141/141 passing,
> `tsc --noEmit` clean) + security review complete 2026-10-30; not yet
> deployed — see `docs/EXECUTION_PLAN.md`'s Phase 0 row for status.

### 5.1.3 Canonical record shape (`packages/contracts/src/cve.ts`)

```ts
export type Severity = 'NONE'|'LOW'|'MEDIUM'|'HIGH'|'CRITICAL';

export interface NormalizedCveRecord {
  cveId: string;                    // 'CVE-YYYY-NNNNN'
  publishedAt: number;              // unix ms
  lastModifiedAt: number;           // unix ms
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
  cwes: string[];                   // ['CWE-79', …]
  cpes: NormalizedCpe[];
  references: { url: string; tags: string[] }[];
}

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
  extras: Record<string, string>;   // edition, update, sw_edition, …
}

export interface KevPatch {
  cveId: string;
  kevDateAdded: number;
  kevDueDate: number | null;
  kevRequiredAction: string;
}

export interface EpssPatch {
  cveId: string;
  epssScore: number;                // 0–1
  epssPercentile: number;           // 0–1
  epssUpdatedAt: number;
}
```

### 5.1.4 Persistence sequence

For each `NormalizedCveRecord` returned by the NVD adapter, the pipeline
executes the following in this exact order. (As of 2026-10-30 the `mitre`
adapter no longer produces `NormalizedCveRecord`s — see §5.1.2's note above
— so this sequence applies to `nvd` only; `mitre`'s CWE gap-fill writes
directly to `cwe`/`cve_cwe`/`cve_source_provenance` via its own consumer,
bypassing this sequence entirely.)

1. **Compute hashes:**
   - `textHash` over (description, cwes joined, top-3 vendor:product
     strings).
   - `stateHash` over (severity, cvssBase, kevListed, epssScore,
     epssPercentile, topVendor).
2. **Read prior hashes:** `SELECT text_hash, state_hash FROM cve WHERE cve_id = ?`.
3. **Update provenance safely:** if the prior `cve` row exists, write to
   `cve_source_provenance` before the hash decision so the "last seen at"
   timestamp reflects reality even when no other change occurred. This is
   a single-row upsert outside the larger batch so the no-op branch stays
   cheap. If the `cve` row does not exist yet, defer provenance until after
   the parent `cve` upsert inside the full D1 write batch:
   ```sql
   INSERT INTO cve_source_provenance (cve_id, source, last_seen_at)
   VALUES (?, ?, ?)
   ON CONFLICT(cve_id, source)
   DO UPDATE SET last_seen_at = excluded.last_seen_at;
   ```
4. **Decide work (or check operation type):**
   - If `options?.opType === 'VECTORIZE_ONLY'`: Skip D1 write. Directly run the Vectorize upsert path (reusing `options.vector` if provided, otherwise calling Workers AI first).
   - Otherwise, compare calculated hashes to database hashes:
     - Both unchanged → done (provenance already bumped in step 3).
     - Only `stateHash` changed → write D1 (cve + cve_state) and Vectorize metadata-only upsert; no AI call.
     - `textHash` changed → write D1. The D1 write is a single atomic database transaction (`db.batch()`) executing:
       1. `PRAGMA foreign_keys = ON;`
       2. Dynamic CWE registration: `INSERT OR IGNORE INTO cwe (cwe_id, name) VALUES (?, NULL)` for each CWE ID.
       3. Upsert `cve`: `INSERT INTO cve (...) ON CONFLICT(cve_id) DO UPDATE ...`
       4. Write bridge table `cve_cwe` (clearing stale associations first).
       5. Upsert `cve_state`.
       6. Insert associated `cpe` rows.
       Then, call Workers AI for the new embedding, and perform a Vectorize upsert with vector + metadata.
5. **Cache invalidation:** delete `cve:<id>` from the `CACHE` KV
   namespace, plus the threat-intel keys if KEV/EPSS fields changed.
6. **Analytics emit:** one `INGEST` event with timings, source,
   payload bytes, and whether an embedding was computed.
 
If step 4 or 5 fails for a record, the pipeline enqueues a `RetryMessage`
(Section 3.5.1) to `cve-ingest-retry` with:
- `opType = 'VECTORIZE_ONLY'` if D1 write succeeded but AI embedding, Vectorize upsert, or cache invalidation failed.
- `opType = 'UPSERT_ALL'` if the D1 write itself failed.
The message includes the generated `vector` if the AI embedding succeeded. The pipeline then continues with the next record.
The pipeline never stops mid-batch on a single failure.

### 5.1.5 KEV and EPSS patches

`KevPatch` and `EpssPatch` updates flow through a simpler path:

1. Apply the patch to `cve_state` in D1 (no `cve` row write).
2. If the CVE row exists, recompute `state_hash`. If it changed:
   - Vectorize metadata-only upsert.
   - Delete `cve:<id>`, `threat:kev:list`, `threat:epss:top:200` from CACHE.
3. Analytics emit (`KEV_FLIP` or `EPSS_SHIFT`).
4. If the CVE row does not exist (KEV/EPSS for a record we have not yet ingested):
   - **For an `EpssPatch`**: Write to `cve_quarantine` with `error_code = 'ORPHAN_STATE'` (so the next NVD delta can resolve it).
   - **For a `KevPatch`**:
     1. Trigger a targeted upstream fetch for the CVE ID using the NVD CVE API v2.0 (falling back to MITRE's public single-record endpoint, `GET cveawg.mitre.org/api/cve/{id}` — the same endpoint §5.1.2 describes the `mitre` CWE gap-fill using, corrected 2026-10-30 from this section's prior "MITRE raw JSON commit endpoint" wording, which was never a real endpoint — if NVD is down or rate-limited).
     2. If the fetch succeeds:
        - Normalize the response into a `NormalizedCveRecord`.
        - Execute both the base CVE record insertion (including its related tables and CWE/provenance upserts) and the `KevPatch` application (setting `kev_listed = 1` and saving KEV metadata in `cve_state`) inside a single atomic D1 database transaction (using `db.batch()`). Wrapping these writes in a single transaction guarantees that the aging sweep cannot race and delete the record between the base insert and the KEV state write.
     3. If the fetch fails (due to API down, rate limit, or not found upstream):
        - Write to `cve_quarantine` with `error_code = 'ORPHAN_FETCH_FAILED'`.

> **Drift flag (2026-10-30, `docs-writer`):** beyond the endpoint-name
> correction just above, `apps/ingest/src/lib/server/processRecord.ts`'s
> `applyKevPatch` does not appear to implement this orphan-fetch fallback at
> all — it reads/writes `cve_state` directly with no check for whether a
> `cve` row exists first, no upstream fetch, and no `cve_quarantine` write.
> Whether this orphan path was ever built elsewhere, was dropped silently,
> or this section describes intended-but-unbuilt behavior is not something
> this pass investigated beyond this one file — flagging per this file's own
> rule that spec/code drift is a bug, not resolving it (`planner` call).

### 5.1.6 Aging sweep (`runAgingSweep`)

Runs daily at 02:30 UTC.

```sql
WITH aging AS (
  SELECT c.cve_id
  FROM cve c
  LEFT JOIN cve_state s USING (cve_id)
  WHERE c.published_at < (strftime('%s','now','-24 months') * 1000)
    AND COALESCE(s.kev_listed, 0) = 0
)
SELECT cve_id FROM aging LIMIT 1000;
```

For each chunk of up to 1000 returned IDs:

1. `VECTORIZE.deleteByIds(ids)`.
2. Split the chunk of up to 1000 IDs into sub-batches of up to 100 IDs. Construct a `DELETE FROM cve WHERE cve_id IN (?, ?, ...)` statement for each sub-batch, and execute them via `db.batch()`, which runs the queries sequentially in a single transaction to respect D1 bound parameter limits while ensuring atomic execution (cascading deletes will clear `cpe`, `cve_cwe`, `cve_reference`, and `cve_state`).
3. `CACHE.delete("cve:<id>")` for each.

4. Loop until the query returns fewer than 1000 rows.

After processing all aged-out CVE deletions, the aging sweep executes
four tail-purge statements in a single `db.batch()`. Folding these into
the aging sweep avoids consuming an additional cron slot (Workers
scripts are capped at 5 cron triggers; we are already at 5):

```sql
-- Ledger purges (7-day rolling window)
DELETE FROM search_quota_ledger
  WHERE day < strftime('%Y-%m-%d', 'now', '-7 days');

DELETE FROM search_quota_ip_ledger
  WHERE bucket < strftime('%Y-%m-%d-%H', 'now', '-7 days');

-- Audit log purge (90-day retention per Section 4.4)
DELETE FROM audit_log
  WHERE occurred_at < (strftime('%s','now','-90 days') * 1000);

-- Quarantine purge (90-day retention; older entries are stale
-- and have either been resolved by subsequent ingests or
-- represent permanently malformed source data)
DELETE FROM cve_quarantine
  WHERE quarantined_at < (strftime('%s','now','-90 days') * 1000);
```

The sweep writes one row to `ingest_run` with `source = 'AGING'` and
`records_processed` = (CVEs deleted) + (ledger rows purged) + (audit
rows purged) + (quarantine rows purged). The four counts are also
broken out into `cve_metrics_daily` under keys
`aging.cve_deleted`, `aging.ledger_purged`, `aging.audit_purged`,
`aging.quarantine_purged`.

### 5.1.7 Retry queue consumer

The consumer invokes `processRecord(record, env, ctx, options)`.

- The consumer inspects `message.opType` and invokes `processRecord(message.normalizedRecord, env, ctx, { opType: message.opType, vector: message.vector })`. If `opType === 'VECTORIZE_ONLY'`, this bypasses the D1 write and hash-checking logic to directly run the Vectorize upsert path. If `message.vector` is provided, Vectorize uses it directly. If `message.vector` is missing, the retry consumer must re-calculate the embedding by invoking the Workers AI model (`@cf/baai/bge-base-en-v1.5`) on the source text generated by `buildEmbeddingSourceText(message.normalizedRecord)` prior to calling the Vectorize upsert API.

On exhaustion of retries (5 attempts, exponential backoff handled by Cloudflare Queues) the message lands in `cve-ingest-dlq`. `/api/admin/health` surfaces the DLQ depth (Section 2.2.6).

---

## 5.2 Gateway Router Contracts (`threat-lens-app`)

All routes are server endpoints in SvelteKit (`apps/app/src/routes/api/.../+server.ts`).
They return `Content-Type: application/json; charset=utf-8` and use the
shared error envelope defined in 5.2.1.

### 5.2.1 Error envelope (canonical)

```ts
export interface ErrorEnvelope {
  error: {
    code:
      | 'VALIDATION_ERROR'
      | 'CVE_NOT_FOUND'
      | 'RATE_LIMITED'
      | 'GLOBAL_QUOTA_EXHAUSTED'
      | 'FORBIDDEN_NETWORK'
      | 'METHOD_NOT_ALLOWED'
      | 'UPSTREAM_FAILURE'
      | 'INTERNAL_ERROR';
    message: string;
    retryAfterSeconds: number | null;
    requestId: string;                  // CF-Ray
    details?: Record<string, unknown>;  // VALIDATION_ERROR field map, etc.
  };
}
```

The same envelope is produced by both worker code and the Cloudflare WAF
custom JSON responses (Section 4.2.2), so the client never needs to branch
on origin.

### 5.2.2 `GET /api/cve/:id`

- **Path param:** `id` matched against `^CVE-\d{4}-\d{4,7}$`. Mismatch →
  `400 VALIDATION_ERROR`.
- **Retrieval:** If the CVE does not exist in D1 (either never existed or was hard-deleted by the aging sweep) → `404 CVE_NOT_FOUND`.
- **Response 200:**

  ```ts
  interface CveDetailResponse {
    cveId: string;
    publishedAt: string;            // ISO 8601 (converted from unix ms)
    lastModifiedAt: string;
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
  ```

- **Cache:** read-through against KV key `cve:<id>` with a 1-hour TTL.
  On miss, fetch from D1 and populate the cache before responding.
- **Audit:** `action = 'VIEW'`, `detail_json = {cveId}`.

### 5.2.3 `POST /api/search`

- **Body:**

  ```ts
  interface SearchRequest {
    query: string;                 // 1–256 chars
    filters?: {
      severity?: Severity[];
      kev?: boolean;
      minCvss?: number;
      vendor?: string[];
      publishedSince?: string;     // ISO date
    };
    similarTo?: string;            // CVE id — alternative to `query`
    limit?: number;                // 1–50, default 25
  }
  ```

  Exactly one of `query` or `similarTo` is required. `similarTo` triggers
  the "more like this" path (Section 2.3) by reading the existing vector
  for that CVE and issuing a neighbour query without a fresh embedding.

- **Hybrid pipeline (executed in order):**
  1. **Exact-match short circuit** — if `query` matches the CVE ID regex,
     return a single result for that CVE without invoking any other layer.
  2. **Lexical layer** — `SELECT cve_id, snippet(cve_search, 1, '<mark>', '</mark>', '…', 32) AS snippet, rank FROM cve_search WHERE cve_search MATCH ? ORDER BY rank LIMIT 200`. Applies filters via a JOIN to `cve` and `cve_state`.
  3. **Semantic layer** — embed `query` via Workers AI, then `VECTORIZE.query` with `topK = 200` and the available metadata pre-filters (`severity`, `kev_listed`, `published_ms`, `epss_percentile`, `top_vendor` if the filter has exactly one vendor).
  4. **Fusion** — Reciprocal Rank Fusion with `k = 60` over the two lists.
     Multi-vendor filters and the CVSS minimum are applied as a post-fusion
     filter via a single D1 batch `SELECT … WHERE cve_id IN (…)` that
     attaches the data needed for the result list.
  5. **Trim** to `limit` (default 25, max 50).

  > **Drift flag (2026-10-29, `docs-writer`):** `apps/app/src/lib/server/rerank.ts`
  > now exists in code and adds a reranking step between steps 4 and 5 above
  > — `@cf/baai/bge-reranker-base` reorders the top ~40 post-filter
  > candidates, fused into the RRF score as a third term rather than
  > replacing it (so exact lexical/CVE-ID matches stay protected). It is
  > optional and budget-gated: it skips entirely on exact-CVE-ID queries,
  > `similarTo`-only requests, fewer than 2 filtered candidates, an
  > already-failed embed in the same request, or once a 1,000-reranked-
  > searches/day account-wide cap trips — in every skip case (and on any
  > reranker failure) the pipeline falls back to steps 1–5 exactly as
  > specified here, silently, with no error surfaced. Per this file's own
  > rule that spec/code drift is a bug, this is real drift — but it's
  > reported here, not resolved, per `docs-writer`'s charter: whether this
  > spec's pipeline description should be formally extended to a 6-step
  > pipeline (and whether an optional/budget-gated step belongs in a spec
  > that otherwise describes unconditional behavior) is a `planner` decision.
  > See `docs/EXECUTION_PLAN.md`'s Phase 2 "Reranker on search" row for the
  > full design and status (code + tests + security review complete, not
  > yet deployed).

- **Response 200:**

  ```ts
  interface SearchResponse {
    results: Array<{
      cveId: string;
      score: number;              // fused score
      severity: Severity;
      cvssBase: number | null;
      kevListed: boolean;
      epssPercentile: number | null;
      publishedAt: string;
      vendors: string[];          // top-3 distinct
      snippet: string;            // FTS5 highlighted, or first 200 chars
    }>;
    truncated: boolean;           // true when more than `limit` candidates were available
  }
  ```

- **No pagination cursor.** The contract caps at 50 results and instructs
  the user to refine. This is intentional (Section 2.2.2): fused rankings
  are not stable across pages.
- **Audit:** `action = 'SEARCH'`, `detail_json = {query, filterCount, resultCount}`.
- **Rate limit / Quota:** Enforced at the edge by the application-level per-IP hourly AI quota ledger (Section 4.3.1) and at the application level by the Application-level Search Quota Ledger (Section 5.3.7).

### 5.2.4 `GET /api/affected-products`

- **Query params:**

  ```ts
  interface AffectedProductsRequest {
    vendor?: string;
    product?: string;
    minCvss?: number;
    cursor?: string;              // base64 of last row_id
    limit?: number;               // 1–100, default 50
  }
  ```

- **Response 200:**

  ```ts
  interface AffectedProductsResponse {
    rows: Array<{
      vendor: string;
      product: string;
      versionRange: string;       // pretty-formatted range
      cveCount: number;
      latestCveId: string;
      latestPublishedAt: string;
      maxSeverity: Severity;
    }>;
    nextCursor: string | null;
  }
  ```

- **Cache:** Cache API at the response level, 5 minutes
  stale-while-revalidate.
- **Audit:** `action = 'LIST_PRODUCTS'`.

### 5.2.5 `GET /api/threat-intel/kev` and `/epss`

- **No request body.** Optional `limit` (default 100, max 500) and
  `cursor` query params.
- **KEV response:**

  ```ts
  interface KevListResponse {
    rows: Array<{
      cveId: string;
      severity: Severity;
      vendor: string;
      kevDateAdded: string;
      kevDueDate: string | null;
      kevRequiredAction: string;
    }>;
    nextCursor: string | null;
  }
  ```

- **EPSS response:** structurally identical but ordered by `epssScore DESC`
  and with `epssScore`, `epssPercentile` columns instead of KEV columns.
- **Cache:** KV `threat:kev:list` (15 min, ingest invalidates) and
  `threat:epss:top:200` (15 min, ingest invalidates).
- **Audit:** `action = 'LIST_THREATS'`, `detail_json = {panel: 'kev'|'epss'}`.

### 5.2.6 `GET /api/metrics/:window`

- **Path param:** `window ∈ {'1h', '24h', '7d', '30d', '90d'}`. Anything
  else → `400 VALIDATION_ERROR`.
- **Behaviour:** for `1h` / `24h` queries Analytics Engine via the SQL HTTP
  API (using `ANALYTICS_QUERY_TOKEN`). For `7d`+ reads `cve_metrics_daily`
  from D1 (Analytics Engine retention is 90 days).
- **Response 200:**

  ```ts
  interface MetricsResponse {
    window: string;
    generatedAt: string;
    kpis: {
      totalCves: number;
      criticalCount: number;
      kevCount: number;
      meanEpssPercentile7d: number;
    };
    series: {
      severityDistribution: Array<{ severity: Severity; count: number }>;
      publicationVelocity: Array<{ date: string; count: number }>;
      topVendors: Array<{ vendor: string; cveCount: number; kevCount: number }>;
      kevInflow: Array<{ date: string; count: number }>;
    };
  }
  ```

- **Cache:** KV `dash:kpi:<window>` per the catalog in Section 3.4.2.
- **Not audited.** Dashboard aggregates are not sensitive.

### 5.2.7 `GET /api/admin/health`

- **Auth:** `Authorization: Bearer <ADMIN_BEARER>` required in addition to
  the IP allowlist. Missing or wrong token → `403`.
- **Response 200:**

  ```ts
  interface HealthResponse {
    generatedAt: string;
    ingest: Record<'NVD'|'MITRE'|'KEV'|'EPSS'|'AGING', {
      lastStartedAt: string | null;
      lastFinishedAt: string | null;
      lastStatus: 'OK'|'PARTIAL'|'FAILED'|null;
      recordsProcessed: number | null;
      recordsFailed: number | null;
      staleness: 'green'|'amber'|'red';
    }>;
    counts: {
      cve: number;
      cpe: number;
      cveState: number;
      cveQuarantine: number;
      auditLog: number;
    };
    queues: {
      retryDepth: number;
      dlqDepth: number;
    };
    rateLimits: {
      lastHourBlocks: number;
      topIps: Array<{ ip: string; blocks: number }>;
    };
  }
  ```

- **Queue Depths:** The queue depths (`retryDepth` and `dlqDepth`) are fetched dynamically via the Cloudflare REST API endpoint `/accounts/{account_id}/queues/{queue_name}` using the bound `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`. If the Cloudflare REST API is unreachable, rate-limited, or returns an error, the endpoint falls back to returning `-1` for the queue depths without failing the rest of the health check.
- **Audit:** `action = 'ADMIN_HEALTH'`.

### 5.2.8 Cross-cutting concerns

- **Validation:** every request is validated at the endpoint entry using
  hand-written type guards in `apps/app/src/lib/server/validate/`. No
  Zod or Yup dependency.
- **`requestId`:** set to `request.headers.get('cf-ray')` on every
  response.
- **Time format:** all `unix ms` integers stored in D1 are converted to
  ISO 8601 UTC strings at the API boundary. Inbound ISO strings are
  parsed back to unix ms at the entry guard.

---

## 5.3 SvelteKit Edge Loading Interface

### 5.3.1 Loader split

Each route follows the same shape:

- `+page.server.ts` — runs on the worker, uses the shared query module (Section 5.3.8) to retrieve data using bound D1 / Vectorize / Analytics / KV directly. Returns:
  - Synchronous fields needed for first paint.
  - `Promise`s for streamed secondary content (charts, supplementary tabs).
- `+page.ts` — universal load that runs on both server (during SSR) and client (during navigation). Used only when a route needs to issue extra fetches after first paint, never as a substitute for `+page.server.ts`.

The server load **never** calls the gateway API over HTTP; it imports and invokes the shared query library functions directly to access database bindings. The gateway routes (`+server.ts` endpoints) also import and invoke this same shared query library, providing API access for the client (JS-enabled navigation) and for external integrations.

### 5.3.2 Streaming contract example (`/cve/[id]`)

The server load returns:

```ts
return {
  header: { cveId, severity, cvssBase, kevListed, epssPercentile, publishedAt },
  // streamed:
  overview: getCveDetail(id, env),       // Promise<CveDetailResponse> via shared query
  cwes:     getCwes(env, id),             // Promise<CweRow[]>
  cpes:     getCpes(env, id),             // Promise<CpeRow[]>
  references: getReferences(env, id),     // Promise<RefRow[]>
};
```

SvelteKit streams the header immediately; the promises resolve as their queries complete and the client patches the corresponding tabs. This is the mechanism that keeps TTFB low without sacrificing render completeness.

### 5.3.3 Error boundary integration

The error envelope from 5.2.1 is the source of truth. Server loads throw SvelteKit `error(status, body)` with the envelope shape, and `+error.svelte` renders a contextual UI per `code` (Section 2.6).

A rate-limit response on a background `+page.ts` fetch surfaces as a toast (via the layout shell's toast region) rather than as a full-page error. The discriminator is whether the failing load is the primary one or a secondary fetch.

### 5.3.4 Cache integration

- **Page-server reads** go through a `cacheRead(env.CACHE, key, ttl, producer)` helper that returns the cached value if present and fresh, otherwise invokes the producer and stores the result. The helper writes `{writtenAt, source: 'app'}` metadata so debug tooling can see where cached values came from.
- **No client-side caching** beyond SvelteKit's own page data cache.

### 5.3.5 Audit log integration

A SvelteKit server hook (`apps/app/src/hooks.server.ts`) intercepts every request that resolves to an `/api/*` route (which includes `/api/admin/*`). After the response is generated, it enqueues an `audit_log` insert via `event.platform.context.waitUntil(...)`. The hook does NOT match `/admin/*` page routes — those serve only the login prompt; the underlying data fetch goes to `/api/admin/*` and is captured there. This is the only place audit writes happen; endpoints never write directly.

### 5.3.6 Hook-based ergonomics

The same `hooks.server.ts` file:

- Captures `cf-connecting-ip` and `cf-ray` into a request-scoped context exposed through `event.locals`.
- Translates upstream `Response` objects with non-2xx status into typed `ErrorEnvelope` throws so SvelteKit's `error()` machinery picks them up.
- Sets `Cache-Control` headers per route based on the table in Section 2.7.

### 5.3.7 Application-level Search Quota Ledgers

Two D1-backed ledgers enforce search quotas that exceed what Cloudflare
WAF rate limiting can express on Pro (60s periods) or Business (10-min
periods). Both ledgers are checked before any Workers AI invocation, so
a blocked request never incurs AI cost.

**Ledger 1 — Per-IP hourly cap (500 / hour per `cf-connecting-ip`):**

1. Construct the hour bucket: `bucket = YYYY-MM-DD-HH` (UTC).
2. Atomic check-and-increment with a cap guard so blocked requests do
   not continue to inflate the counter:

   ```sql
   INSERT INTO search_quota_ip_ledger (bucket, client_ip, query_count)
   VALUES (?, ?, 1)
   ON CONFLICT(bucket, client_ip)
   DO UPDATE SET query_count = query_count + 1
     WHERE query_count < 500
   RETURNING query_count;
   ```

3. If the statement returns no row, the bucket was already at the cap:
   throw `429 RATE_LIMITED` with `retryAfterSeconds` computed as seconds
   until the next UTC hour. If the statement returns `query_count = 500`,
   allow the request; it is the 500th successful search in that bucket.

**Ledger 2 — Org-wide daily cap (50,000 / day across all IPs):**

1. Construct the day key: `day = YYYY-MM-DD` (UTC).
2. Atomic check-and-increment with the same cap-guard pattern:

   ```sql
   INSERT INTO search_quota_ledger (day, query_count)
   VALUES (?, 1)
   ON CONFLICT(day)
   DO UPDATE SET query_count = query_count + 1
     WHERE query_count < 50000
   RETURNING query_count;
   ```

3. If the statement returns no row, the daily org-wide bucket was already
   at the cap: throw `503 GLOBAL_QUOTA_EXHAUSTED` with
   `retryAfterSeconds` = seconds until midnight UTC. If the statement
   returns `query_count = 50000`, allow the request; it is the 50,000th
   successful search that day.

**Order of evaluation:** Ledger 1 (per-IP) is checked first to prevent a
single IP from exhausting the global daily counter for everyone else.
Only if the per-IP check passes does the org-wide ledger increment.

### 5.3.8 Shared Server-side Query Modules

The server-side query modules reside under `apps/app/src/lib/server/queries/`. They encapsulate the direct interactions with the database (D1, Vectorize, KV) to ensure consistency between API routes (`+server.ts`) and page-server loaders (`+page.server.ts`).

- `searchCves(query, filters, env, ctx)`: Implements the exact-match, lexical FTS5, Vectorize semantic query, Reciprocal Rank Fusion (RRF), and post-fusion D1 filtration pipeline. Also enforces the Application-level Search Quota Ledger (Section 5.3.7).
- `getCveDetail(cveId, env)`: Retrieves the core CVE record from D1 or KV cache, fetches related CWEs, CPEs, and references.
- `getAffectedProducts(vendor, product, limit, cursor, env)`: Queries the D1 database for vendors, products, versions, and maximum severity.
- `getThreatIntel(type, limit, cursor, env)`: Fetches lists of CISA KEV or EPSS top records.
- `getMetrics(window, env)`: Queries the Analytics Engine or `cve_metrics_daily` based on the specified window.
- `getAdminHealth(env)`: Gathers ingest run status, table counts, queue depths, and error metrics.

---

## 5.4 Workers AI Embedding Path (shared concern)

The embedding call is identical in both workers:

- Model: `@cf/baai/bge-base-en-v1.5`.
- Input: a single string, pre-truncated by the caller to ≤ 1500 chars.
- Output: a 768-dim `number[]`.
- **Shared contract** (`packages/contracts/src/embed.ts`) — type-only:

  ```ts
  export type EmbedFn = (env: { AI: Ai }, text: string) => Promise<number[]>;
  ```

- **Per-worker implementation** — each worker owns its concrete
  implementation at `apps/<worker>/src/lib/server/embed.ts`. The
  implementations must be byte-identical in behaviour: same model id,
  same input truncation rule, same single retry on HTTP 5xx with 250 ms
  delay, same propagation on second failure.

The duplication is deliberate: keeping `packages/contracts` as a
type-only package prevents runtime coupling between workers. The
function is ~15 lines and the conformance test (Section 6) verifies
both implementations produce the same vector for a fixed input.

---

## 5.5 Section 5 Deliverable Order

These steps execute in Phase 3 (ingestion) and Phase 4 (gateway).

**Phase 3 (ingest):**

1. Implement `packages/contracts/src/cve.ts` with the shapes in 5.1.3.
2. Implement the four source adapters as pure functions with unit tests.
3. Implement `processRecord(record, env, ctx)` covering the persistence
   sequence in 5.1.4.
4. Implement the cron handler with the dispatch table in 5.1.1.
5. Implement the retry-queue consumer that re-invokes `processRecord`.
6. Implement `runAgingSweep` (5.1.6).
7. End-to-end smoke: trigger the daily cron in staging against a small
   synthetic dataset; confirm D1 rows, Vectorize entries, KV deletions,
   and `ingest_run` markers all appear.

**Phase 4 (gateway):**

1. Implement the seven `/api/*` endpoints + `/api/admin/health`.
2. Implement `apps/app/src/lib/server/validate/` with one guard per
   endpoint.
3. Implement the `cacheRead` helper and wire it into the routes per
   Section 2.7.
4. Implement `hooks.server.ts` per 5.3.5–5.3.6.
5. End-to-end smoke: from an in-list IP, hit each endpoint with valid
   and invalid inputs; confirm response shapes and audit_log writes.
6. From an off-list IP, confirm `403 FORBIDDEN_NETWORK` envelope.
7. From an in-list IP, exceed the application-level per-IP hourly AI quota ledger and confirm `429
   RATE_LIMITED` envelope with `retryAfterSeconds` populated.
