# threat-lens-ingest

Cron-driven ingest worker for Threat-Lens CVE Hub. Pulls vulnerability data from NVD, MITRE, CISA KEV, and EPSS, normalises it, and writes it to D1 + Vectorize. Has no public HTTP routes — `workers_dev = false`.

## Stack

| Layer | Technology |
|-------|------------|
| Runtime | Cloudflare Workers (`compatibility_date = 2026-05-22`, `nodejs_compat`) |
| Database | Cloudflare D1 (SQLite, write path) |
| Vector store | Cloudflare Vectorize — upsert on text change, metadata-only update on state change |
| AI | Workers AI `@cf/baai/bge-base-en-v1.5` — ingest-time embeddings |
| Cache | Cloudflare KV — write-only: invalidates `CACHE` keys after record updates |
| Retry | Cloudflare Queues (`cve-ingest-retry` → DLQ `cve-ingest-dlq`) |
| EPSS ingest | Cloudflare Queues (`epss-ingest` → DLQ `epss-ingest-dlq`) — decouples EPSS's D1 writes from the daily cron invocation (see below) |
| NVD ingest | Cloudflare Queues (`nvd-ingest` → DLQ `nvd-ingest-dlq`) — decouples NVD's per-record `processRecord()` D1/Vectorize/AI writes from the daily cron invocation, same reasoning as EPSS ingest (see below). Also reused by the weekly reconciliation producer (`reconcile.ts`), which feeds the same queue + consumer. **Not yet deployed** |
| KEV ingest | Cloudflare Queues (`kev-ingest` → DLQ `kev-ingest-dlq`) — decouples the 6-hourly KEV catalog's per-entry D1 change-detect + write work from the cron invocation; `kev.ts` is now a pure producer, `kevQueue.ts`'s consumer does the batched D1 work (`applyKevPatchBatch`). Replaces the old inline per-entry `applyKevPatch` loop that blew the 50-D1-query-per-invocation Free-plan cap on a 1,000+-entry catalog. **Not yet deployed** |
| MITRE ingest | Cloudflare Queues (`mitre-ingest` → DLQ `mitre-ingest-dlq`) — narrow CWE-only gap-fill lookup against NVD records with zero CWEs; replaces the old, broken full-MITRE-delta re-ingest (see below). **Not yet deployed** |
| OSV ingest | Cloudflare Queues (`osv-ingest` → DLQ `osv-ingest-dlq`) — carries both the daily discovery kick-off and per-record fetch work, since OSV has no cron slot of its own (see below). Deployed and live |
| Telemetry | Analytics Engine — one event per record, one event per pipeline run |
| Types | `@threat-lens/contracts` workspace package |

## Cron Schedule

| Expression | Pipeline | Description |
|------------|----------|-------------|
| `0 1 * * *` | `runDailyFullDelta` | NVD + MITRE + EPSS delta (48h lookback) — pure producer |
| `0 */6 * * *` | `runKevFastLane` | CISA KEV full snapshot (runs every 6 hours) — pure producer onto `kev-ingest` |
| `0 3 * * 0` | `runWeeklyReconciliation` | 30-day NVD re-sync to catch late edits — pure producer onto the existing `nvd-ingest` queue |
| `30 2 * * *` | `runAgingSweep` | 24-month hard-delete + metrics rollup |
| `0 4 * * *` | `runIpListPrune` | Expire temporary IP allowlist entries |

## Source Adapters (`src/adapters/`)

| Adapter | Source | Notes |
|---------|--------|-------|
| `nvd.ts` | NVD CVE API 2.0 | 2000 records/page · 600ms inter-page delay · Retry-After honoured |
| `mitre.ts` | MITRE public single-record API (`cveawg.mitre.org/api/cve/{id}`) | CWE-only gap-fill, one CVE ID per fetch — not a record source. Looks up CVE IDs NVD's own ingestion saw with zero CWEs; extracts the structured `cweId` or falls back to a free-text `/^CWE-(\d+)\b/` regex, capped at 10 CWEs/CVE. Replaces the old `fetchMitreDelta`/list-endpoint code, which called MITRE's Secretariat/Bulk-Download-only LIST endpoint (HTTP 400 for public callers, never worked in production) and fabricated synthetic CPEs — see `docs/EXECUTION_PLAN.md`'s Phase 0 MITRE row. **Not yet deployed** |
| `kev.ts` | CISA KEV JSON feed | Full snapshot on every run |
| `epss.ts` | EPSS CSV (gzip) | `DecompressionStream('gzip')` · yields per-CVE patches |
| `osv.ts` | OSV.dev (GHSA, CVE-linked only) | GCS `modified_id.csv` per-ecosystem export (`storage.googleapis.com`) for delta discovery · per-record REST fetch (`api.osv.dev/v1/vulns/{id}`) · 8 ecosystem dirs · 1MB/record cap · deployed and migration applied 2026-10-30, see `docs/EXECUTION_PLAN.md`'s Phase 2 row |

## Persistence Engine (`src/lib/server/processRecord.ts`)

The two-hash strategy avoids redundant D1 writes and AI calls:

```
processRecord(record)
  │
  ├─ computeTextHash   (SHA-256 of description + CWEs + top-5 vendors)
  ├─ computeStateHash  (SHA-256 of severity + cvss_base + kev_listed + epss_score + top_vendor)
  │
  ├─ text changed?
  │   └─ YES → full D1 write (4 batches) + new AI embedding + Vectorize upsert
  │
  ├─ state only changed?
  │   └─ YES → D1 state update + Vectorize metadata-only upsert (getByIds → reuse vector)
  │
  └─ no change? → skip (no-op)

  On D1 failure  → enqueue UPSERT_ALL  to retry queue
  On AI failure  → enqueue VECTORIZE_ONLY (re-embed on retry)
  On Vec failure → enqueue VECTORIZE_ONLY with pre-computed vector
```

### D1 Write Batches

| Batch | Tables written |
|-------|----------------|
| 1 | `cve`, `cve_state`, `cve_source_provenance` |
| 2 | `cve_cwe` |
| 3 | `cpe` (capped at 500 per CVE) |
| 4 | `cve_reference` (capped at 200 per CVE) |

## Pipelines (`src/pipelines/`)

| File | Pipeline | Key behaviour |
|------|----------|---------------|
| `daily.ts` | `runDailyFullDelta` | Pure producer for NVD, MITRE, and EPSS — fetches, chunks, and enqueues onto `nvd-ingest`, `mitre-ingest`, and `epss-ingest` respectively; zero D1/Vectorize/AI work of its own (that moved to the three queue consumers below). The NVD loop also collects the CVE IDs of any record it sees with zero CWEs (capped at 1,000/run, overflow logged) and chunks those onto `mitre-ingest`. Writes `ingest_run` rows for all three sources, reflecting enqueue outcome, not D1-write outcome |
| `nvdQueue.ts` | `runNvdConsumer` | Queue consumer for `nvd-ingest`/`nvd-ingest-staging`. One invocation per queued message (≤8 `NormalizedCveRecord`s, byte-capped at ~100KB), runs the unchanged `processRecord()` per record with its own fresh D1 budget. Split out from `daily.ts` for the same reason as `epssQueue.ts`: NVD's 48h delta processed inline could exceed the 50-D1-query-per-invocation Free-plan cap. **Not yet deployed** |
| `epssQueue.ts` | `runEpssConsumer` | Queue consumer for `epss-ingest`/`epss-ingest-staging`. One invocation per queued message (~1,000 EPSS patches); applies them to D1 via `applyEpssPatchBatch`'s two-hash-style change detection. Split out from `daily.ts` because FIRST.org's feed is a 250k+-row full daily snapshot — doing the change-detection reads + writes inline would exceed D1's 100-bound-param-per-query and 50-query-per-invocation Free-plan caps; each queue invocation gets its own fresh budget instead |
| `mitreQueue.ts` | `runMitreCweConsumer` | Queue consumer for `mitre-ingest`/`mitre-ingest-staging`. One invocation per queued message (≤20 CVE IDs); re-verifies each still has zero CWEs (a fresh D1 read, since time may have passed since `daily.ts` collected them), fetches MITRE's single-record endpoint per ID (bounded concurrency), and writes only `cwe`/`cve_cwe`/`cve_source_provenance` — never `cve`/`cpe`/`cve_reference`/hashes/Vectorize/AI/KV. **Not yet deployed** |
| `osv.ts` | `runOsvDiscovery` / `runOsvFetchBatch` | Queue consumer for `osv-ingest`/`osv-ingest-staging`, two message kinds. `OSV_DISCOVER` (kicked off daily from `daily.ts`, since OSV has no cron slot of its own) streams all 8 ecosystem dirs' `modified_id.csv`, skip-if-unchanged filters, runs a bounded re-link pass, and chunks the result into `OSV_FETCH` messages (20 items each). `OSV_FETCH` fetches+normalizes each item (bounded concurrency) and writes via `applyOsvPatchBatch`. Deployed and migration applied 2026-10-30 — see `docs/EXECUTION_PLAN.md`'s Phase 2 row |
| `kev.ts` | `runKevFastLane` | Pure producer — fetches the full CISA KEV catalog (zero D1 work, just an HTTP fetch), chunks it (`KEV_MESSAGE_CHUNK_SIZE`=500), and enqueues onto `kev-ingest`. Writes a `KEV` `ingest_run` row reflecting the ENQUEUE outcome. No longer invalidates `threat:kev:list` unconditionally — the consumer does that only when an entry actually changes. **Not yet deployed** |
| `kevQueue.ts` | `runKevConsumer` | Queue consumer for `kev-ingest`/`kev-ingest-staging`. One message (~500 patches) per invocation; applies them via `applyKevPatchBatch`'s batched change-detect + write (bounded D1-query count that does NOT grow with the number of changed entries). Split out from `kev.ts` for the same reason as `epssQueue.ts`. **Not yet deployed** |
| `nvdProducer.ts` | `enqueueNvdRecords` | Shared NVD producer helper — drains an async iterable of `NormalizedCveRecord`s, size-aware-batches (`NVD_QUEUE_MAX_RECORDS`/`NVD_QUEUE_MAX_BYTES`), and enqueues onto `nvd-ingest`. Used by `reconcile.ts`; `daily.ts` imports its sizing constants (and keeps its own loop because it also collects zero-CWE IDs for MITRE inline). Single source of truth for the NVD batch bounds both producers must agree on |
| `reconcile.ts` | `runWeeklyReconciliation` | Pure producer — fetches the 30-day NVD window and enqueues onto the EXISTING `nvd-ingest` queue via `enqueueNvdRecords` (no own queue). Replaces the old inline per-record `processRecord()` loop that hit the same 50-D1-query cap as the daily NVD delta, but over a 30-day window. The shared consumer's two-hash gate makes unchanged records cheap no-ops |
| `aging.ts` | `runAgingSweep` | Hard-deletes CVEs older than 24 months (KEV-exempt); rebuilds `cpe_search` FTS; writes `cve_metrics_daily` |
| `iplist.ts` | `runIpListPrune` | Reads Cloudflare IP List via API; deletes items with `expires:<timestamp>` in past |

## Queue Consumers

The `queue()` handler in `src/index.ts` dispatches on `batch.queue` name:

```
cve-ingest-retry → [ingest worker queue handler]
  │
  ├─ UPSERT_ALL   → processRecord (full path, D1 + Vectorize)
  └─ VECTORIZE_ONLY → processRecord (skips D1, re-runs Vectorize + optional pre-computed vector)
                                                    ↓ on 5th failure
                                            cve-ingest-dlq

epss-ingest (+ -staging) → runEpssConsumer (src/pipelines/epssQueue.ts)
  │
  └─ applyEpssPatchBatch — chunked SELECT (100 bound params/query) +
     batched writes (500/sub-batch) against cve_state, skip-if-unchanged
                                                    ↓ on 3rd failure
                                            epss-ingest-dlq

kev-ingest (+ -staging) → runKevConsumer (src/pipelines/kevQueue.ts)
  │
  └─ applyKevPatchBatch — chunked change-detect SELECT (100 bound params/query)
     + batched cve_state upserts + batched cve.state_hash recompute + a single
     multi-id Vectorize metadata upsert, skip-if-unchanged
                                                    ↓ on 3rd failure
                                            kev-ingest-dlq

nvd-ingest (+ -staging) → runNvdConsumer (src/pipelines/nvdQueue.ts)
  │                        (fed by BOTH daily.ts and reconcile.ts)
  └─ processRecord() per record (≤8/message, byte-capped) — full two-hash
     D1 + Vectorize + AI path, same as cve-ingest-retry's UPSERT_ALL
                                                    ↓ on 3rd failure
                                            nvd-ingest-dlq

mitre-ingest (+ -staging) → runMitreCweConsumer (src/pipelines/mitreQueue.ts)
  │
  └─ re-check zero-CWE qualification (fresh D1 read) → fetch MITRE's
     single-record endpoint per CVE ID (bounded concurrency) → write only
     cwe/cve_cwe/cve_source_provenance for CVEs that gained ≥1 CWE
                                                    ↓ on 3rd failure
                                            mitre-ingest-dlq

osv-ingest (+ -staging) → src/pipelines/osv.ts, dispatched by message kind
  │
  ├─ OSV_DISCOVER → runOsvDiscovery (cursor + 8-dir GCS scan + re-link pass
  │                 → chunks and sends OSV_FETCH messages)
  └─ OSV_FETCH    → runOsvFetchBatch → applyOsvPatchBatch (one db.batch()
                     call against osv_record_state/cve_osv_affected)
                                                    ↓ on 3rd failure
                                            osv-ingest-dlq
```

`max_batch_size = 1` on the `epss-ingest`, `kev-ingest`, `nvd-ingest`,
`mitre-ingest`, and `osv-ingest` consumers (`wrangler.toml`) means one queue
message = one invocation, so each gets its own fresh 50-D1-query budget — the
reason these queues exist rather than going through `cve-ingest-retry`.
`epss-ingest` and `osv-ingest` are deployed and live. `kev-ingest`,
`nvd-ingest`, and `mitre-ingest` are code-complete and tested but **not yet
deployed** (queues declared in `wrangler.toml` but not yet provisioned via
`wrangler queues create`, and the code not yet `wrangler deploy`d) — see
`docs/EXECUTION_PLAN.md`'s Phase 0 rows for status.

## Backfill (`src/scripts/backfill.ts`)

One-time full NVD corpus load for initial deployment.

```sh
# From the ingest app directory
cd apps/ingest
wrangler dev --script-path scripts/backfill.ts
```

**Features:**
- Pages through all NVD records (2000/page, 650ms delay per page)
- KV checkpoint (`backfill:nvd:cursor`, 14-day TTL) — safe to interrupt and resume
- Applies KEV overlay after NVD pass
- Applies EPSS overlay after KEV pass
- `SKIP_KEV=1` and `SKIP_EPSS=1` env vars skip the respective overlay passes

## Vectorize Metadata Shape

Each vector stored with six filterable metadata fields:

```ts
{
  severity:        'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE',
  cvss_base:       number | null,
  published_ms:    number,   // unix ms
  kev_listed:      0 | 1,
  epss_percentile: number | null,
  top_vendor:      string | null,
}
```

## KV Invalidation

The ingest worker deletes these keys after record updates so the app worker never serves stale snapshots:

| Trigger | Key(s) invalidated |
|---------|--------------------|
| CVE updated | `cve:<cve_id>` |
| KEV entry actually changed (in `applyKevPatchBatch`) | `cve:<cve_id>` + `threat:kev:list` — only on a real change, no longer unconditionally every 6-hourly run |
| Aging sweep complete | `dash:kpi:*` |

## Bindings (wrangler.toml)

| Binding | Type | Purpose |
|---------|------|---------|
| `DB` | D1 | CVE database — write path |
| `VECTORIZE` | Vectorize | Embedding store — upsert + metadata update |
| `CACHE` | KV | Cache invalidation (write-only intent) |
| `AI` | Workers AI | Ingest-time embedding (`@cf/baai/bge-base-en-v1.5`) |
| `ANALYTICS` | Analytics Engine | Pipeline telemetry |
| `RETRY_QUEUE` | Queue producer | Failed record retry |
| `EPSS_QUEUE` | Queue producer | EPSS patch chunks, produced by `daily.ts`, consumed by `epssQueue.ts` |
| `KEV_QUEUE` | Queue producer | CISA KEV catalog patch chunks (≤500), produced by `kev.ts`, consumed by `kevQueue.ts`. Code-complete, **not yet deployed** |
| `NVD_QUEUE` | Queue producer | NVD `NormalizedCveRecord` batches (≤8, byte-capped), produced by `daily.ts`, consumed by `nvdQueue.ts`. Code-complete, **not yet deployed** |
| `MITRE_QUEUE` | Queue producer | Zero-CWE CVE ID chunks (≤20), produced by `daily.ts`'s NVD section, consumed by `mitreQueue.ts`. Code-complete, **not yet deployed** |
| `OSV_QUEUE` | Queue producer | OSV discover/fetch messages, produced by `daily.ts` (kick-off) and `pipelines/osv.ts` itself (fetch chunks), consumed by `pipelines/osv.ts`. Deployed and live (2026-10-30) |

## Secrets

| Secret | Description |
|--------|-------------|
| `NVD_API_KEY` | NVD API key — raises rate limit to 50 req/30s |
| `CLOUDFLARE_API_TOKEN` | Cloudflare API token — Queue depth queries + IP List management |
| `CLOUDFLARE_ACCOUNT_ID` | Cloudflare account ID |

Set via `wrangler secret put <NAME> --env <staging|production>`.

## Development Commands

```sh
# Type-check
pnpm --filter @threat-lens/ingest check

# Deploy to staging
pnpm --filter @threat-lens/ingest exec wrangler deploy --env staging

# Deploy to production
pnpm --filter @threat-lens/ingest exec wrangler deploy

# Trigger a cron manually in staging
wrangler cron trigger --name threat-lens-ingest-staging "0 1 * * *"

# Run backfill script
cd apps/ingest && wrangler dev --script-path scripts/backfill.ts
```
