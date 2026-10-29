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
| OSV ingest | Cloudflare Queues (`osv-ingest` → DLQ `osv-ingest-dlq`) — carries both the daily discovery kick-off and per-record fetch work, since OSV has no cron slot of its own (see below) |
| Telemetry | Analytics Engine — one event per record, one event per pipeline run |
| Types | `@threat-lens/contracts` workspace package |

## Cron Schedule

| Expression | Pipeline | Description |
|------------|----------|-------------|
| `0 1 * * *` | `runDailyFullDelta` | NVD + MITRE + EPSS delta (48h lookback) |
| `0 */6 * * *` | `runKevFastLane` | CISA KEV full snapshot (runs every 6 hours) |
| `0 3 * * 0` | `runWeeklyReconciliation` | 30-day NVD re-sync to catch late edits |
| `30 2 * * *` | `runAgingSweep` | 24-month hard-delete + metrics rollup |
| `0 4 * * *` | `runIpListPrune` | Expire temporary IP allowlist entries |

## Source Adapters (`src/adapters/`)

| Adapter | Source | Notes |
|---------|--------|-------|
| `nvd.ts` | NVD CVE API 2.0 | 2000 records/page · 600ms inter-page delay · Retry-After honoured |
| `mitre.ts` | MITRE CVE Services API | 500 records/page · CVE JSON 5.0 format |
| `kev.ts` | CISA KEV JSON feed | Full snapshot on every run |
| `epss.ts` | EPSS CSV (gzip) | `DecompressionStream('gzip')` · yields per-CVE patches |
| `osv.ts` | OSV.dev (GHSA, CVE-linked only) | GCS `modified_id.csv` per-ecosystem export (`storage.googleapis.com`) for delta discovery · per-record REST fetch (`api.osv.dev/v1/vulns/{id}`) · 8 ecosystem dirs · 1MB/record cap · **not yet deployed, see `docs/EXECUTION_PLAN.md`** |

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
| `daily.ts` | `runDailyFullDelta` | Runs NVD → MITRE inline (`processRecord` per record). EPSS is fetch-chunk-enqueue only — no D1 writes in this invocation, see `epssQueue.ts` below. Writes `ingest_run` rows for all three sources (EPSS's reflects enqueue outcome, not D1-write outcome) |
| `epssQueue.ts` | `runEpssConsumer` | Queue consumer for `epss-ingest`/`epss-ingest-staging`. One invocation per queued message (~1,000 EPSS patches); applies them to D1 via `applyEpssPatchBatch`'s two-hash-style change detection. Split out from `daily.ts` because FIRST.org's feed is a 250k+-row full daily snapshot — doing the change-detection reads + writes inline would exceed D1's 100-bound-param-per-query and 50-query-per-invocation Free-plan caps; each queue invocation gets its own fresh budget instead |
| `osv.ts` | `runOsvDiscovery` / `runOsvFetchBatch` | Queue consumer for `osv-ingest`/`osv-ingest-staging`, two message kinds. `OSV_DISCOVER` (kicked off daily from `daily.ts`, since OSV has no cron slot of its own) streams all 8 ecosystem dirs' `modified_id.csv`, skip-if-unchanged filters, runs a bounded re-link pass, and chunks the result into `OSV_FETCH` messages (20 items each). `OSV_FETCH` fetches+normalizes each item (bounded concurrency) and writes via `applyOsvPatchBatch`. **Not yet deployed** — see `docs/EXECUTION_PLAN.md`'s Phase 2 row for status, including an open security finding that blocks deploy |
| `kev.ts` | `runKevFastLane` | Applies all KEV patches; invalidates `threat:kev:list` KV key |
| `reconcile.ts` | `runWeeklyReconciliation` | 30-day NVD window; two-hash means unchanged records are cheap no-ops |
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

osv-ingest (+ -staging) → src/pipelines/osv.ts, dispatched by message kind
  │
  ├─ OSV_DISCOVER → runOsvDiscovery (cursor + 8-dir GCS scan + re-link pass
  │                 → chunks and sends OSV_FETCH messages)
  └─ OSV_FETCH    → runOsvFetchBatch → applyOsvPatchBatch (one db.batch()
                     call against osv_record_state/cve_osv_affected)
                                                    ↓ on 3rd failure
                                            osv-ingest-dlq
```

`max_batch_size = 1` on the `epss-ingest` and `osv-ingest` consumers
(`wrangler.toml`) means one queue message = one invocation, so each gets its
own fresh 50-D1-query budget — the reason these queues exist rather than
EPSS/OSV going through `cve-ingest-retry`. **Not yet deployed** — see
`docs/EXECUTION_PLAN.md`'s Phase 2 row for status.

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
| KEV patch applied | `threat:kev:list` |
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
| `OSV_QUEUE` | Queue producer | OSV discover/fetch messages, produced by `daily.ts` (kick-off) and `pipelines/osv.ts` itself (fetch chunks), consumed by `pipelines/osv.ts`. **Not yet deployed** |

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
