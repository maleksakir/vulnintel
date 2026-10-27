# Threat-Lens CVE Hub

Serverless vulnerability intelligence platform. Ingests the NVD CVE corpus, CISA KEV, MITRE CVE list, and EPSS scores into Cloudflare D1. Exposes them through a SvelteKit UI and REST API deployed on Cloudflare Workers — secured behind an IP allowlist and WAF rules with no infrastructure to operate.

## Architecture

```
  Corp network (IP allowlist)
          │
  Cloudflare WAF + IP List
          │
  ┌───────┴──────────────────────────────────────────┐
  │  threat-lens-app  (Cloudflare Workers)            │
  │  SvelteKit 2 · Svelte 5 · adapter-cloudflare      │
  │                                                   │
  │  Bindings: D1 · Vectorize · KV · AI · Analytics  │
  └───────────────────────────────────────────────────┘
          │ D1 · Vectorize · KV · Queues
  ┌───────┴──────────────────────────────────────────┐
  │  threat-lens-ingest  (Cloudflare Workers)         │
  │  Cron-driven · no public routes                   │
  │                                                   │
  │  Sources: NVD · MITRE · CISA KEV · EPSS          │
  │  Bindings: D1 · Vectorize · KV · AI · Queues     │
  └───────────────────────────────────────────────────┘
```

The two workers share state only through Cloudflare-managed services (D1, Vectorize, KV, Queues). They never call each other over HTTP.

## Repository layout

```
threat-lens-cve-hub/
├── apps/
│   ├── app/                    # SvelteKit 2 app worker (UI + API gateway)
│   │   └── src/
│   │       ├── routes/         # SvelteKit file-based routes
│   │       │   ├── +page.svelte              # Dashboard
│   │       │   ├── search/                   # CVE search
│   │       │   ├── cve/[id]/                 # CVE detail
│   │       │   ├── affected-products/        # Vendor/product browser
│   │       │   ├── threat-intel/             # KEV + EPSS views
│   │       │   ├── admin/health/             # System health dashboard
│   │       │   └── api/                      # REST API endpoints
│   │       └── lib/
│   │           ├── server/                   # Server-only helpers + queries
│   │           └── ui/                       # Shared Svelte components
│   └── ingest/                 # Cron-driven ingest worker
│       └── src/
│           ├── adapters/       # NVD · MITRE · KEV · EPSS source adapters
│           ├── lib/server/     # processRecord · hash · embed · ingestRun
│           ├── pipelines/      # daily · kev · reconcile · aging · iplist
│           ├── scripts/        # backfill.ts — one-time corpus loader
│           └── index.ts        # Cron dispatch + queue consumer
├── packages/
│   └── contracts/              # Shared TypeScript types (no runtime code)
├── migrations/                 # D1 SQL migrations (0001–0006)
├── docs/
│   ├── spec/                   # Full platform specification (read-only reference)
│   └── network/                # IP allowlist ledger
├── pnpm-workspace.yaml
├── package.json
└── tsconfig.base.json
```

## Development

**Prerequisites:** Node 20+, pnpm 11+, Wrangler 4+

```sh
# Install all workspace dependencies
pnpm install

# Type-check all packages at once
pnpm check

# Type-check individual packages
pnpm --filter threat-lens-app check
pnpm --filter @threat-lens/ingest check
pnpm --filter @threat-lens/contracts check

# Local dev server for the app worker (with Miniflare)
pnpm --filter threat-lens-app dev

# Dry-run deploy (validates bindings resolve — run after provisioning)
pnpm --filter threat-lens-app exec wrangler deploy --env staging --dry-run
pnpm --filter @threat-lens/ingest exec wrangler deploy --env staging --dry-run
```

## UI Routes

| Route | Description |
|-------|-------------|
| `/` | Dashboard — KPI cards, severity chart, publication velocity, top vendors, KEV inflow |
| `/search` | Hybrid CVE search — FTS5 + vector + RRF fusion, severity/KEV/CVSS filters |
| `/cve/[id]` | CVE detail — CVSS metrics, threat intel (KEV/EPSS), CWEs, affected products, references |
| `/affected-products` | Vendor/product browser with cursor pagination |
| `/threat-intel` | CISA KEV list and EPSS top-scored CVEs in tab layout |
| `/admin/health` | System health — ingest staleness, queue depths, rate-limit stats (bearer token required) |

## REST API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/cve/:id` | CVE detail (KV-cached 300s) |
| `POST` | `/api/search` | Hybrid search with quota enforcement |
| `GET` | `/api/affected-products` | Vendor/product list with cursor pagination |
| `GET` | `/api/threat-intel/kev` | CISA KEV list (KV-cached 3600s) |
| `GET` | `/api/threat-intel/epss` | EPSS top CVEs by score (KV-cached 3600s) |
| `GET` | `/api/metrics/:window` | Platform metrics (KV-cached 300s) — windows: `1h` `24h` `7d` `30d` `90d` |
| `GET` | `/api/admin/health` | System health — requires `Authorization: Bearer <ADMIN_BEARER>` |

All endpoints return `ErrorEnvelope` JSON on error. The API enforces 500 req/hr per IP and 50k req/day org-wide via D1 ledger tables.

## Ingest Cron Schedule

| Cron | Pipeline | Description |
|------|----------|-------------|
| `0 1 * * *` | `runDailyFullDelta` | NVD + MITRE + EPSS 48h lookback |
| `0 */6 * * *` | `runKevFastLane` | CISA KEV full snapshot |
| `0 3 * * 0` | `runWeeklyReconciliation` | 30-day NVD re-sync |
| `30 2 * * *` | `runAgingSweep` | 24-month cutoff hard delete + metrics rollup |
| `0 4 * * *` | `runIpListPrune` | Expire temporary IP allowlist entries |

## Provisioning

Before deploying, provision the Cloudflare resources and fill the ID placeholders in both `wrangler.toml` files. See [docs/spec/RESOURCES.md](docs/spec/RESOURCES.md) for the full provisioning commands.

```sh
# Create D1 databases
wrangler d1 create cve_prod_d1
wrangler d1 create cve_staging_d1

# Create Vectorize indexes (768-dim, cosine)
wrangler vectorize create cve-vector-index --dimensions=768 --metric=cosine
wrangler vectorize create cve-vector-index-staging --dimensions=768 --metric=cosine

# Create KV namespaces
wrangler kv namespace create cve_cache_prod
wrangler kv namespace create cve_cache_staging

# Create Queues
wrangler queues create cve-ingest-retry
wrangler queues create cve-ingest-dlq

# Apply D1 migrations
wrangler d1 migrations apply cve_prod_d1
wrangler d1 migrations apply cve_staging_d1
```

## Secrets

Secrets are never in `wrangler.toml`. Set them per worker per environment:

```sh
# App worker
wrangler secret put ADMIN_BEARER --env staging          # Admin health endpoint bearer token
wrangler secret put ANALYTICS_QUERY_TOKEN --env staging  # Analytics query API (optional)

# Ingest worker
wrangler secret put NVD_API_KEY --env staging            # NVD API key (50 req/30s with key)
wrangler secret put CLOUDFLARE_API_TOKEN --env staging   # Queues API depth + IP List management
wrangler secret put CLOUDFLARE_ACCOUNT_ID --env staging  # Account ID for Cloudflare API calls
```

## Backfill

To load the entire NVD corpus on first deployment:

```sh
# From the ingest app directory
cd apps/ingest
wrangler dev --script-path scripts/backfill.ts
```

The backfill script checkpoints its progress in KV (`backfill:nvd:cursor`) and can resume after interruption. It applies KEV and EPSS overlays after the NVD pass. Set `SKIP_KEV=1` or `SKIP_EPSS=1` to skip those passes.

## Data Model

Stored in Cloudflare D1 (SQLite). Six migrations covering:

| Migration | Contents |
|-----------|----------|
| `0001_core_tables.sql` | `cve`, `cwe`, `cve_cwe`, `cpe`, `cve_reference`, `cve_state` |
| `0002_operational_tables.sql` | `cve_quarantine`, `ingest_run`, `audit_log`, `cve_source_provenance`, quota ledgers |
| `0003_indices.sql` | Performance indexes on hot query paths |
| `0004_fts5.sql` | `cve_search` and `cpe_search` FTS5 virtual tables + triggers |
| `0005_metrics_daily.sql` | `cve_metrics_daily` rollup table |
| `0006_cwe_catalog_seed.sql` | 161 CWE catalog entries |

Vectorize stores 768-dim cosine embeddings (`@cf/baai/bge-base-en-v1.5`) keyed by CVE ID. The two-hash strategy (`text_hash` + `state_hash`) avoids redundant AI calls — only records with changed description/CWEs/vendors re-embed.

## Phase Status

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | Bootstrap & scaffolding — monorepo, wrangler config, TypeScript, CSS tokens, UI component shell | Complete |
| 2 | D1 schema & migrations — 14 tables, FTS5, indexes, CWE catalog | Complete |
| 3 | Ingest pipeline — 4 source adapters, processRecord two-hash engine, 5 cron pipelines, retry queue | Complete |
| 4 | API gateway — 7 REST endpoints, hybrid search (FTS5 + Vectorize + RRF), quota, KV caching | Complete |
| 5 | UI — 6 page routes, 6 UI components, dark/light theme, active nav, admin health gate | Complete |
| 6 | Backfill — paginated NVD corpus loader with KV checkpoint, KEV+EPSS overlay passes | Complete |

## Spec

The full platform specification is in [docs/spec/](docs/spec/) and is the authoritative source of truth. Do not modify spec files when making code changes — reconcile code to spec or raise a spec change explicitly.

- [00-overview.md](docs/spec/00-overview.md) — Goals, locked decisions, and non-negotiable rules
- [01-bootstrap-and-deployment.md](docs/spec/01-bootstrap-and-deployment.md) — Repo layout, wrangler config, TypeScript profile, CSS tokens
- [02-page-topology-and-navigation.md](docs/spec/02-page-topology-and-navigation.md) — Route map, caching strategy, error boundaries
- [03-system-blueprints.md](docs/spec/03-system-blueprints.md) — D1 schema, Vectorize index, KV catalog, Analytics Engine schema
- [04-perimeter-security.md](docs/spec/04-perimeter-security.md) — IP allowlist, WAF rules, rate limiting
- [05-component-interactions.md](docs/spec/05-component-interactions.md) — Ingest sequence, API contracts, hybrid search, SvelteKit loaders
- [06-execution-plan.md](docs/spec/06-execution-plan.md) — Phase-by-phase build plan, acceptance criteria, risk register
