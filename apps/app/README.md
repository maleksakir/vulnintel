# threat-lens-app

SvelteKit 2 app worker — the public-facing request handler for Threat-Lens CVE Hub. Serves the UI and REST API on Cloudflare Workers via `@sveltejs/adapter-cloudflare`.

## Stack

| Layer | Technology |
|-------|------------|
| Framework | SvelteKit 2 + Svelte 5 (runes: `$state`, `$derived`, `$effect`, `$props`) |
| Runtime | Cloudflare Workers (`compatibility_date = 2026-05-22`, `nodejs_compat`) |
| Database | Cloudflare D1 (SQLite, read-mostly access pattern) |
| Search | Cloudflare Vectorize (768-dim cosine) + D1 FTS5 — fused with RRF |
| Cache | Cloudflare KV (`CACHE` namespace, read-through via `cacheReadJson`) |
| AI | Workers AI `@cf/baai/bge-base-en-v1.5` — query-time embeddings only |
| Telemetry | Analytics Engine — page views, search latencies, rate-limit events |
| UI primitives | Bits UI v1 (zero CSS, Svelte 5 native) |
| Styling | Pure CSS custom properties — no frameworks |
| Types | `@threat-lens/contracts` workspace package |

## Routes

### Pages

| Route | Load file | Description |
|-------|-----------|-------------|
| `/` | `+page.server.ts` | Dashboard — KPI cards, severity distribution, publication velocity, top vendors, KEV inflow |
| `/search` | `+page.server.ts` | CVE search with FTS5 + Vectorize hybrid pipeline, severity/KEV/CVSS filters |
| `/cve/[id]` | `+page.server.ts` | CVE detail — header, CVSS, threat intel, CWEs, CPE table, references |
| `/affected-products` | `+page.server.ts` | Vendor/product browser with cursor pagination |
| `/threat-intel` | `+page.server.ts` | CISA KEV list and EPSS top-CVEs in tab layout |
| `/admin/health` | `+page.server.ts` | System health dashboard — ingest staleness, queue depths, rate limits (bearer token gate) |

### API Endpoints

| Method | Route | Cache TTL | Description |
|--------|-------|-----------|-------------|
| `GET` | `/api/cve/:id` | 300s KV | CVE full detail |
| `POST` | `/api/search` | — | Hybrid search with per-IP + org-wide quota |
| `GET` | `/api/affected-products` | — | Vendor/product list, cursor paginated |
| `GET` | `/api/threat-intel/kev` | 3600s KV | CISA KEV list, cursor paginated |
| `GET` | `/api/threat-intel/epss` | 3600s KV | EPSS top CVEs by score, cursor paginated |
| `GET` | `/api/metrics/:window` | 300s KV | Platform metrics — `1h` `24h` `7d` `30d` `90d` |
| `GET` | `/api/admin/health` | no-store | System health — `Authorization: Bearer <ADMIN_BEARER>` required |

All endpoints return `application/json`. Errors use `ErrorEnvelope` shape defined in `@threat-lens/contracts`.

## Search Pipeline

```
POST /api/search
  │
  ├─ Quota check (500/hr per IP · 50k/day org)
  │
  ├─ Exact CVE ID? → D1 shortcut (skips FTS + Vectorize)
  │
  ├─ FTS5 lexical search → top 200 candidates
  ├─ Vectorize semantic search → top 200 candidates
  │     (embed query via Workers AI)
  │
  ├─ Reciprocal Rank Fusion (K=60)
  │     score = Σ 1/(K + rank)
  │
  ├─ D1 post-filter (vendor, publishedSince, kev, severity, minCvss)
  │
  └─ Fetch metadata + vendors → return SearchResponse
```

## Rate Limiting

Application-level quota enforced in D1 (no WAF Business tier required):

- **Per-IP hourly:** 500 requests/hr (`search_quota_ip_ledger`)
- **Org daily:** 50,000 requests/day (`search_quota_ledger`)
- Exceeded quota returns `429` with `Retry-After` header
- All quota events are written to `audit_log`

## KV Cache Keys

| Key pattern | TTL | Content |
|-------------|-----|---------|
| `cve:<cve_id>` | 300s | `CveDetailResponse` JSON |
| `threat:kev:list` | 3600s | First page of KEV list |
| `threat:epss:top:200` | 3600s | Top 200 EPSS scores |
| `dash:metrics:<window>` | 300s | `MetricsResponse` JSON |

Keys are invalidated by the ingest worker after record updates.

## UI Components (`src/lib/ui/`)

| Component | Description |
|-----------|-------------|
| `Modal.svelte` | Native `<dialog>` modal with backdrop, Escape key, focus management |
| `Toast.svelte` | Auto-dismissing notifications (4s default) with variant icons and slide-in animation |
| `Tooltip.svelte` | Hover/focus tooltip with open/close delay and 4 placement options |
| `SearchCombobox.svelte` | Debounced combobox (250ms) with keyboard navigation (↑↓ Enter Escape) |
| `Select.svelte` | Styled native `<select>` with custom chevron |
| `Tabs.svelte` | Keyboard-navigable tabs (Arrow keys, Home, End) with `aria-selected` |

## Bindings (wrangler.toml)

| Binding | Type | Purpose |
|---------|------|---------|
| `DB` | D1 | CVE database — read queries |
| `VECTORIZE` | Vectorize | Semantic similarity search |
| `CACHE` | KV | Response cache + invalidation |
| `AI` | Workers AI | Query-time embedding (`@cf/baai/bge-base-en-v1.5`) |
| `ANALYTICS` | Analytics Engine | Telemetry — search events, rate-limit hits |
| `ASSETS` | Static assets | SvelteKit build output |

## Secrets

| Secret | Description |
|--------|-------------|
| `ADMIN_BEARER` | Bearer token for `/api/admin/health` |
| `ANALYTICS_QUERY_TOKEN` | Optional — Analytics Engine query API |

Set via `wrangler secret put <NAME> --env <staging|production>`.

## Development Commands

```sh
# Type-check
pnpm --filter threat-lens-app check

# Local dev (Miniflare — no real D1/Vectorize, use wrangler dev for full fidelity)
pnpm --filter threat-lens-app dev

# Build
pnpm --filter threat-lens-app build

# Deploy to staging
pnpm --filter threat-lens-app exec wrangler deploy --env staging

# Deploy to production
pnpm --filter threat-lens-app exec wrangler deploy

# Generate Cloudflare env types
pnpm --filter threat-lens-app exec wrangler types --env-interface CloudflareEnv
```
