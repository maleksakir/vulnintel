# Section 1 — Bootstrapping & Deployment Configuration (v2)

This section defines the repository layout, language and styling foundations, and
the Cloudflare deployment topology for **Threat-Lens CVE Hub**. It supersedes
the v1 draft and incorporates all corrections from the validation pass.

---

## 1.1 Repository Layout

The project is a single Git repository organised as a **pnpm workspace** with
two deployable workers and one shared package. This layout enforces the
Separation-of-Duties contract between the request-handling and ingestion
workers without duplicating type definitions or migrations.

```
threat-lens-cve-hub/
├── apps/
│   ├── app/                  # threat-lens-app worker (SvelteKit 2 + Svelte 5)
│   │   ├── src/
│   │   ├── static/
│   │   ├── svelte.config.js
│   │   ├── tsconfig.json
│   │   ├── package.json
│   │   └── wrangler.toml
│   └── ingest/               # threat-lens-ingest worker (cron-driven)
│       ├── src/
│       ├── tsconfig.json
│       ├── package.json
│       └── wrangler.toml
├── packages/
│   └── contracts/            # Shared TypeScript types (API envelopes, records)
│       ├── src/
│       ├── tsconfig.json
│       └── package.json
├── migrations/               # D1 migrations (shared schema, applied once)
├── docs/
│   └── spec/                 # This specification set
├── .gitignore
├── package.json              # Workspace root, scripts only
├── pnpm-workspace.yaml
└── tsconfig.base.json        # Shared strict TS settings
```

**Why pnpm workspaces:** native dependency hoisting, deterministic installs,
explicit `workspace:*` protocol for the shared `contracts` package, and lower
disk usage than npm or yarn for two-app repositories.

---

## 1.2 Framework & Language Foundations

### 1.2.1 Runtime stack

- **Svelte 5** with runes-based reactivity (`$state`, `$derived`, `$effect`,
  `$props`). Legacy stores (`writable`, `readable`) are not used in new code.
- **SvelteKit 2** application shell with file-based routing.
- **Adapter:** `@sveltejs/adapter-cloudflare` (Workers Static Assets mode,
  **not** the legacy `adapter-cloudflare-workers` and **not** Workers Sites).
- **Cron-only worker** (`apps/ingest`) uses the Workers ESM module format
  directly, with no SvelteKit dependency, to keep its cold-start surface
  minimal.

### 1.2.2 Shared `tsconfig.base.json`

The base config enforces strict typing across both workers and the contracts
package. Each project extends it and adds its own `compilerOptions.outDir` and
`include` paths.

| Setting                             | Value       |
|-------------------------------------|-------------|
| `target`                            | `ES2023`    |
| `module`                            | `ESNext`    |
| `moduleResolution`                  | `Bundler`   |
| `strict`                            | `true`      |
| `noUncheckedIndexedAccess`          | `true`      |
| `noImplicitOverride`                | `true`      |
| `exactOptionalPropertyTypes`        | `true`      |
| `noFallthroughCasesInSwitch`        | `true`      |
| `noUnusedLocals`                    | `true`      |
| `verbatimModuleSyntax`              | `true`      |
| `isolatedModules`                   | `true`      |
| `allowImportingTsExtensions`        | `false`     |
| `esModuleInterop`                   | `false`     |
| `forceConsistentCasingInFileNames`  | `true`      |
| `skipLibCheck`                      | `true`      |

### 1.2.3 Type-check gating

- `svelte-check` runs on `apps/app` as a pre-commit hook and a CI gate.
- `tsc --noEmit` runs on `apps/ingest` and `packages/contracts` in the same
  gate.
- Any change to `packages/contracts` triggers a rebuild of both consumers
  via pnpm's `--filter` graph.

---

## 1.3 Styling Foundations

### 1.3.1 Forbidden dependencies

The following will not appear in any `package.json` in this repository:
Tailwind, UnoCSS, Bootstrap, Skeleton, shadcn-svelte, Flowbite, Tailwind
plugins, CSS-in-JS runtimes (styled-components, emotion, vanilla-extract),
or any vendor-branded utility framework.

### 1.3.2 Permitted layers

- **`apps/app/src/app.css`** — single global file owning the design token layer
  (CSS custom properties only), the CSS reset, and base element rules.
- **Per-route stylesheets** (`+layout.css`, `+page.css`) — optional, loaded via
  SvelteKit's automatic CSS injection.
- **Scoped `<style>` blocks** inside Svelte components — for component-local
  rules that reference the token layer.
- **`data-theme="dark"` attribute** on `<html>` — toggles the dark token set.

### 1.3.3 Headless behavior layer

- **Bits UI v2** (Svelte 5 native, ships zero CSS) provides correct behavior
  and accessibility for: Combobox, Dialog, Tabs, Tooltip, Select, Toast.
- Each consumed primitive is wrapped exactly once in `apps/app/src/lib/ui/`
  (e.g. `Modal.svelte`, `SearchCombobox.svelte`). The rest of the application
  imports only from `$lib/ui/`, never from `bits-ui` directly. This bounds the
  dependency to a single replaceable seam.
- Components not provided by Bits UI (Accordion, Pagination, SortableTable,
  Skip-link, Badge, VisuallyHidden) are hand-rolled against the token layer.

### 1.3.4 Layout primitives

CSS Grid and Flexbox only. Container queries are permitted. No CSS
preprocessors (Sass, Less). PostCSS is allowed solely for `autoprefixer` and
`postcss-nested` to reduce stylesheet noise; no third-party PostCSS plugins
beyond those.

---

## 1.4 Cloudflare Deployment Configuration

Both workers ship from the same repository under distinct `wrangler.toml`
files. They share the D1 database and Vectorize index but bind them with
different access intents.

### 1.4.1 `apps/app/wrangler.toml`

```toml
name = "threat-lens-app"
main = ".svelte-kit/cloudflare/_worker.js"
compatibility_date = "2026-05-22"
compatibility_flags = ["nodejs_compat"]

# Static assets emitted by adapter-cloudflare. The SPA not-found handling
# routes deep-link cold loads (e.g. /cve/CVE-2026-12345 typed directly)
# to the worker entry instead of returning a static 404.
[assets]
directory = ".svelte-kit/cloudflare"
binding = "ASSETS"
not_found_handling = "single-page-application"
run_worker_first = true

# Production database. The app worker uses a read-mostly access pattern;
# write paths are gated by the application layer to admin-only routes.
[[d1_databases]]
binding = "DB"
database_name = "cve_prod_d1"
database_id = "REPLACE_AFTER_PROVISIONING"
migrations_dir = "../../migrations"

# Vector index for hybrid semantic search.
[[vectorize]]
binding = "VECTORIZE"
index_name = "cve-vector-index"

# Telemetry sink for request-side metrics (search latencies, page views,
# rate-limit hits, audit log of IP + request_id).
[[analytics_engine_datasets]]
binding = "ANALYTICS"
dataset = "cve_analytics_dataset"

# Workers AI binding for query-time embeddings on /api/search.
[ai]
binding = "AI"

# Hot-path response cache (metric snapshots, KEV list, CVE detail).
[[kv_namespaces]]
binding = "CACHE"
id = "REPLACE_AFTER_PROVISIONING"

[env.staging]
name = "threat-lens-app-staging"

[env.staging.assets]
directory = ".svelte-kit/cloudflare"
binding = "ASSETS"
not_found_handling = "single-page-application"
run_worker_first = true

[[env.staging.d1_databases]]
binding = "DB"
database_name = "cve_staging_d1"
database_id = "REPLACE_AFTER_PROVISIONING"
migrations_dir = "../../migrations"

[[env.staging.vectorize]]
binding = "VECTORIZE"
index_name = "cve-vector-index-staging"

[[env.staging.analytics_engine_datasets]]
binding = "ANALYTICS"
dataset = "cve_analytics_dataset_staging"

# Wrangler does NOT inherit top-level bindings into [env.staging]; every
# binding must be redeclared here. The [env.staging.ai] block is required
# or env.AI will be undefined in the staging deploy.
[env.staging.ai]
binding = "AI"

[[env.staging.kv_namespaces]]
binding = "CACHE"
id = "REPLACE_AFTER_PROVISIONING"
```

### 1.4.2 `apps/ingest/wrangler.toml`

```toml
name = "threat-lens-ingest"
main = "src/index.ts"
compatibility_date = "2026-05-22"
compatibility_flags = ["nodejs_compat"]

# This worker has no public routes. It is invoked solely by cron triggers
# and the retry queue. Workers.dev route is disabled in the dashboard.
workers_dev = false

# Cron schedule. Each cron expression dispatches to a distinct pipeline
# inside the scheduled() handler. Full dispatch table is in Section 5.1.1.
[triggers]
crons = [
  "0 1 * * *",       # 01:00 UTC daily — NVD + MITRE + EPSS full delta
  "0 */6 * * *",     # every 6 hours — CISA KEV fast lane
  "0 3 * * 0",       # 03:00 UTC Sunday — 30-day reconciliation sweep
  "30 2 * * *",      # 02:30 UTC daily — aging sweep (24-month cutoff)
  "0 4 * * *",       # 04:00 UTC daily — IP allowlist expiry prune
]

[[d1_databases]]
binding = "DB"
database_name = "cve_prod_d1"
database_id = "REPLACE_AFTER_PROVISIONING"
migrations_dir = "../../migrations"

[[vectorize]]
binding = "VECTORIZE"
index_name = "cve-vector-index"

[[analytics_engine_datasets]]
binding = "ANALYTICS"
dataset = "cve_analytics_dataset"

# Workers AI binding for ingest-time embeddings (only when text fields change).
[ai]
binding = "AI"

# Same KV namespace the app worker uses. The ingest worker holds write-only
# intent: it deletes cache keys after a record is updated so the app worker
# does not serve a stale snapshot. See Section 2.7 for the invalidation map.
[[kv_namespaces]]
binding = "CACHE"
id = "REPLACE_AFTER_PROVISIONING"

# Retry queue for failed per-record persistence. DLQ binding is in the
# producer config; the queue consumer worker subscribes separately.
[[queues.producers]]
queue = "cve-ingest-retry"
binding = "RETRY_QUEUE"

[[queues.consumers]]
queue = "cve-ingest-retry"
max_batch_size = 25
max_batch_timeout = 30
max_retries = 5
dead_letter_queue = "cve-ingest-dlq"

[env.staging]
name = "threat-lens-ingest-staging"

# Wrangler does NOT inherit top-level bindings or triggers into
# [env.staging]; every binding and the cron list must be redeclared here.

[env.staging.triggers]
crons = [
  "0 1 * * *",
  "0 */6 * * *",
  "0 3 * * 0",
  "30 2 * * *",
  "0 4 * * *",
]

[[env.staging.d1_databases]]
binding = "DB"
database_name = "cve_staging_d1"
database_id = "REPLACE_AFTER_PROVISIONING"
migrations_dir = "../../migrations"

[[env.staging.vectorize]]
binding = "VECTORIZE"
index_name = "cve-vector-index-staging"

[[env.staging.analytics_engine_datasets]]
binding = "ANALYTICS"
dataset = "cve_analytics_dataset_staging"

[env.staging.ai]
binding = "AI"

[[env.staging.kv_namespaces]]
binding = "CACHE"
id = "REPLACE_AFTER_PROVISIONING"

[[env.staging.queues.producers]]
queue = "cve-ingest-retry-staging"
binding = "RETRY_QUEUE"

[[env.staging.queues.consumers]]
queue = "cve-ingest-retry-staging"
max_batch_size = 25
max_batch_timeout = 30
max_retries = 5
dead_letter_queue = "cve-ingest-dlq-staging"
```

### 1.4.3 Why these specific choices

- **`compatibility_flags = ["nodejs_compat"]`** — the v1 spec used the
  deprecated `node_compat` flag. The current flag is `nodejs_compat`, and it
  requires a compatibility date on or after `2024-09-23`. Our date
  (`2026-05-22`) satisfies this.
- **`[assets]` instead of `[site]`** — `[site]` is the legacy Workers Sites
  mechanism. The current adapter emits to Workers Static Assets, which is
  bound via `[assets]` and served by the platform without invoking a worker
  on cache hit.
- **`[[vectorize]]` instead of `[[vector_indexes]]`** — the binding type in
  current Wrangler is `vectorize`. The binding name `VECTORIZE` replaces the
  v1 misnomer `AI_SEARCH` (AI Search is a different Cloudflare product, namely
  AutoRAG, not what we need).
- **`workers_dev = false` on ingest** — the ingest worker must never be
  reachable from the public internet. Cron and queue triggers are the only
  invocation paths.
- **Two `[ai]` bindings** — Workers AI is used for query-time embeddings (app
  worker) and ingest-time embeddings (ingest worker). Both bind the same way.
- **`CACHE` KV namespace on both workers** — the app worker reads and writes
  cached snapshots; the ingest worker invalidates them on record update.
- **Wrangler env inheritance** — Wrangler does **not** inherit top-level
  bindings into named environments. Every `[block]` and `[[block]]` at the
  top of a `wrangler.toml` file is implicitly scoped to the default
  (production) environment only. Each binding must be re-declared under
  `[env.<name>.…]` for that environment, including `[env.<name>.triggers]`
  if crons should fire. This is the single most common source of "works in
  prod, missing in staging" errors and is the reason both `wrangler.toml`
  files above repeat every block twice.
- **Wrangler version pinning** — pin `wrangler` in the root `package.json`
  (e.g. `"wrangler": "^4.0.0"` or whichever major is current at Phase 1
  start). The binding-syntax assumptions in this spec (`[[vectorize]]`,
  `[assets]`, `nodejs_compat`) are version-sensitive; an unpinned wrangler
  will drift between developer machines.

### 1.4.4 Secrets

The following secrets are provisioned via `wrangler secret put` per worker
and per environment. They never appear in `wrangler.toml`.

| Secret                  | Workers   | Purpose                                       |
|-------------------------|-----------|-----------------------------------------------|
| `NVD_API_KEY`           | ingest    | Raises NVD rate limit from 5/30s to 50/30s    |
| `ANALYTICS_QUERY_TOKEN` | app       | Bearer token for Analytics Engine SQL HTTP API|
| `ADMIN_BEARER`          | app       | Protects `/api/admin/health` and admin routes |
| `CLOUDFLARE_API_TOKEN`  | app, ingest| Cloudflare API token with `Account.IP Lists` (Edit) and `Account.Queues` (Read) permissions |
| `CLOUDFLARE_ACCOUNT_ID` | app, ingest| Cloudflare Account ID for API queries and IP List operations |

---

## 1.5 Phase 1 Bootstrapping Steps (deliverable order)

This is the strict sequence the implementer follows. Each step produces a
verifiable artifact before the next begins.

1. **Initialise the workspace.** Create the repo skeleton from Section 1.1,
   the root `package.json`, `pnpm-workspace.yaml`, and `tsconfig.base.json`.
   Verify `pnpm install` resolves cleanly with zero dependencies.
2. **Scaffold `apps/app`.** Use the SvelteKit 2 minimal template with
   `--types=typescript --eslint --prettier`. Install `@sveltejs/adapter-cloudflare`.
   Configure `svelte.config.js` to use the Cloudflare adapter with the
   Static Assets output mode.
3. **Scaffold `apps/ingest`.** Hand-write the worker entry — no template.
   `src/index.ts` exports `fetch`, `scheduled`, and `queue` handlers from
   placeholder modules. Confirm `wrangler deploy --dry-run --outdir=.dryrun`
   succeeds.
4. **Scaffold `packages/contracts`.** Create the package with no
   implementation, only the exported type names that Sections 3 and 5 will
   fill in (`NormalizedCveRecord`, `CveDetail`, `SearchRequest`,
   `SearchResponse`, `ErrorEnvelope`).
5. **Author the design token layer.** Write `apps/app/src/app.css` with the
   complete CSS custom property catalog (colour scale, type scale, spacing
   scale, radii, motion curves, z-index strata) under `:root` and
   `[data-theme="dark"]`. Do not yet style components.
6. **Install Bits UI.** Add `bits-ui` to `apps/app`. Create
   `apps/app/src/lib/ui/` with empty wrapper Svelte files for each consumed
   primitive (`Modal.svelte`, `SearchCombobox.svelte`, `Tabs.svelte`,
   `Tooltip.svelte`, `Select.svelte`, `Toast.svelte`). Bodies are filled in
   Phase 5.
7. **Provision Cloudflare resources** (manual or scripted via Wrangler):
   D1 databases (prod + staging), Vectorize indexes, Analytics Engine
   datasets, KV namespace, Queue `cve-ingest-retry`, and Queue
   `cve-ingest-dlq`. Capture all generated IDs into a sealed `RESOURCES.md`
   under `docs/spec/`.
8. **Fill the `wrangler.toml` placeholders** with the captured IDs. Verify
   both workers deploy to staging cleanly with `wrangler deploy --env staging
   --dry-run`.
9. **Configure secrets** in both workers for both environments using
   `wrangler secret put`.
10. **Smoke-deploy** the empty app worker and ingest worker to staging.
    Confirm the app worker returns the default SvelteKit landing page and the
    ingest worker reports its scheduled bindings in the Cloudflare dashboard.

The perimeter security configuration (IP allowlist, WAF rules, rate limits)
is deferred to Section 4 and applied as the second deliverable inside
Phase 1.
