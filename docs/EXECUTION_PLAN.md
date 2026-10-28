# Threat-Lens Execution Plan

Durable, team-visible map from the [platform strategy](../CLAUDE.md) to concrete
work: what gets built, in what order, by which agent, with what tools, and
where in the repo. The full research/reasoning behind each decision lives in
the roadmap artifact from the 2026-10-27 research session — this file is the
execution-tracking layer on top of it. Update the **Status** column as work
lands; don't let this drift from reality (see `docs-writer`'s charter).

Agent names below (`planner`, `cf-backend-dev`, `sveltekit-dev`, `deployer`,
`qa-tester`, `security-reviewer`, `docs-writer`) are the project's own
subagents — see `.claude/agents/*.md`. "Me" means the orchestrating session
handles it directly (usually because it needs the Cloudflare API token, or is
an account-level/security-boundary decision not safe to hand to a subagent).

## Phase 0 — Stop the bleeding (free-tier-only)

| Item | Agent | How | Status |
|---|---|---|---|
| EPSS/KEV change-detection: batch the D1 read | `cf-backend-dev` | `WHERE cve_id IN (...)` chunked reads, 200/chunk, in `apps/ingest/src/lib/server/processRecord.ts` | ✅ done (`948b99f`) |
| `quota.ts`: move per-IP check off D1 | `cf-backend-dev` | Workers-native `[[ratelimits]]` binding, D1 keeps only the org-wide daily counter | ✅ done (`948b99f`) |
| Bits UI version drift (1.3.16 → 2.20.2) | `cf-backend-dev` | `package.json` bump + `pnpm install` — zero runtime impact, unused dependency today | ✅ done (`f94d19a`) |
| Native Workers Logs | `deployer` | `[observability] enabled = true` in both `wrangler.toml` files | ✅ done (`33ef4ed`) |
| D1 size (500.98MB, at the 500MB free cap) | Me | Blocked until the daily D1 read-quota resets (00:00 UTC) — query `dbstat`-equivalent table sizes for real, then decide FTS5/retention changes with actual numbers, not a guess | ⏸ blocked until quota resets |
| `ADMIN_BEARER` URL leak | `cf-backend-dev` | Cookie + redirect + constant-time compare, `apps/app/src/routes/admin/health/` | ✅ done (`9f7c870`) |
| Public API routes other than search have no quota/rate-limit | Me (fixed directly) | Found by `security-reviewer` 2026-10-28: only `searchCves.ts` called `checkAndIncrementQuota`. Added a lighter `checkRateLimit()` (native binding only, no D1/KV cost) to `cve/[id]`, `affected-products`, `metrics/[window]`, `threat-intel/kev`, `threat-intel/epss` — shares the same bucket as search so route-switching doesn't bypass it | ✅ done (`546b36b`) |

## Phase 1 — Foundation & hygiene

| Item | Agent | How | Status |
|---|---|---|---|
| Testing infra | `qa-tester` | `@cloudflare/vitest-plugin` (current name — `vitest-pool-workers` was renamed Aug 2026) for `apps/app` + `apps/ingest`; D1/KV/Queues run real against `workerd`, Vectorize/AI mocked per Cloudflare's own fixtures. Priority target: `processRecord.ts`'s change-detection paths — the exact logic that caused the KV incident. | ✅ done (`233e172`) — 16 tests (12 ingest + 4 app), all passing; `tsc --noEmit` clean repo-wide |
| CI/CD | `deployer`, fixed by `security-reviewer` findings | GitHub Actions: PR workflow (lint + typecheck + vitest-plugin tests, required check) + merge-to-`main` deploy workflow using `cloudflare/wrangler-action@v4` **pinned to a commit SHA** (not the floating tag — see the May 2026 supply-chain note in the roadmap). Uses the already-declared but unused `[env.staging]` blocks. | ✅ done — `218777f` (initial) had a **critical** vuln (fork-PR could reach the deploy job's `CLOUDFLARE_API_TOKEN` via `workflow_run` matching an attacker-controlled `head_branch`) plus a CI job broken on a clean checkout; both fixed in a follow-up commit (reusable-workflow `needs:` gating instead of `workflow_run`, added the missing `apps/app` build step before tests). 3 of 5 pinned action SHAs independently re-verified against GitHub's API, 2 not yet re-confirmed. `CLOUDFLARE_API_TOKEN` secret and both the `staging` and `production` GitHub Environments (the latter needs required reviewers) still need manual setup |
| Biome (`.ts` files) | — (tooling, no agent role fits cleanly) | `.ts` across all 3 packages; keep `prettier-plugin-svelte` for `.svelte` (Biome's Svelte support is still experimental) | ✅ done (`723c906`) — `biome.json`, scoped to `**/*.ts` only; `.svelte` untouched (no Svelte formatter exists in-repo). `pnpm lint` / `pnpm lint:fix` |
| Renovate | — (tooling) | Mend-hosted GitHub App config, grouped `@cloudflare/*` bumps so `wrangler`/`workers-types` can't silently drift between the two Workers | ✅ done (`723c906`) — `renovate.json`, `config:recommended` + a `Cloudflare Workers packages` group (`wrangler`, `@cloudflare/*`). GitHub App install is an account-level step, still outstanding |
| Cloudflare Access on `/admin/*` | Me | Account-level Zero Trust config via the Cloudflare API — replaces the Phase 0 cookie stopgap. Needs explicit confirmation before touching account auth boundaries. | ⏸ after Phase 1 code lands |
| Review pass | `security-reviewer` | Checks the CI secret handling, SHA-pinning, and whatever the above four produce | ✅ done — first attempt crashed on a network error mid-review (zero findings, incorrectly recorded as "clean" by a downstream agent — corrected here). Re-run found 3 ship-blockers (fork-PR→prod-token vuln in `deploy.yml`, broken `apps/app` CI test job, the false-clean doc claim itself) plus several mediums (`ADMIN_BEARER` fails open when unset, staging missing its rate-limiter binding, staging duplicating the full prod cron schedule against the 5-cron account cap) — all fixed in the same pass as this doc update. Also surfaced a separate, pre-existing, still-open production issue: only the search API route is quota/rate-limited, not `/api/cve/[id]`, `/api/threat-intel/kev`, or `/api/threat-intel/epss` — same bug shape as the 2026-10-27 KV incident, tracked separately |
| Docs sync | `docs-writer` | Updates `CLAUDE.md`/READMEs to describe the new testing/CI setup once it's real, not aspirational | ✅ done — `CLAUDE.md` Conventions section updated with test/lint commands and CI behavior |

## Phase 2 — Data & search quality

| Item | Agent | How | Status |
|---|---|---|---|
| OSV.dev ingestion | `cf-backend-dev` | New adapter in `apps/ingest/src/adapters/osv.ts`, batched `/v1/querybatch` (≤1000 pairs/call), correlate `aliases[]` CVE IDs into existing rows, first-class record when no CVE alias exists | not started |
| SSVC "Exploitation" field | `cf-backend-dev` | Parse from the CISA Vulnrichment/ADP container already present in ingested CVE 5.x records — check first whether it's already being captured before adding new fetch logic | not started |
| GHSA (scoped) | `cf-backend-dev` | GraphQL pull for CWE/CVSS backfill + withdrawal tracking only — not a coverage source (OSV already covers it) | not started |
| Exploit-signal aggregation | `cf-backend-dev` | ExploitDB CSV + Metasploit `modules_metadata_base.json` + PoC-in-GitHub (confidence-ranked, latter labeled unverified) | not started |
| Reranker on search | `cf-backend-dev` | `@cf/baai/bge-reranker-base` over existing Vectorize retrieval in `apps/app/src/lib/server/queries/searchCves.ts` | not started |
| Large-table UX | `sveltekit-dev` | `@tanstack/svelte-table` + `@tanstack/svelte-virtual` for search results / future asset inventory | not started |
| Dashboard charts | `sveltekit-dev` | LayerChart 2.x for bars/trends (SSR-safe); ECharts isolated client-only for the CVSS×EPSS heatmap | not started |

## Phase 3 — Watchlists (the core differentiator)

| Item | Agent | How | Status |
|---|---|---|---|
| Watchlists schema + API | `cf-backend-dev` | New migration: multi-tenant "project" primitive (OpenCVE-modeled) from day one, vendor/product subscriptions, status pipeline per tracked CVE | not started |
| Watchlists UI | `sveltekit-dev` | New routes under `apps/app/src/routes/watchlists/` | not started |
| Notifications | `cf-backend-dev` | Email/Slack/webhook alongside Watchlists | not started |
| AI prioritization rationale | `cf-backend-dev` | Workers AI explains the deterministic score (KEV/EPSS/CVSS/watchlist membership) — advisory only, not autonomous triage | not started |
| Durable Objects rate limiter | `cf-backend-dev` | Structural fix for the KV-incident bug class; also converts the IP-allowlist-prune cron to a DO Alarm, clawing back one of the 5 account-wide cron slots | not started |
| API keys | `cf-backend-dev` | Hand-rolled: `crypto.getRandomValues` + SHA-256 hash, D1 table | not started |

## Phase 4 — Asset-centric features

| Item | Agent | How | Status |
|---|---|---|---|
| SBOM Import + Asset Inventory | `cf-backend-dev` + `sveltekit-dev` | Dependency-Track-modeled: PURL-primary matching (fallback to CPE), project/portfolio hierarchy. Depends on Phase 2's OSV.dev ingestion being live. | not started |
| Remediation | `cf-backend-dev` + `sveltekit-dev` | DefectDojo-modeled risk-acceptance with mandatory expiry → auto-reactivation | not started |
| Conflicts | `cf-backend-dev` | Cross-source CVSS/CWE reconciliation (NVD vs CNA vs ADP) | not started |
| Live push (SSE) | `cf-backend-dev` + `sveltekit-dev` | Server-Sent Events for new-CVE/KEV notifications, Worker-native | not started |

## Phase 5 — Differentiation (revisit in 6+ months)

Sightings + Bundles, ATT&CK reference data (CVE↔technique auto-mapping deferred —
current research found only ~39% expert-agreement on LLM-generated mappings),
Shodan InternetDB/CVEDB enrichment, Export/API, CVSS v4.0 dual-track display.
Not scheduled yet — revisit once Phase 3/4 ship.

## Explicitly not doing

GitLab Advisory DB / PyPA / RustSec / Go-vulndb as separate pipelines
(redundant with OSV.dev), abuse.ch, GreyNoise free tier, Turborepo/Nx,
`cmdk-sv`, `svelte-sonner`, Lucia Auth, Auth.js, any self-hosted IdP,
Hyperdrive + external Postgres, CVE↔ATT&CK auto-mapping.

## Working agreement

- A phase starts only once its dependencies (noted inline) are actually
  shipped, not just planned.
- Every item lands through its assigned agent via the Agent/Workflow tool,
  not ad hoc in the main thread — keeps changes scoped and reviewable.
- `security-reviewer` runs after every phase's code lands, before deploy.
- Deploys stay manual-confirmed (`deployer` prepares, a human/the orchestrating
  session executes) until CI/CD (Phase 1) replaces that with automated
  staging deploys + gated production promotion.
