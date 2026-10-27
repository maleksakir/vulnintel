# Threat-Lens — CVE Intelligence Platform

Cloudflare Workers + SvelteKit CVE/vulnerability-intelligence platform. Live at
https://threat-lens-app.sakirm.workers.dev/. This file orients any agent working
in this repo — read it before making changes.

## Architecture

- `apps/app/` — SvelteKit frontend (Cloudflare Pages/Workers). SSR routes query D1
  directly; a few public `/api/*` JSON endpoints go through a KV read-through
  cache (`src/lib/server/cacheRead.ts`).
- `apps/ingest/` — Cloudflare Worker, cron-triggered (`wrangler.toml` `[triggers]`).
  Pulls NVD, MITRE CVE, CISA KEV, and FIRST.org EPSS data, normalizes it, and
  writes to D1 (+ Vectorize embeddings, + KV cache invalidation).
- `packages/contracts/` — shared TypeScript types between `app` and `ingest`.
- `migrations/` — D1 schema (numbered SQL files, applied via Wrangler).
- `docs/spec/` — the original design spec (phases, blueprints, security model).
  Treat it as the source of truth for intended behavior; flag drift when found,
  don't assume the spec is stale without checking.

Data flow: `ingest` cron → D1 (source of truth) + Vectorize (semantic search) →
`app` reads D1 directly for pages, KV as a short-TTL cache for the JSON API.

## Known constraints (check before changing ingest code)

- **D1 writes and KV deletes must be skip-if-unchanged.** EPSS/KEV sources ship
  full snapshots daily, not deltas — `processRecord.ts` has a two-hash
  (text/state) change-detection gate; `applyEpssPatch`/`applyKevPatch` now have
  an equivalent guard (added 2026-10-27 after a KV free-tier quota incident —
  250k+ unconditional KV deletes/day from the EPSS full-CSV re-ingest). Any new
  ingest path that touches KV or D1 per-record must have the same guard, or it
  will blow through Cloudflare's free-tier daily KV write/delete cap (1,000/day).
- Cloudflare free tier in general: KV reads 100k/day, writes+deletes+lists
  1k/day combined. Design any new cron/batch job with that ceiling in mind.
- `wrangler` is **not authenticated in the agent's environment** — code changes
  land in git but someone with Cloudflare account access must run
  `wrangler deploy` (or wire up the CI job) to actually ship them.

## Repo state (as of 2026-10-27)

- GitHub (`github.com/maleksakir/vulnintel`, personal, public) is the
  canonical repo going forward — single `main` branch, this codebase only.
- This superseded an earlier, now-removed legacy stack (Docker Compose +
  Python FastAPI + .NET + 2 React apps) that was never actually deployed
  anywhere — don't resurrect it or treat it as a reference architecture.
- A GitLab remote (company, `infopercept/vulnor-invinsense`) also exists for
  prior work; it is unrelated to this repo's ongoing direction.

## The team

See `.claude/agents/` for specialized subagents (planner, cf-backend-dev,
sveltekit-dev, deployer, qa-tester, security-reviewer, docs-writer). Use the
Agent tool to delegate to the one matching the task rather than doing
cross-cutting work inline. For a task spanning several of them end-to-end
(e.g. "add a feature: plan → code → test → security review → deploy"), use the
Workflow tool to pipeline them — the user has opted into multi-agent
orchestration for this project.

## Conventions

- Package manager: pnpm (`pnpm-workspace.yaml` at root — this is a monorepo).
- TypeScript strict; run `tsc --noEmit` in the relevant `apps/*` dir before
  committing.
- D1 migrations are additive/numbered — never edit a shipped migration file,
  add a new one.
- Commit messages: explain *why*, not what (the diff shows what).
- Tests: `@cloudflare/vitest-plugin`, real D1/KV/Queues against `workerd`
  (Vectorize/Workers AI mocked). Run with `pnpm test` inside `apps/app/` or
  `apps/ingest/` (each has its own `test` script; there is no root-level
  aggregate script).
- Lint: Biome, `.ts` files only (`.svelte` is untouched — no Svelte formatter
  is configured). Run `pnpm lint` from the repo root, or `pnpm lint:fix` to
  auto-fix.
- CI: GitHub Actions (`.github/workflows/ci.yml`) runs typecheck + lint +
  tests automatically on every PR and on push to `main`; per-app test jobs
  are path-filtered so only the affected app's suite runs.
