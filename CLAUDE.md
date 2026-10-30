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

## Known constraints (Workers Free plan — check before changing either app)

- **D1 writes and KV deletes must be skip-if-unchanged.** EPSS/KEV sources ship
  full snapshots daily, not deltas — `processRecord.ts` has a two-hash
  (text/state) change-detection gate; `applyEpssPatchBatch`/`applyKevPatch` have
  an equivalent guard (added 2026-10-27 after a KV free-tier quota incident —
  250k+ unconditional KV deletes/day from the EPSS full-CSV re-ingest). Any new
  ingest path that touches KV or D1 per-record must have the same guard, or it
  will blow through Cloudflare's free-tier daily KV write/delete cap (1,000/day).
- **Bulk D1 operations (DELETE, full-table rebuilds) must be batched, bounded,
  and conditional.** A single unbatched DELETE + an unconditional daily FTS
  rebuild in the aging sweep silently exceeded the per-invocation CPU budget
  as a backlog grew, got killed mid-run, and stayed broken for ~2 months
  before anyone noticed (2026-08-27 → 2026-10-28, see
  `docs/EXECUTION_PLAN.md`). Chunk large deletes (`WHERE id IN (SELECT ...
  LIMIT n)`, looped with a batch-count cap); skip expensive rebuild steps
  on no-op runs.
- **Per-request CPU budget is fixed and NOT raisable on this plan.**
  `[limits] cpu_ms` in `wrangler.toml` is rejected outright at deploy time:
  "CPU limits are not supported for the Free plan." This matters for more
  than ingest crons — **server-rendering any non-trivial chart/visualization
  library is almost certainly not viable**: LayerChart (SVG output, in
  principle SSR-safe) measured 127–389ms server-side CPU for 3 dashboard
  charts, 12–39x the budget (2026-10-28). "Emits SVG instead of canvas"
  means SSR *won't crash* — it does not mean SSR *fits the CPU budget*. Any
  charting/heavy-computation UI work should default to a client-only island
  (`import()` inside `onMount`, gated by `import.meta.env.SSR` so the library
  never enters the server bundle) unless proven cheap enough to server-render
  by actually measuring it, not by assuming "SVG = safe."
- **D1 caps 100 bound parameters per query on every plan, and 50 D1 queries
  per Worker invocation on the Free plan (1,000 on Paid) — the same
  underlying subrequest-cap mechanism as the "too many subrequests" error
  that killed the lost CSAF/ICS adapters (see `docs/EXECUTION_PLAN.md`'s
  "Lost ingestion sources" row).** Any ingestion path that processes a
  large/unbounded external dataset — a full daily snapshot, not a delta —
  must spread its D1 reads/writes across multiple Queue-consumer
  invocations, each with its own fresh per-invocation budget; never do that
  work inline within one cron invocation. Found 2026-10-29 in
  `apps/ingest`'s EPSS path (added 2026-10-27, `948b99f`): a
  `WHERE cve_id IN (...)` SELECT bound one param per row against FIRST.org's
  250k+-row daily full snapshot, with all reads/writes running inline in the
  single daily cron invocation — both caps would be blown through. Fixed by
  moving the D1 work into a dedicated `epss-ingest` Queue consumer
  (`apps/ingest/src/pipelines/epssQueue.ts`, `max_batch_size = 1` so every
  message gets its own fresh 50-query budget); the surviving inline SELECT
  is chunked at the 100-param cap regardless of caller
  (`apps/ingest/src/lib/server/processRecord.ts`). Deployed 2026-10-29, see
  `docs/EXECUTION_PLAN.md`'s Phase 0 table for status. **Confirmed repeat
  pattern (now FOUR times):** `apps/ingest`'s NVD path hit this identical bug
  independently (found/fixed 2026-10-30), and the KEV fast-lane
  (`pipelines/kev.ts`, every 6 hours over CISA's full 1,000+-entry catalog)
  and weekly reconciliation (`pipelines/reconcile.ts`, 30-day NVD window) both
  had it too — all fixed with the same producer/consumer split (`kev.ts` →
  `kev-ingest` → `kevQueue.ts`'s `applyKevPatchBatch`; `reconcile.ts` → the
  existing `nvd-ingest` queue). The KEV fix also removed an unconditional
  `threat:kev:list` KV delete that fired on every 6-hourly run regardless of
  whether anything changed — the consumer now deletes it only on a real
  change. Treat inline per-record D1 work in a cron invocation as the default
  failure mode for any future ingest code, not a one-off: the fix is always a
  producer (zero D1, chunk + enqueue) + a `max_batch_size = 1` Queue consumer
  whose batched D1-query count does NOT grow with the number of changed
  records.
- **Cloudflare Queues' 10,000-operations/day allowance (Workers Free plan) is
  one pool shared account-wide, not per-queue** — a write, a read, and a
  delete each count as a separate operation (so one message ≈ 3 operations,
  ~3,333 messages/day in practice). `apps/ingest` now has 6 queues drawing
  from that same pool: `cve-ingest-retry` (per-record retry), `epss-ingest`
  (added 2026-10-27), `osv-ingest` (added 2026-10-29, deployed and migrated
  2026-10-30, see `docs/EXECUTION_PLAN.md`'s Phase 2 row), `nvd-ingest`
  and `mitre-ingest` (both added 2026-10-30), and `kev-ingest` (added
  2026-10-30 as part of the KEV fast-lane producer/consumer fix — see that
  file's Phase 0 rows; `nvd-ingest`/`mitre-ingest`/`kev-ingest` code-complete,
  not all yet provisioned/deployed). The KEV fast-lane enqueues one message
  per ~500-entry catalog chunk every 6 hours (a handful of messages, not one
  per entry), so it is a small, bounded draw on this pool. None of them
  individually tracks the others' usage, so a burst on one (e.g. a large
  retry storm) can starve the others' headroom for the rest of the day; no
  incident yet, but design future Queue-based ingest paths with this shared
  ceiling in mind, the same way D1/KV's per-resource caps are already treated
  above.
- **Workers AI's 10,000-neurons/day free allocation is one account-wide pool,
  shared between `apps/ingest`'s per-CVE embeddings and `apps/app`'s search
  reranker (`apps/app/src/lib/server/rerank.ts`, `@cf/baai/bge-reranker-base`)
  — not a per-feature budget.** Exhausting it doesn't just fail the request
  that tripped it: a failed `embed()` call during ingestion retries into
  `cve-ingest-retry`, exhausts its retries the same day (no `retry_delay`
  configured), lands in the DLQ, and the next ingest pass sees an unchanged
  `text_hash` on that record and never re-attempts the vector — a silent,
  permanent-until-manually-fixed gap in semantic search coverage, not a
  transient blip. This is why the reranker has a hard self-limiting daily
  budget gate (`RERANK_DAILY_SEARCH_CAP = 1000` reranked searches/day,
  checked against the existing search-quota-ledger read, zero new D1/KV
  cost) and silently falls back to plain RRF ordering once tripped, rather
  than just catching errors and hoping the shared pool has headroom. Any new
  feature that calls `env.AI.run(...)` — ingest or app-side — draws from
  this same pool and needs the same kind of self-limiting ceiling, not just
  try/catch.
- **A D1 database at/over its size cap cannot be shrunk by `DELETE` — not
  even a single-row one, with or without a subquery.** Found 2026-10-30
  applying OSV's migration: `wrangler d1 migrations apply` failed with
  `Exceeded maximum DB size [7500]` at 501MB. Every attempted manual
  `DELETE` (batched subquery, explicit literal ID list, even one row) also
  failed, with either `Exceeded maximum DB size [7500]` or
  `D1 DB exceeded its CPU time limit and was reset [7429]` — SQLite needs
  transactional/journal headroom to execute *any* write safely, and D1 won't
  allocate past the cap even temporarily, so the aging sweep's batched-delete
  fix (bullet above) can never recover a database that's already over the
  line, only prevent one from getting there. **`DROP TABLE` works fine even
  at/over the cap** (tested: one empty table, then a 126k-row table that
  freed ~97.5MB in a single statement) — if a DB is ever stuck over cap
  again, drop unused tables first, don't try to delete your way out row by
  row. Also found while diagnosing this: production D1 carried **~53 unused
  tables** (only ~28 belong to this repo's actual schema) — a far larger
  remnant of unrecoverable prior work than the already-known "6 lost
  ingestion sources" row below, covering a full asset-inventory/SBOM/
  watchlist/remediation/notification/multi-tenant data model that was never
  committed to this repo. Two of those tables alone (`vulnerability`, a
  complete 126k-row parallel to `cve`; `cve_field_provenance`, 93k rows)
  accounted for most of a 132MB cleanup (501MB → 368.81MB). Before adding
  any new migration, a quick `sqlite_master` listing against production is
  worth the (tiny) D1 read cost to check it still matches migrations
  0001–0007's expected table set — this drifted silently for a long time
  before anyone checked.
- **`AGING`'s cron (`30 2 * * *`) recorded zero invocations between
  2026-08-27 and 2026-10-30** despite being correctly declared in
  `wrangler.toml` and correctly matched in `index.ts`'s `scheduled()`
  dispatch — confirmed not a code bug (other crons on the same Worker fire
  on schedule; `markIngestStarted` is AGING's unconditional first statement,
  so if the cron fired at all, `ingest_run.AGING.last_started_at` would show
  it, and it never moved). Cause still unknown as of 2026-10-30 — no
  read-only way was found via `wrangler` to list a Worker's actually-
  registered cron triggers (only `wrangler triggers deploy`, which mutates).
  If this is still stale after the next `30 2 * * *` UTC window, it needs a
  Cloudflare dashboard check or support ticket, not more code changes — see
  `docs/EXECUTION_PLAN.md`'s Phase 0 table.
- OSV.dev ingestion (`apps/ingest/src/adapters/osv.ts`, deployed and
  migrated 2026-10-30) adds two new outbound hosts beyond NVD/MITRE/CISA/FIRST.org:
  `storage.googleapis.com` (GCS per-ecosystem `modified_id.csv` export, used
  for delta discovery) and `api.osv.dev` (per-record REST fetch). Note for
  `docs-writer`/`security-reviewer`: `docs/network/whitelist-ledger.md` is
  the IP *inbound* allowlist (`corp_authorized_sources`, WAF-side) and is
  unrelated to ingest adapters' outbound fetch targets — there is currently
  no separate outbound-allowlist doc despite `docs-writer`'s charter
  describing one; the adapter table in `apps/ingest/README.md` is where
  outbound sources are actually tracked.
- Cloudflare free tier in general: KV reads 100k/day, writes+deletes+lists
  1k/day combined; D1 reads 5M/day, writes 100k/day, 500MB per database;
  Cron Triggers 5 per account (already fully used by `apps/ingest`). Design
  any new cron/batch job, or chart/feature that queries D1 per request, with
  these ceilings in mind.
- **Any D1 query that runs on every page load (SSR `load` functions, not just
  `/api/*` routes) must go through the KV cache, the same as the JSON API
  does.** The homepage's `+page.server.ts` called `getMetrics()` (5 queries,
  including an unfiltered `COUNT(*)` over the full `cve` table) directly,
  unlike `/api/metrics/[window]` which wraps the identical call in
  `cacheReadJson`. That one uncached route alone re-exhausted the 5M/day D1
  read quota in ~7 hours from ordinary traffic — no diagnostic queries, no
  attack, just pageviews (2026-10-29, fixed in `d7033cf`). Before adding a
  `+page.server.ts`/`+server.ts` that queries D1, check whether the result can
  be stale for a few minutes; if so, wrap it in `cacheReadJson` like the
  existing API routes do.
- **Live-debugging D1 issues against the real account spends from the same
  daily read budget production traffic uses.** A round of diagnostic `curl`
  calls to the D1 HTTP API (one alone read 733k rows) exhausted the day's 5M
  read quota and caused a second, unrelated site-wide outage while
  investigating the aging-sweep bug (2026-10-28). Prefer local testing
  (`@cloudflare/vitest-plugin`'s real-but-local `workerd` D1) over live
  queries whenever the question can be answered locally; if live querying is
  genuinely necessary, keep it to as few, cheap round-trips as possible.
- CI/CD (`.github/workflows/`) can deploy via `wrangler deploy` once
  `CLOUDFLARE_API_TOKEN` is set as a repo secret (done 2026-10-28) — `wrangler`
  itself still isn't authenticated in an interactive agent's own shell unless
  someone passes a token in for that session.

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
