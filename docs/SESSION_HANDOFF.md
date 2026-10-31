# Autonomous Session Handoff (while you were resting)

Everything below is **committed, CI-green, and live on STAGING**. Nothing has
been deployed to production and no production D1 migration has been applied —
per your instruction to batch the end-to-end production deploy for when you're
back. All work stayed within the Cloudflare free tier (zero new paid
resources; no AI features that could drain the shared neuron pool were shipped
unattended — see "Deliberately deferred" below).

## What shipped this session (newest first)

| Commit | Feature |
|---|---|
| `69da2bb` | Remediation wiring: risk-accepted flag on asset CVEs, `/cve/[id]` accept/revoke panel, `/remediation` overview page |
| `fe2de79` | Remediation: risk acceptance (mandatory expiry, auto-reactivation) — migration 0012 |
| `5beb9a3` | Asset inventory + SBOM import (CycloneDX, PURL/CPE matching) — migration 0011 |
| `652971d` | Watchlist deterministic priority score (zero AI) |
| `e04e681`…`aa23459` | Watchlists complete (schema/engine/API/UI/notifications) — migrations 0009, 0010 |
| earlier | KEV+reconcile queue fix, SSR caching, dashboard cache-key fix, per-IP AI quota cap |

Test totals now: **apps/app 102, apps/ingest 177** — all green; `tsc`,
`svelte-check`, and `biome ci` all clean.

## TO DO WHEN YOU'RE BACK — batched production deploy

Two things, in this order:

### 1. Apply the pending production D1 migrations (0009–0012)
All four are additive, validated on staging (each with a leftover-table
pre-flight check), and idempotent. From `apps/ingest`:
```
pnpm exec wrangler d1 migrations apply cve_prod_d1 --remote
```
Note: production D1 was already cleaned of the ~53 lost-implementation tables
on 2026-10-30, so unlike staging it should have NO leftover
watchlist/asset/remediation tables to drop first — but do a quick
`sqlite_master` check for `watchlist%`, `asset%`, `sbom%`, `remediation%`,
`cve_risk_acceptance` before applying, just in case (same cheap control-plane
read used throughout this project).

### 2. Approve the pending production deploys
Several Deploy runs are queued at the GitHub "production" Environment's
required-reviewer gate (the deploy identity I have can't self-approve — 403).
Approve the latest at the Actions UI; it deploys both workers. The new
Cloudflare Queues for watchlists (`watchlist-ingest` + DLQ + staging pair)
were already provisioned this session; no new queues are needed for the asset
/remediation work (they're pure app-worker + D1).

After deploy, watchlists/assets/remediation become live in production. A
first watchlist/asset will populate on the next daily ingest cron (watchlist
reconciliation) or immediately on an SBOM import (assets) / subscription add
(watchlists — has an inline backfill).

## Deliberately deferred (need you / a supervised session)

- **AI prioritization rationale** (natural-language): draws on the shared
  10k-neuron/day pool ingest embeddings depend on. The deterministic priority
  score shipped; the AI layer needs a budget gate built while the neuron
  budget can be watched — not safe to run unattended.
- **Cross-source conflicts** (CVSS/CWE): the NVD adapter collapses to one
  CVSS today, so the multi-source data isn't captured. Needs an ingest schema
  change + backfill + a live cron cycle to verify.
- **Live push (SSE)**: wants Durable Objects for fan-out — verify its
  free-tier profile first; realtime is hard to verify offline.
- **Durable Objects rate limiter**, **API keys**: flagged earlier as
  pause-and-decide (billing / security-surface decisions).

## Still open from before (unchanged)
- `AGING` cron recorded zero invocations Aug 27–Oct 30 (platform mystery, not
  a code bug) — watch `ingest_run.AGING` after a `30 2 * * *` window.
- Live confirmation that NVD/MITRE/OSV/KEV ingestion is landing rows in
  production (needs a daily cron cycle + a cheap spot-check).
