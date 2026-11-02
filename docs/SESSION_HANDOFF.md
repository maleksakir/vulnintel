# Session Handoff — Production is LIVE

Both workers are deployed to production and serving. Everything below is
committed, CI-green (app 125 tests, ingest 212, all green; `tsc`,
`svelte-check`, `biome ci` clean), pushed to `github/main`, and running on the
Cloudflare free tier (zero paid resources).

Live: https://threat-lens-app.sakirm.workers.dev/

## Deployed versions

| Worker | Version ID | Carries |
|---|---|---|
| threat-lens-ingest | `c29c95f2-5be3-4dc7-9c90-d696b42f9b57` | KEV message-size fix, EPSS write-amplification fix, FTS trigger fix (0013), dashboard rollups (0014), aging-sweep budget restructure |
| threat-lens-app | `713e3f97-ad0c-4511-b801-051588e812b7` | operator read-gate on assets/watchlists/remediation, rollup-backed dashboard read path with base-table fallback, all 13 security-review fixes |

## Commits this session (newest first)

| Commit | What |
|---|---|
| `3b2f363` | app: dashboard renders even when rollup tables are absent (not just empty) |
| `e63a3fa` | ingest: fix the 3 live pipeline failures (KEV byte-size, EPSS over-write + FK poisoning, aging CPU) |
| `daa85ca` | perf(d1): FTS trigger fix + day-grain rollups — the read-quota blowout |
| `2f0dda9` | security review: webhooks, reconcile cursor, orphan sweeps, write quotas |
| `8508405` | security: gate the operator read surface; make SBOM matching work and bounded |

## ⚠ ONE THING LEFT: apply production migrations 0008 + 0014

Blocked today (2026-11-02) by D1's free-tier **daily write cap**, which was
exhausted before 05:00 UTC by the EPSS over-write bug — a bug this session
fixed, but the fix deployed *after* the day's budget was already spent, so the
cap won't clear until **00:00 UTC** (~17h from the 06:19 UTC handoff).

A hook (`.kiro/hooks/apply-prod-migrations.json`) is set to apply them at the
next session start; or run it by hand once the cap resets:

```
cd apps/ingest
pnpm exec wrangler d1 migrations apply cve_prod_d1 --remote
```

0008 adds the four SSVC columns `writeD1` binds; 0009–0012 add
watchlists/assets/remediation; **0014 builds the dashboard rollup tables**.

Why this is NOT currently breaking production:
- **getMetrics** degrades to the base-table queries on a missing rollup table
  (commit `3b2f363`, test-covered), so the dashboard renders correct numbers,
  just without the read-cost reduction, until 0014 lands.
- **The read-quota relief is already live** regardless of migrations: the FTS
  trigger that was burning 11.3M reads/day ships in the *worker* (migration
  0013 only re-points the trigger; the EPSS write fix is pure worker code).
  So ingestion can complete again starting with tonight's cron.

What 0014 unlocks once applied: the first aging sweep after it (cron `30 2 * *
*`) builds the rollups, and the dashboard switches from base-table scans to
~540-row rollup reads.

## Verified live this session

- `/` 200, `/search?q=linux` 200, `/threat-intel` 200, `/affected-products` 200
- `/assets`, `/remediation`, `/watchlists` → sign-in gate renders, **no data
  leaked** (no table, no import panel) for an unauthenticated visitor
- `/api/remediation` → 403 without a bearer token
- homepage served with no 500 against the un-migrated schema (fallback works)

## Still open (pre-existing, not blocking)

- `IPLIST_PRUNE` failing since 2026-10-08 (Rulesets API 403) — separate credential issue
- Production ingestion backlog: NVD last wrote 2026-10-30; tonight's crons
  should now land rows (the three pipeline failures that prevented it are fixed)
- Deferred by design: cross-source CVSS conflicts, SSE live-push, AI
  prioritization rationale (see docs/EXECUTION_PLAN.md)
