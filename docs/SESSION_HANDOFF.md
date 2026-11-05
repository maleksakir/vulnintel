# Session Handoff — Production is LIVE with data

Threat-Lens is fully deployed, migrated, and serving live data on the
Cloudflare free tier. Live: https://threat-lens-app.sakirm.workers.dev/

Last verified: 2026-11-05. Dashboard renders real numbers (119,264 CVEs,
11,448 critical, 460 KEV, mean EPSS 31.5%); every page returns 200.

## Deployed state

| Worker | Carries |
|---|---|
| threat-lens-app (`b7d5edb2`) | Operator Console redesign; rollup-only dashboard reads (no corpus scan on request path); graceful degrade-to-notice on D1 unavailability |
| threat-lens-ingest (`b3fb51fd`) | FTS trigger fix, EPSS write-amplification fix, KEV per-message AND per-sendBatch-call size bounds, dashboard rollup builders |

Production D1: **all migrations 0001–0014 applied.** SSVC columns, watchlists,
assets, remediation, the fixed FTS trigger (per-row cve_fts_delete removed),
and the rollup tables all exist.

## What this session fixed (newest first)

| Commit | What |
|---|---|
| `6efdbb8` | KEV sendBatch bounded by cumulative bytes (256KB/call cap), not just the 100-message count — was failing every run with "batch size … exceeds 256000" |
| `3adc91e` | Dashboard never runs a full-corpus scan on a request; windowed views read only the rollups/snapshot, else show "warming up" |
| `55ba95d` | Read-heavy SSR pages degrade to an offline notice instead of 500ing when D1 is capped |
| `af63409`, `54ff8ae` | Operator Console redesign across every page (cyan command-center theme, shared SeverityBadge/PageHeader/data-grid) |

## Manual steps performed this session (reproducible)

When migrations finally applied (quota window opened 2026-11-05), the rollup
tables were empty, so the dashboard showed "warming up". Populated them
manually to light up the console immediately, mirroring what the 02:30 UTC
aging sweep does:

- `cve_rollup_daily` (4,049 rows), `cve_rollup_kev_daily` (272 rows) rebuilt
  from the corpus via the same INSERT…SELECT the sweep runs.
- `cve_rollup_vendor_daily` is **empty by design**: no CVEs were *published*
  in the last 90 days in the corpus (it's a 2-year retrospective set), so the
  top-vendors panel is empty until recent-published CVEs ingest. Not a bug.
- `cve_metrics_daily` snapshot for 20261105 written (the KPI card source).
- Cleared `dash:metrics:*` KV keys so the dashboard re-read the fresh rollups.

From here the 02:30 UTC aging sweep keeps all of this current automatically.

## Known-good / watch items

- **KEV & AGING pipelines**: both had failed earlier *today* (06:00 / 02:31)
  on the OLD schema — KEV on the sendBatch size (now fixed + deployed), AGING
  on the per-row FTS delete trigger CPU blowup (removed by migration 0013,
  now applied). Both should go green on their next scheduled run. Confirm via
  `ingest_run` after the next 02:30 (aging) and 6-hourly (KEV) cycles.
- **SSVC columns** exist but are unpopulated (`ssvc=0`) — NVD's SSVC data
  fills in as records re-ingest; not blocking.
- **Free-tier ceiling**: the read blowout is fixed (dashboard no longer scans
  the corpus on request), but a 119k-corpus on the free tier stays tight. If
  an empty dashboard ever appears again, check the D1 daily quota first — it
  resets at 00:00 UTC. The $5/mo Workers Paid plan removes this entirely if
  $0 ever stops being a hard constraint.

## Still open (pre-existing, not blocking)

- `IPLIST_PRUNE` failing since 2026-10-08 (Rulesets API 403) — separate
  credential issue, unrelated to ingestion.
- Deferred by design: cross-source CVSS conflicts, SSE live-push, AI
  prioritization rationale (see docs/EXECUTION_PLAN.md).
