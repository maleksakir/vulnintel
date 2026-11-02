-- Migration 0014: day-grain rollups for the dashboard read path
--
-- WHY (measured on production 2026-10-31 with `wrangler d1 insights`, after
-- the account hit D1's free-tier 5M-row/day read cap):
--
--   getMetrics() answers the homepage and /api/metrics/[window] with five
--   aggregates computed from scratch on every cache miss. Their real cost:
--
--     top vendors (cpe JOIN cve JOIN cve_state, GROUP BY vendor)  236k rows
--     KPI panel (COUNT(*) over cve + two cve_state subqueries)    116k rows
--     severity distribution (GROUP BY severity over a window)      56k rows
--
--   At the 25-ish cache misses a day the site was actually getting, that is
--   ~10M rows/day — twice the entire daily allowance — for five numbers and
--   three small charts. Worse, the cost scales with the CORPUS, not with
--   traffic: every month of retained CVEs makes a dashboard view more
--   expensive, so the read budget degrades on its own.
--
-- WHAT: pre-aggregate at day grain. Every one of those five outputs is a sum
-- over days, so a day-grain rollup answers all of them exactly — this is
-- precomputation, not sampling or estimation.
--
--   severity distribution  ->  SUM(cve_count) GROUP BY severity        ~540 rows for 90d
--   publication velocity   ->  SUM(cve_count) GROUP BY day              ~90 rows for 90d
--   KEV inflow             ->  cve_rollup_kev_daily                     ~90 rows for 90d
--   top vendors            ->  SUM over cve_rollup_vendor_daily        ~30k rows for 90d
--   KPI panel              ->  cve_metrics_daily (migration 0005)        ~10 rows
--
-- The KPI panel needs no new table: the aging sweep has always written
-- total_cves / severity_* / kev_listed into cve_metrics_daily. The dashboard
-- was recomputing, with a full table scan, numbers that were already sitting
-- in a ten-row snapshot.
--
-- Rollups are rebuilt by the ingest worker (lib/server/rollups.ts): a full
-- rebuild in the daily aging sweep, and a trailing-window refresh after each
-- ingest run so the dashboard is exactly as fresh as the corpus it describes.
-- Both are idempotent upserts, so a re-run or an overlapping run is safe.
--
-- Day keys are INTEGER yyyymmdd (e.g. 20261031), matching cve_metrics_daily's
-- metric_date convention from 0005 rather than inventing a second one.
--
-- IF NOT EXISTS on every table and index: 0007/0009's re-runnability lesson.

-- ── Published-CVE counts by day and severity ─────────────────────────────────
-- Serves the severity-distribution donut and the publication-velocity line
-- for every window. Bounded by the 24-month retention: ~730 days x 6
-- severities, so it can never exceed a few thousand rows.
CREATE TABLE IF NOT EXISTS cve_rollup_daily (
  day        INTEGER NOT NULL,   -- yyyymmdd of cve.published_at (UTC)
  severity   TEXT NOT NULL,
  cve_count  INTEGER NOT NULL,
  PRIMARY KEY (day, severity)
) STRICT, WITHOUT ROWID;

-- ── KEV additions by day ─────────────────────────────────────────────────────
-- Grain is cve_state.kev_date_added, NOT published_at — a CVE from 2019 can
-- enter the KEV catalogue today, which is precisely the signal this chart
-- exists to show. That different grain is why it isn't a column on
-- cve_rollup_daily.
CREATE TABLE IF NOT EXISTS cve_rollup_kev_daily (
  day        INTEGER NOT NULL,   -- yyyymmdd of cve_state.kev_date_added (UTC)
  kev_count  INTEGER NOT NULL,
  PRIMARY KEY (day)
) STRICT, WITHOUT ROWID;

-- ── Vendor exposure by day ───────────────────────────────────────────────────
-- Serves the top-vendors table for every window. This is the one rollup with
-- non-trivial cardinality (a day's CVEs touch a few hundred distinct vendors),
-- so it is capped to the widest window the dashboard offers — 90 days, pruned
-- by the aging tail. That keeps it around 30k rows and, critically, makes the
-- read cost a function of the WINDOW rather than of total corpus depth.
--
-- cve_count is COUNT(DISTINCT cve_id) for that vendor on that day, so summing
-- across days is exact as long as a CVE has a single published day — which it
-- does, by definition.
CREATE TABLE IF NOT EXISTS cve_rollup_vendor_daily (
  day        INTEGER NOT NULL,   -- yyyymmdd of cve.published_at (UTC)
  vendor     TEXT NOT NULL,
  cve_count  INTEGER NOT NULL,
  kev_count  INTEGER NOT NULL,
  PRIMARY KEY (day, vendor)
) STRICT, WITHOUT ROWID;

-- Window queries filter on day and aggregate by vendor. The PK's leading edge
-- is day, so the range scan is already covered; this index serves the
-- aging-tail prune and any vendor-first lookup.
CREATE INDEX IF NOT EXISTS idx_rollup_vendor_vendor
  ON cve_rollup_vendor_daily(vendor);

-- ── Rollup build bookkeeping ─────────────────────────────────────────────────
-- One row per rollup, so /admin/health can show whether the dashboard's
-- numbers are current and a failed rebuild is visible rather than silently
-- serving stale aggregates (the "stale OK status" failure mode CLAUDE.md
-- records for the aging sweep).
CREATE TABLE IF NOT EXISTS rollup_state (
  rollup_key      TEXT PRIMARY KEY,   -- 'daily' | 'kev_daily' | 'vendor_daily'
  last_full_at    INTEGER,            -- unix ms of the last FULL rebuild
  last_refresh_at INTEGER,            -- unix ms of the last trailing refresh
  last_status     TEXT,               -- 'OK' | 'FAILED'
  last_error      TEXT,
  rows_written    INTEGER
) STRICT, WITHOUT ROWID;
