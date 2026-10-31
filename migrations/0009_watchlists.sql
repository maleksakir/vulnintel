-- Migration 0009: Watchlists (Phase 3 — the core differentiator).
--
-- A watchlist is a named set of vendor/product SUBSCRIPTIONS; CVEs whose CPEs
-- match a subscription are materialized into watchlist_match with a per-CVE
-- triage status pipeline. Modeled on OpenCVE's subscription + change-tracking
-- model, but SINGLE-TENANT: the spec locks IP-allowlist-only auth with "no
-- user identity" (docs/spec/00, 02), so there are no users/orgs to scope a
-- multi-tenant "project" to. This schema is shaped so multi-tenancy is a
-- purely ADDITIVE migration later (add an owner/org_id column defaulting to a
-- single implicit tenant) — no retrofit of these tables needed. See the
-- Phase 3 design doc.
--
-- Additive only; never touches cve/cpe/cve_state/etc. (NVD/MITRE-owned, per
-- CLAUDE.md's migration convention).
--
-- IF NOT EXISTS on every table AND index: production D1 carried ~53 leftover
-- tables from a lost prior implementation that INCLUDED watchlists (see
-- docs/EXECUTION_PLAN.md's "D1 over 500MB cap" row — they were DROPped
-- 2026-10-30, but this guard matches the 0007 OSV convention so a re-run or a
-- lingering same-named table can't fail the deploy. Residual risk, same as
-- 0007: a DIFFERENTLY-shaped leftover table would be silently kept instead of
-- failing loudly — verify production's schema (a cheap sqlite_master listing)
-- before applying if any watchlist_* table unexpectedly already exists.

PRAGMA foreign_keys = ON;

-- A named watchlist (e.g. "Perimeter stack", "Core infrastructure").
CREATE TABLE IF NOT EXISTS watchlist (
  watchlist_id  INTEGER PRIMARY KEY AUTOINCREMENT,
  name          TEXT NOT NULL,
  description   TEXT,
  created_at    INTEGER NOT NULL,   -- unix ms
  updated_at    INTEGER NOT NULL    -- unix ms
) STRICT;

-- Vendor and/or product subscriptions that define what a watchlist matches.
-- product = NULL means "all products for this vendor". Matched case-sensitively
-- against cpe.vendor / cpe.product (NVD normalizes these to lowercase, so the
-- API layer lowercases user input before storing — see the watchlist API).
CREATE TABLE IF NOT EXISTS watchlist_subscription (
  subscription_id INTEGER PRIMARY KEY AUTOINCREMENT,
  watchlist_id    INTEGER NOT NULL REFERENCES watchlist(watchlist_id) ON DELETE CASCADE,
  vendor          TEXT NOT NULL,
  product         TEXT,            -- NULL = all products for the vendor
  created_at      INTEGER NOT NULL
) STRICT;

-- One subscription per (watchlist, vendor, product). COALESCE isn't needed in
-- the index because SQLite treats NULLs as distinct in a UNIQUE index, which
-- is actually the behavior we want: ('vendor', NULL) ["all products"] and
-- ('vendor', 'product') coexist as separate, both-valid subscriptions.
CREATE UNIQUE INDEX IF NOT EXISTS idx_wl_sub_unique
  ON watchlist_subscription(watchlist_id, vendor, product);

-- Drives the match-reconciliation scan (vendor/product lookup over all
-- subscriptions across all watchlists).
CREATE INDEX IF NOT EXISTS idx_wl_sub_vendor_product
  ON watchlist_subscription(vendor, product);

-- Per-CVE triage status for CVEs matched into a watchlist. One row per
-- (watchlist, cve). cve_id is deliberately NOT a foreign key to cve(cve_id):
-- a matched CVE can age out of the 24-month window and be hard-deleted, but
-- the analyst's triage decision (status + note) should survive that rather
-- than CASCADE-vanishing. Orphaned terminal-status matches are swept by the
-- aging tail instead (see pipelines/aging.ts), not by a cascade here.
CREATE TABLE IF NOT EXISTS watchlist_match (
  watchlist_id      INTEGER NOT NULL REFERENCES watchlist(watchlist_id) ON DELETE CASCADE,
  cve_id            TEXT NOT NULL,
  status            TEXT NOT NULL DEFAULT 'NEW'
                      CHECK (status IN ('NEW','TRIAGING','ACKNOWLEDGED','RESOLVED','IGNORED')),
  note              TEXT,
  first_matched_at  INTEGER NOT NULL,   -- unix ms, when this CVE first matched
  status_updated_at INTEGER NOT NULL,   -- unix ms, last triage status change
  PRIMARY KEY (watchlist_id, cve_id)
) STRICT, WITHOUT ROWID;

-- Status-filtered listing within a watchlist (the detail-page match table).
CREATE INDEX IF NOT EXISTS idx_wl_match_status
  ON watchlist_match(watchlist_id, status);

-- The incremental match-reconciliation consumer tracks how far it has scanned
-- via a cursor row here (keyed 'watchlist_match'), so each run only considers
-- CVEs modified since the last run rather than re-scanning the whole corpus.
-- Reuses the ingest_run table's shape intent but is a distinct concern, so its
-- own tiny table rather than overloading ingest_run.
CREATE TABLE IF NOT EXISTS watchlist_sync_state (
  key                TEXT PRIMARY KEY,   -- 'watchlist_match'
  last_cursor_ms     INTEGER NOT NULL,   -- cve.last_modified_at high-water mark
  last_run_at        INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

-- Seed the ingest_run row for the watchlist reconciliation consumer so
-- /admin/health has a row for it and markIngestStarted's UPDATE isn't a
-- silent no-op (it UPDATEs WHERE source = ?, so the row must pre-exist —
-- same convention as migration 0002's seeds and 0007's OSV seed).
-- INSERT OR IGNORE: safe to re-run, and tolerant of a leftover row.
INSERT OR IGNORE INTO ingest_run (source) VALUES ('WATCHLIST');
