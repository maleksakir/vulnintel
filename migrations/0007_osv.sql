-- Migration 0007: OSV (GHSA) ingestion state + CVE-linked affected packages.
--
-- Additive only. Deliberately does NOT touch cve/cpe/cve_reference/cve_cwe —
-- those are owned by NVD/MITRE's processRecord.ts, which DELETEs-and-reinserts
-- (cpe/cve_reference/cve_cwe) or UPSERTs (cve) on every write; mixing OSV data
-- into those tables would churn or silently wipe it on the next NVD/MITRE
-- pass. OSV gets its own tables and its own write path
-- (apps/ingest/src/lib/server/osvPatch.ts), per CLAUDE.md's migration
-- convention (forward-only, never edit a shipped migration).

PRAGMA foreign_keys = ON;

-- One row per OSV record this ingest path has ever seen (across all 8
-- ecosystem directories). Tracks enough to (a) skip-if-unchanged on every
-- rescan via `modified_at` string equality — OSV re-exports full CSVs, not
-- deltas, so this is the same philosophy as processRecord.ts's two-hash gate
-- — and (b) find records seen before any NVD/MITRE CVE row existed for them,
-- so a later re-link pass can promote them once NVD/MITRE catches up.
--
-- IF NOT EXISTS: production D1 may already carry a leftover table of this
-- name from a previous, now-lost OSV adapter implementation that ran
-- against production through Oct 26 (see docs/EXECUTION_PLAN.md's "Lost
-- ingestion sources" row) — this migration must not fail outright at deploy
-- time on that collision, same reasoning as the INSERT OR IGNORE seed row
-- below. Residual risk this does NOT cover: if a leftover table has a
-- DIFFERENT shape than this migration expects, IF NOT EXISTS silently skips
-- creating the correct schema instead of failing loudly — that case still
-- needs a human to check production's actual schema before this migration
-- is applied (already flagged elsewhere as pending).
CREATE TABLE IF NOT EXISTS osv_record_state (
  osv_id         TEXT PRIMARY KEY,
  ecosystem_dir  TEXT NOT NULL,
  -- OSV's `modified` field, verbatim (nanosecond-precision ISO string).
  -- Compared as plain string equality for the skip-if-unchanged gate — never
  -- parsed back to ms except as a sort/cursor key, where Date.parse()'s
  -- ms-truncation is explicitly safe for that purpose (not for equality).
  modified_at    TEXT NOT NULL,
  content_hash   TEXT,
  status         TEXT NOT NULL CHECK (status IN ('LINKED','NO_CVE_ALIAS','CVE_NOT_INGESTED','WITHDRAWN')),
  -- Comma-joined CVE aliases this OSV record carries (may be more than what
  -- actually got LINKED — cve_osv_affected only holds rows for alias CVEs
  -- that exist in `cve` at write time; this column is the full alias list,
  -- used by the re-link pass to recheck the ones that didn't exist yet).
  cve_ids        TEXT NOT NULL DEFAULT '',
  first_seen_at  INTEGER NOT NULL,
  checked_at     INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

-- Bounded re-link pass (pipelines/osv.ts's runOsvDiscovery) scans recent
-- CVE_NOT_INGESTED rows oldest-first, LIMIT'd — this partial index keeps
-- that scan cheap regardless of how large osv_record_state grows overall.
--
-- IF NOT EXISTS: so this migration stays safely re-runnable end-to-end (an
-- operator retrying a partially-failed apply) even though the table above it
-- is itself a no-op on a second run via its own IF NOT EXISTS.
CREATE INDEX IF NOT EXISTS idx_osv_state_relink ON osv_record_state(first_seen_at)
  WHERE status = 'CVE_NOT_INGESTED';

-- cve_id leads the PK (not osv_id) so the aging sweep's existing
-- cascade-delete-on-cve behavior (DELETE FROM cve ... → ON DELETE CASCADE)
-- continues to clean these rows up the same way it already does for
-- cpe/cve_reference/cve_cwe — nothing here needs its own aging-sweep logic.
--
-- IF NOT EXISTS: same leftover-table rationale as osv_record_state above,
-- same residual risk (a same-named-but-different-shaped leftover table
-- would be silently kept as-is rather than recreated correctly).
CREATE TABLE IF NOT EXISTS cve_osv_affected (
  cve_id          TEXT NOT NULL REFERENCES cve(cve_id) ON DELETE CASCADE,
  osv_id          TEXT NOT NULL,
  ecosystem       TEXT NOT NULL,
  package_name    TEXT NOT NULL,
  purl            TEXT,
  ranges_json     TEXT NOT NULL,
  fixed_versions  TEXT,
  PRIMARY KEY (cve_id, osv_id, ecosystem, package_name)
) STRICT, WITHOUT ROWID;

-- osv_id lookups (e.g. "delete every row this OSV record previously wrote")
-- don't hit the PK's leading edge, since cve_id leads it — this index covers
-- that access path.
--
-- IF NOT EXISTS: same re-runnability reasoning as idx_osv_state_relink above.
CREATE INDEX IF NOT EXISTS idx_cve_osv_affected_osv ON cve_osv_affected(osv_id);

-- Seed the ingest_run row for OSV so /admin/health always has one, same
-- convention as migration 0002's seed block. INSERT OR IGNORE: production D1
-- may already carry a leftover 'OSV' row from a previous, now-lost adapter
-- implementation (see docs/EXECUTION_PLAN.md's "Lost ingestion sources"
-- row) — this must not collide with (or be clobbered by) that row.
INSERT OR IGNORE INTO ingest_run (source) VALUES ('OSV');
