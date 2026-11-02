-- Migration 0013: stop the cve_search triggers full-scanning the FTS index
--
-- THE BUG (found 2026-10-31 via `wrangler d1 insights`, after production D1
-- hit the free-tier 5M-row/day read cap with ingestion unable to complete):
--
--   migration 0004 declares `cve_search` as fts5(cve_id UNINDEXED, description),
--   then keys both the update and delete triggers on `WHERE cve_id = ?`.
--   An FTS5 UNINDEXED column has no index — by definition, it is stored but
--   not searchable — so each of those statements is a FULL SCAN of the FTS
--   index. Measured cost on production: 3,834 rows read per single-CVE write.
--
--   `writeD1` (processRecord.ts) fires on any text OR state change, which is
--   ~2,960 CVEs/day, and its upsert assigns `description` unconditionally in
--   the ON CONFLICT DO UPDATE clause. SQLite's `AFTER UPDATE OF description`
--   fires on ASSIGNMENT, not on a value change, so the trigger ran on every
--   one of those writes even though a published CVE's description almost
--   never changes — the write was nearly always caused by a severity, CVSS or
--   EPSS change instead.
--
--   2,960 writes/day x 3,834 reads = ~11.3M rows/day, 2.3x the ENTIRE daily
--   read allowance, from the index-maintenance side of ingestion alone. That
--   is why NVD/KEV/OSV rows were never confirmed landing in production: every
--   day ingestion exhausted the account's reads and started failing with
--   D1 error 7500.
--
--   The same defect made the delete trigger a full scan per deleted row.
--   The aging sweep deletes in batches of hundreds, so each batch cost
--   hundreds of full FTS scans — the real reason that job had been getting
--   killed mid-run for ~2 months (recorded in CLAUDE.md as a CPU/time budget
--   problem, which was the symptom, not the cause).
--
-- 0004's own closing comment reasons correctly about exactly this hazard for
-- `cpe_search` ("a per-row DELETE trigger would fire O(n) times during bulk
-- deletes and a single post-sweep rebuild is cheaper") and then does the
-- opposite for `cve_search`.
--
-- THE FIX, in two parts:
--
--   1. The update trigger gains a WHEN guard, so it fires only when the
--      description genuinely changed. This removes essentially all of the
--      11.3M/day — a state-only change now costs zero FTS work.
--
--   2. The delete trigger is REMOVED. Orphan cleanup moves into the aging
--      sweep (pipelines/aging.ts), which now deletes the matching cve_search
--      rows with ONE statement per batch instead of one full scan per row —
--      the same approach 0004 already chose for cpe_search. Between a CVE's
--      deletion and the next sweep an orphaned FTS row can survive, which is
--      harmless: searchCves.ts fuses FTS hits by cve_id and then hydrates
--      from `cve`, so a stale id contributes nothing to the results.
--
-- No data is moved and nothing is rebuilt: `cve_search` keeps its existing
-- contents and its MATCH queries are untouched (an UNINDEXED column is fine
-- as a returned payload — it is only the WHERE that was pathological). That
-- matters because re-indexing 375k descriptions would cost more writes than
-- the 100k/day free-tier write allowance permits.
--
-- A properly-keyed external-content FTS5 table (content='cve',
-- content_rowid='rowid') would make deletes O(log n) as well, but requires
-- that full rebuild, so it is deliberately left as a separate, planned
-- migration rather than bundled into an urgent capacity fix.

DROP TRIGGER IF EXISTS cve_fts_update;

CREATE TRIGGER cve_fts_update AFTER UPDATE OF description ON cve
WHEN new.description IS NOT old.description
BEGIN
  UPDATE cve_search SET description = new.description WHERE cve_id = new.cve_id;
END;

DROP TRIGGER IF EXISTS cve_fts_delete;
