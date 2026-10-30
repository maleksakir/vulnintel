-- Migration 0008: SSVC (Stakeholder-Specific Vulnerability Categorization)
-- decision points, sourced from NVD API 2.0's metrics.ssvcV203[] (CISA-ADP
-- entry only — see apps/ingest/src/adapters/nvd.ts's extractSsvcDecision).
--
-- Additive only: four nullable columns on the EXISTING cve_state table, not
-- a new table. This is 1:1 external-enrichment data keyed by cve_id, the
-- exact same pattern cve_state already uses for KEV/EPSS (migration 0001).
--
-- No CHECK constraint on the enum columns. processRecord.ts's writeD1 writes
-- these columns inside the SAME db.batch() as the core cve/cve_state/
-- provenance write — a CHECK violation there would roll back that entire
-- batch, including the core CVE row, over a problem that's purely
-- SSVC-shaped. The enum is validated in the adapter instead
-- (apps/ingest/src/adapters/nvd.ts's pickSsvcEnum): an unexpected/unknown
-- value becomes null rather than throwing or ever reaching D1 unvalidated.
--
-- ⚠ PROVISIONING NOTE — unverified against production:
-- SQLite's `ALTER TABLE ADD COLUMN` has no `IF NOT EXISTS`, and this
-- migration will fail outright if any of the four column names below
-- already exist on production's cve_state (e.g. a leftover from the lost
-- prior implementation — see docs/EXECUTION_PLAN.md's "Lost ingestion
-- sources" row — the same collision risk migration 0007 documents for OSV).
-- This migration was authored WITHOUT running `PRAGMA table_info(cve_state)`
-- against production first, by deliberate choice: CLAUDE.md's "Known
-- constraints" section documents a live-debugging-caused outage on
-- 2026-10-28 from exactly this kind of "just a cheap diagnostic query"
-- reasoning, and this task's own instructions separately said not to run
-- wrangler commands against the live account. Run
-- `PRAGMA table_info(cve_state)` against production yourself and confirm
-- none of ssvc_exploitation / ssvc_automatable / ssvc_technical_impact /
-- ssvc_updated_at already exist BEFORE applying this migration. If one
-- does, stop and reconcile the schema — do not silently rename around it.

ALTER TABLE cve_state ADD COLUMN ssvc_exploitation     TEXT;
ALTER TABLE cve_state ADD COLUMN ssvc_automatable      TEXT;
ALTER TABLE cve_state ADD COLUMN ssvc_technical_impact TEXT;
ALTER TABLE cve_state ADD COLUMN ssvc_updated_at       INTEGER;
