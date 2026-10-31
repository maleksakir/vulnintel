-- Migration 0012: Remediation / risk acceptance (Phase 4).
--
-- An analyst can formally RISK-ACCEPT a CVE for a bounded time with a written
-- justification. While an acceptance is active (not past its expiry), the CVE
-- is demoted/suppressed in watchlist + asset views; once it expires it
-- AUTO-REACTIVATES (becomes actionable again) — modeled on DefectDojo's
-- risk-acceptance, where expiry is mandatory specifically so acceptances
-- can't silently become permanent.
--
-- Scope: GLOBAL per CVE (not per-watchlist/per-asset). The same CVE surfaces
-- across watchlists and assets, so one acceptance decision per CVE is the
-- coherent model; "active" is derived at read time from expires_at vs now, so
-- auto-reactivation needs no cron (it just stops being active when the clock
-- passes expiry). Single-tenant, same as 0009/0011.
--
-- Additive only. IF NOT EXISTS per the re-runnability lesson. cve_id is NOT an
-- FK (an acceptance can outlive an aged-out CVE as an audit record; the aging
-- tail prunes long-expired ones).

PRAGMA foreign_keys = ON;

-- One current risk-acceptance decision per CVE (PK = cve_id). Re-accepting a
-- CVE (e.g. extending the window) upserts this row; its history is not kept
-- (a decisions-log table is a later enhancement if ever needed).
CREATE TABLE IF NOT EXISTS cve_risk_acceptance (
  cve_id        TEXT PRIMARY KEY,
  justification TEXT NOT NULL,
  accepted_by   TEXT,              -- optional free-text (analyst handle); no user model
  accepted_at   INTEGER NOT NULL,  -- unix ms
  expires_at    INTEGER NOT NULL,  -- unix ms — MANDATORY (DefectDojo model)
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

-- The aging-sweep tail prunes acceptances whose expiry is well in the past
-- (they've long since auto-reactivated; keep a short grace window for audit).
CREATE INDEX IF NOT EXISTS idx_risk_acceptance_expires
  ON cve_risk_acceptance(expires_at);
