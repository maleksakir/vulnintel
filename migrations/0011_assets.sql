-- Migration 0011: Asset inventory + SBOM import (Phase 4).
--
-- An "asset" is a tracked application/service; its components come from an
-- uploaded CycloneDX SBOM. Each component is matched to CVEs PURL-first
-- (against cve_osv_affected, which OSV ingestion already populates — so this
-- reuses existing ingested data, no new ingest pipeline), falling back to CPE
-- vendor/product (against the cpe table) when no PURL match exists.
--
-- Modeled on OWASP Dependency-Track (PURL-primary identity, project
-- hierarchy). SINGLE-TENANT, same reasoning as watchlists (0009) — the spec
-- has no user identity to scope a multi-tenant portfolio to; shaped so
-- multi-tenancy is an additive column later.
--
-- Additive only; never touches cve/cpe/cve_osv_affected (read-only against
-- those). IF NOT EXISTS on every table + index (0007/0009 re-runnability
-- lesson) and tolerant of a leftover same-named table from the lost prior
-- implementation (the dropped ~53 tables included an asset-inventory model;
-- a DIFFERENTLY-shaped leftover must be checked for before applying, same
-- caveat as 0009's header).

PRAGMA foreign_keys = ON;

-- A tracked application/service.
CREATE TABLE IF NOT EXISTS asset (
  asset_id      INTEGER PRIMARY KEY AUTOINCREMENT,
  name          TEXT NOT NULL,
  description   TEXT,
  created_at    INTEGER NOT NULL,   -- unix ms
  updated_at    INTEGER NOT NULL,
  -- Last SBOM import: timestamp + component count, for the inventory list.
  last_import_at        INTEGER,
  last_component_count  INTEGER NOT NULL DEFAULT 0
) STRICT;

-- One component (dependency) of an asset, from its SBOM. purl is the primary
-- identity; vendor/product are a best-effort CPE fallback parsed from the purl
-- (or left null for match-by-purl-only components).
CREATE TABLE IF NOT EXISTS asset_component (
  component_id  INTEGER PRIMARY KEY AUTOINCREMENT,
  asset_id      INTEGER NOT NULL REFERENCES asset(asset_id) ON DELETE CASCADE,
  name          TEXT NOT NULL,
  version       TEXT,
  purl          TEXT,              -- pkg:ecosystem/namespace/name@version (nullable)
  ecosystem     TEXT,              -- derived from purl (npm, pypi, maven, …)
  cpe_vendor    TEXT,              -- CPE fallback (lowercased), nullable
  cpe_product   TEXT,              -- CPE fallback (lowercased), nullable
  created_at    INTEGER NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_asset_component_asset
  ON asset_component(asset_id);
-- Purl lookups against cve_osv_affected during matching.
CREATE INDEX IF NOT EXISTS idx_asset_component_purl
  ON asset_component(purl) WHERE purl IS NOT NULL;

-- Materialized CVE matches per component. Like watchlist_match: cve_id is NOT
-- an FK (an aged-out CVE's match record survives the hard-delete; swept by the
-- aging tail, not CASCADE). `match_via` records how the link was found.
CREATE TABLE IF NOT EXISTS asset_component_match (
  component_id  INTEGER NOT NULL REFERENCES asset_component(component_id) ON DELETE CASCADE,
  cve_id        TEXT NOT NULL,
  match_via     TEXT NOT NULL CHECK (match_via IN ('PURL', 'CPE')),
  first_matched_at INTEGER NOT NULL,
  PRIMARY KEY (component_id, cve_id)
) STRICT, WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_asset_match_cve
  ON asset_component_match(cve_id);
