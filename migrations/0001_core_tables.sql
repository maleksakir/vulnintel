-- Migration 0001: Core CVE tables
-- cve, cwe, cve_cwe, cpe, cve_reference, cve_state
-- Forward-only. Fix errors with a new migration, never edit this file.

PRAGMA foreign_keys = ON;

CREATE TABLE cve (
  cve_id              TEXT PRIMARY KEY,
  published_at        INTEGER NOT NULL,
  last_modified_at    INTEGER NOT NULL,
  description         TEXT NOT NULL,
  cvss_version        TEXT,
  cvss_vector         TEXT,
  cvss_base           REAL,
  cvss_exploitability REAL,
  cvss_impact         REAL,
  severity            TEXT CHECK (severity IN ('NONE','LOW','MEDIUM','HIGH','CRITICAL')),
  source              TEXT NOT NULL,
  text_hash           TEXT NOT NULL,
  state_hash          TEXT NOT NULL,
  ingested_at         INTEGER NOT NULL
) STRICT;

CREATE TABLE cwe (
  cwe_id   TEXT PRIMARY KEY,
  name     TEXT,
  category TEXT
) STRICT;

CREATE TABLE cve_cwe (
  cve_id TEXT NOT NULL REFERENCES cve(cve_id) ON DELETE CASCADE,
  cwe_id TEXT NOT NULL REFERENCES cwe(cwe_id),
  PRIMARY KEY (cve_id, cwe_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE cpe (
  cpe_row_id              INTEGER PRIMARY KEY AUTOINCREMENT,
  cve_id                  TEXT NOT NULL REFERENCES cve(cve_id) ON DELETE CASCADE,
  cpe_uri                 TEXT NOT NULL,
  part                    TEXT CHECK (part IN ('a','o','h')),
  vendor                  TEXT NOT NULL,
  product                 TEXT NOT NULL,
  version                 TEXT,
  version_start_including TEXT,
  version_start_excluding TEXT,
  version_end_including   TEXT,
  version_end_excluding   TEXT,
  vulnerable              INTEGER NOT NULL DEFAULT 1,
  extras_json             TEXT
) STRICT;

CREATE TABLE cve_reference (
  cve_id TEXT NOT NULL REFERENCES cve(cve_id) ON DELETE CASCADE,
  url    TEXT NOT NULL,
  tags   TEXT,
  PRIMARY KEY (cve_id, url)
) STRICT, WITHOUT ROWID;

CREATE TABLE cve_state (
  cve_id              TEXT PRIMARY KEY REFERENCES cve(cve_id) ON DELETE CASCADE,
  kev_listed          INTEGER NOT NULL DEFAULT 0,
  kev_date_added      INTEGER,
  kev_due_date        INTEGER,
  kev_required_action TEXT,
  epss_score          REAL,
  epss_percentile     REAL,
  epss_updated_at     INTEGER,
  state_updated_at    INTEGER NOT NULL
) STRICT, WITHOUT ROWID;
