-- Migration 0002: Operational tables
-- cve_quarantine, ingest_run, audit_log, cve_source_provenance,
-- search_quota_ledger, search_quota_ip_ledger

PRAGMA foreign_keys = ON;

CREATE TABLE cve_quarantine (
  quarantine_id  INTEGER PRIMARY KEY AUTOINCREMENT,
  source         TEXT NOT NULL,
  cve_id         TEXT,
  payload        TEXT NOT NULL,
  error_code     TEXT NOT NULL,
  error_message  TEXT NOT NULL,
  quarantined_at INTEGER NOT NULL
) STRICT;

CREATE TABLE ingest_run (
  source            TEXT PRIMARY KEY,
  last_started_at   INTEGER,
  last_finished_at  INTEGER,
  last_status       TEXT CHECK (last_status IN ('OK','PARTIAL','FAILED')),
  records_processed INTEGER,
  records_failed    INTEGER,
  last_error        TEXT
) STRICT, WITHOUT ROWID;

-- Seed known sources so /admin/health always has a row per source
INSERT INTO ingest_run (source) VALUES ('NVD');
INSERT INTO ingest_run (source) VALUES ('MITRE');
INSERT INTO ingest_run (source) VALUES ('KEV');
INSERT INTO ingest_run (source) VALUES ('EPSS');
INSERT INTO ingest_run (source) VALUES ('AGING');
INSERT INTO ingest_run (source) VALUES ('RECONCILE');
INSERT INTO ingest_run (source) VALUES ('IPLIST_PRUNE');

CREATE TABLE audit_log (
  audit_id    INTEGER PRIMARY KEY AUTOINCREMENT,
  occurred_at INTEGER NOT NULL,
  client_ip   TEXT NOT NULL,
  cf_ray      TEXT NOT NULL,
  route       TEXT NOT NULL,
  action      TEXT NOT NULL,
  detail_json TEXT
) STRICT;

CREATE TABLE cve_source_provenance (
  cve_id       TEXT NOT NULL REFERENCES cve(cve_id) ON DELETE CASCADE,
  source       TEXT NOT NULL,
  last_seen_at INTEGER NOT NULL,
  PRIMARY KEY (cve_id, source)
) STRICT, WITHOUT ROWID;

CREATE TABLE search_quota_ledger (
  day         TEXT PRIMARY KEY,
  query_count INTEGER NOT NULL DEFAULT 0
) STRICT, WITHOUT ROWID;

CREATE TABLE search_quota_ip_ledger (
  bucket      TEXT NOT NULL,
  client_ip   TEXT NOT NULL,
  query_count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (bucket, client_ip)
) STRICT, WITHOUT ROWID;
