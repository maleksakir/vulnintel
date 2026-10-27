-- Migration 0003: Performance indices
-- All entries from Section 3.1.3 of the spec.

CREATE INDEX idx_cve_severity_published    ON cve(severity, published_at DESC);
CREATE INDEX idx_cve_last_modified         ON cve(last_modified_at DESC);
CREATE INDEX idx_cve_published_at          ON cve(published_at DESC);

CREATE INDEX idx_cpe_vendor_product        ON cpe(vendor, product);
CREATE INDEX idx_cpe_cve                   ON cpe(cve_id);

CREATE INDEX idx_state_kev_partial         ON cve_state(kev_date_added) WHERE kev_listed = 1;
CREATE INDEX idx_state_epss_desc           ON cve_state(epss_score DESC) WHERE epss_score IS NOT NULL;

CREATE INDEX idx_reference_cve             ON cve_reference(cve_id);

CREATE INDEX idx_quarantine_source_time    ON cve_quarantine(source, quarantined_at DESC);

CREATE INDEX idx_audit_time                ON audit_log(occurred_at DESC);
CREATE INDEX idx_audit_ip_time             ON audit_log(client_ip, occurred_at DESC);

CREATE INDEX idx_quota_ip_bucket           ON search_quota_ip_ledger(bucket);
