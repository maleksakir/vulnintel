-- Migration 0004: FTS5 virtual tables and sync triggers
-- cve_search (description full-text) + cpe_search (vendor/product)
-- FTS5 does not support STRICT.

CREATE VIRTUAL TABLE cve_search USING fts5(
  cve_id    UNINDEXED,
  description,
  tokenize = 'porter unicode61 remove_diacritics 2'
);

CREATE VIRTUAL TABLE cpe_search USING fts5(
  vendor,
  product,
  tokenize = 'porter unicode61 remove_diacritics 2'
);

-- Keep cve_search in sync with the cve table.

CREATE TRIGGER cve_fts_insert AFTER INSERT ON cve BEGIN
  INSERT INTO cve_search(cve_id, description) VALUES (new.cve_id, new.description);
END;

CREATE TRIGGER cve_fts_update AFTER UPDATE OF description ON cve BEGIN
  UPDATE cve_search SET description = new.description WHERE cve_id = new.cve_id;
END;

CREATE TRIGGER cve_fts_delete AFTER DELETE ON cve BEGIN
  DELETE FROM cve_search WHERE cve_id = old.cve_id;
END;

-- Keep cpe_search in sync with the cpe table (deduplicated by vendor+product pair).
-- Insert a search row only when a new vendor+product pair appears.

CREATE TRIGGER cpe_fts_insert AFTER INSERT ON cpe BEGIN
  INSERT OR IGNORE INTO cpe_search(vendor, product) VALUES (new.vendor, new.product);
END;

-- Note: cpe rows are deleted in bulk by the aging sweep. After the sweep the
-- ingest worker rebuilds cpe_search from the remaining cpe rows via:
--   DELETE FROM cpe_search;
--   INSERT INTO cpe_search(vendor, product)
--     SELECT DISTINCT vendor, product FROM cpe;
-- This is handled in the aging pipeline (Section 5.1.6), not via a trigger,
-- because a per-row DELETE trigger would fire O(n) times during bulk deletes
-- and a single post-sweep rebuild is cheaper and more correct.
