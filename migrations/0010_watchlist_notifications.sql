-- Migration 0010: Watchlist notifications (Phase 3, step 5).
--
-- A webhook endpoint per watchlist (email/Slack/generic are all webhook
-- shapes from the sender's side), plus per-match notification tracking so a
-- newly-matched CVE fires an alert exactly once rather than on every
-- reconciliation run. Additive only; extends the 0009 watchlist model.
--
-- IF NOT EXISTS / ADD COLUMN guards: forward-only, and tolerant of a re-run.
-- (watchlist_match already existed from 0009, so the new column is an
-- ALTER ADD COLUMN — SQLite has no IF NOT EXISTS for that, but 0010 is a new
-- file applied once by the migrations runner; the re-runnability concern that
-- bit 0007/0009 was about their CREATE statements, which here are guarded.)

PRAGMA foreign_keys = ON;

-- Webhook endpoints for a watchlist. `kind` lets the sender format the
-- payload appropriately (Slack expects {text}, generic gets the raw digest).
CREATE TABLE IF NOT EXISTS watchlist_webhook (
  webhook_id    INTEGER PRIMARY KEY AUTOINCREMENT,
  watchlist_id  INTEGER NOT NULL REFERENCES watchlist(watchlist_id) ON DELETE CASCADE,
  kind          TEXT NOT NULL DEFAULT 'generic' CHECK (kind IN ('generic', 'slack')),
  url           TEXT NOT NULL,
  enabled       INTEGER NOT NULL DEFAULT 1,
  created_at    INTEGER NOT NULL,
  -- Last time a dispatch to this endpoint succeeded / was attempted, for
  -- /admin visibility; not used for dedup (that's watchlist_match.notified_at).
  last_dispatch_at     INTEGER,
  last_dispatch_status TEXT
) STRICT;

CREATE INDEX IF NOT EXISTS idx_wl_webhook_watchlist
  ON watchlist_webhook(watchlist_id);

-- Per-match notification watermark: NULL = never notified. The notifier
-- selects matches with notified_at IS NULL (and still status='NEW') for a
-- watchlist that has an enabled webhook, dispatches a digest, then stamps
-- this — so an alert fires once per newly-matched CVE, not every run.
ALTER TABLE watchlist_match ADD COLUMN notified_at INTEGER;

-- Covers the notifier's "unnotified NEW matches for this watchlist" scan.
CREATE INDEX IF NOT EXISTS idx_wl_match_unnotified
  ON watchlist_match(watchlist_id) WHERE notified_at IS NULL;
