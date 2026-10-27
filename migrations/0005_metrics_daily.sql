-- Migration 0005: Daily metrics rollup table
-- Survives Analytics Engine's 90-day retention limit.
-- Populated by the aging-sweep cron (30 2 * * *).

CREATE TABLE cve_metrics_daily (
  metric_date INTEGER NOT NULL,
  metric_key  TEXT NOT NULL,
  value       REAL NOT NULL,
  PRIMARY KEY (metric_date, metric_key)
) STRICT, WITHOUT ROWID;
