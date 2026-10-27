const ORG_DAILY_LIMIT = 50_000;

export interface QuotaResult {
  allowed: boolean;
  reason?: 'RATE_LIMITED' | 'GLOBAL_QUOTA_EXHAUSTED';
}

/**
 * Per-IP throttling runs on the free Workers-native rate-limit binding
 * (approximate, no D1 read/write at all) — exact accounting only matters
 * for the org-wide daily quota below, which stays in D1. Per-request D1
 * traffic for this check used to be 2 reads + 2 writes; it's now 1 read +
 * 1 write (same D1 unconditional-write-per-request shape that caused the
 * 2026-10-27 KV incident, just for the one counter that actually needs
 * exact durability — see CLAUDE.md).
 */
export async function checkAndIncrementQuota(
  db: D1Database,
  rateLimiter: RateLimit,
  clientIp: string,
): Promise<QuotaResult> {
  const { success } = await rateLimiter.limit({ key: clientIp });
  if (!success) {
    return { allowed: false, reason: 'RATE_LIMITED' };
  }

  const now = new Date();
  const day = now.toISOString().slice(0, 10); // YYYY-MM-DD

  const orgRow = await db.prepare('SELECT query_count FROM search_quota_ledger WHERE day = ?')
    .bind(day).first<{ query_count: number }>();

  if ((orgRow?.query_count ?? 0) >= ORG_DAILY_LIMIT) {
    return { allowed: false, reason: 'GLOBAL_QUOTA_EXHAUSTED' };
  }

  // Increment best-effort — quota enforcement doesn't need perfect accuracy.
  await db.prepare(
    `INSERT INTO search_quota_ledger (day, query_count) VALUES (?, 1)
     ON CONFLICT (day) DO UPDATE SET query_count = query_count + 1`,
  ).bind(day).run().catch(() => { /* best-effort */ });

  return { allowed: true };
}
