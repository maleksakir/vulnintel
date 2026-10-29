const ORG_DAILY_LIMIT = 50_000;

export interface QuotaResult {
  allowed: boolean;
  reason?: 'RATE_LIMITED' | 'GLOBAL_QUOTA_EXHAUSTED';
  /**
   * `search_quota_ledger.query_count` for today as read BEFORE this
   * request's increment — i.e. how many searches were already served today,
   * not counting this one. Omitted when the rate limiter short-circuited
   * before the D1 read ever ran (no count was read). searchCves() uses this
   * to gate query-time reranking against RERANK_DAILY_SEARCH_CAP (see
   * rerank.ts) by piggybacking on the read this function already does —
   * zero extra D1/KV operations, no new counter.
   */
  dailyCount?: number;
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

  const orgRow = await db
    .prepare('SELECT query_count FROM search_quota_ledger WHERE day = ?')
    .bind(day)
    .first<{ query_count: number }>();
  const dailyCount = orgRow?.query_count ?? 0;

  if (dailyCount >= ORG_DAILY_LIMIT) {
    return { allowed: false, reason: 'GLOBAL_QUOTA_EXHAUSTED', dailyCount };
  }

  // Increment best-effort — quota enforcement doesn't need perfect accuracy.
  await db
    .prepare(
      `INSERT INTO search_quota_ledger (day, query_count) VALUES (?, 1)
     ON CONFLICT (day) DO UPDATE SET query_count = query_count + 1`,
    )
    .bind(day)
    .run()
    .catch(() => {
      /* best-effort */
    });

  return { allowed: true, dailyCount };
}

/**
 * Lightweight per-IP throttle for the cache-lookup routes (cve/[id],
 * affected-products, metrics, threat-intel/kev, threat-intel/epss) — just
 * the native rate-limit binding, no D1 traffic at all. Found missing from
 * all of these during the 2026-10-28 security review: cve/[id]'s cache key
 * is `cve:${cveId}`, and CVE IDs are sequentially enumerable, so an
 * unthrottled client could generate effectively unlimited distinct KV
 * writes the same way the 2026-10-27 incident did. Shares the same
 * RATE_LIMITER binding/key as search, so switching routes doesn't let a
 * client multiply their effective throughput.
 */
export async function checkRateLimit(
  rateLimiter: RateLimit,
  clientIp: string,
): Promise<QuotaResult> {
  const { success } = await rateLimiter.limit({ key: clientIp });
  return success ? { allowed: true } : { allowed: false, reason: 'RATE_LIMITED' };
}
