const ORG_DAILY_LIMIT = 50_000;
// Per-IP hourly AI-cost cap (spec §4.3.2 / §5.3.7). This is the cap the
// native rate-limit binding CANNOT express: that binding only accepts a
// period of 10 or 60 seconds (confirmed against Cloudflare's docs), so a
// 1-hour window has to live in D1 — exactly what `search_quota_ip_ledger`
// (migration 0002, bucket = 'YYYY-MM-DD-HH') was created for but nothing
// ever wrote to. Without it, the binding's 500/60s still permits ~30,000
// searches/hour from ONE IP, and at ~2.3 neurons/search that drains the
// shared 10,000-neuron/day Workers AI pool (which ingest's embeddings also
// draw from) in minutes — a failed ingest embed then cascades to permanently
// stale vectors (see rerank.ts / CLAUDE.md). The native binding stays as the
// cheap first-line volumetric guard; this is the real per-IP AI budget.
const IP_HOURLY_LIMIT = 500;

export interface QuotaResult {
  allowed: boolean;
  reason?: 'RATE_LIMITED' | 'GLOBAL_QUOTA_EXHAUSTED';
  /**
   * `search_quota_ledger.query_count` for today as read BEFORE this
   * request's increment — i.e. how many searches were already served today,
   * not counting this one. Omitted when an earlier gate (rate limiter or the
   * per-IP hourly cap) short-circuited before the org-wide D1 read ever ran.
   * searchCves() uses this to gate query-time reranking against
   * RERANK_DAILY_SEARCH_CAP (see rerank.ts) by piggybacking on the read this
   * function already does — zero extra D1/KV operations, no new counter.
   */
  dailyCount?: number;
}

/**
 * Three layered gates for the /api/search path, cheapest first:
 *   1. Workers-native rate-limit binding (free, no D1) — short-window
 *      volumetric abuse guard (~500/60s per IP, per-colo, approximate).
 *   2. Per-IP hourly AI-cost cap in D1 (`search_quota_ip_ledger`, 500/hour)
 *      — the longer window the binding can't express; this is the gate that
 *      actually protects the shared Workers AI neuron pool from a single IP.
 *   3. Org-wide daily cap in D1 (`search_quota_ledger`, 50k/day).
 *
 * Per allowed request: 2 D1 reads + 1 batched D1 write (both counter upserts
 * in one `db.batch()`). The org-wide daily cap is bounded at 50k/day, so even
 * the worst case stays comfortably inside the free-tier D1 write budget —
 * the spec (§4.3.1) explicitly accepts one write per search as trivially
 * cheap. Reads are ordered per-IP-first so a flooding IP is rejected without
 * the org-wide read.
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
  const iso = now.toISOString();
  const day = iso.slice(0, 10); // YYYY-MM-DD
  const bucket = iso.slice(0, 13).replace('T', '-'); // YYYY-MM-DD-HH (UTC)

  // Gate 2: per-IP hourly cap. Rejected as RATE_LIMITED (a per-client limit),
  // not GLOBAL_QUOTA_EXHAUSTED (which is reserved for the org-wide cap).
  const ipRow = await db
    .prepare('SELECT query_count FROM search_quota_ip_ledger WHERE bucket = ? AND client_ip = ?')
    .bind(bucket, clientIp)
    .first<{ query_count: number }>();
  if ((ipRow?.query_count ?? 0) >= IP_HOURLY_LIMIT) {
    return { allowed: false, reason: 'RATE_LIMITED' };
  }

  // Gate 3: org-wide daily cap.
  const orgRow = await db
    .prepare('SELECT query_count FROM search_quota_ledger WHERE day = ?')
    .bind(day)
    .first<{ query_count: number }>();
  const dailyCount = orgRow?.query_count ?? 0;

  if (dailyCount >= ORG_DAILY_LIMIT) {
    return { allowed: false, reason: 'GLOBAL_QUOTA_EXHAUSTED', dailyCount };
  }

  // Increment both ledgers best-effort in a single batch — quota enforcement
  // doesn't need perfect accuracy, and one batch keeps this at ONE D1 write
  // (query) toward the per-invocation budget regardless of the two statements.
  await db
    .batch([
      db
        .prepare(
          `INSERT INTO search_quota_ledger (day, query_count) VALUES (?, 1)
           ON CONFLICT (day) DO UPDATE SET query_count = query_count + 1`,
        )
        .bind(day),
      db
        .prepare(
          `INSERT INTO search_quota_ip_ledger (bucket, client_ip, query_count) VALUES (?, ?, 1)
           ON CONFLICT (bucket, client_ip) DO UPDATE SET query_count = query_count + 1`,
        )
        .bind(bucket, clientIp),
    ])
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
