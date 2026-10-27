const IP_HOURLY_LIMIT = 500;
const ORG_DAILY_LIMIT = 50_000;

export interface QuotaResult {
  allowed: boolean;
  reason?: 'RATE_LIMITED' | 'GLOBAL_QUOTA_EXHAUSTED';
}

/**
 * Checks per-IP hourly (500 req/hr) and org-wide daily (50k/day) quotas.
 * Increments both counters atomically if within limits.
 */
export async function checkAndIncrementQuota(
  db: D1Database,
  clientIp: string,
): Promise<QuotaResult> {
  const now = new Date();
  const day = now.toISOString().slice(0, 10); // YYYY-MM-DD
  const bucket = `${day}-${String(now.getUTCHours()).padStart(2, '0')}`; // YYYY-MM-DD-HH

  const [ipRow, orgRow] = await Promise.all([
    db.prepare(
      'SELECT query_count FROM search_quota_ip_ledger WHERE bucket = ? AND client_ip = ?',
    ).bind(bucket, clientIp).first<{ query_count: number }>(),
    db.prepare('SELECT query_count FROM search_quota_ledger WHERE day = ?')
      .bind(day).first<{ query_count: number }>(),
  ]);

  if ((ipRow?.query_count ?? 0) >= IP_HOURLY_LIMIT) {
    return { allowed: false, reason: 'RATE_LIMITED' };
  }

  if ((orgRow?.query_count ?? 0) >= ORG_DAILY_LIMIT) {
    return { allowed: false, reason: 'GLOBAL_QUOTA_EXHAUSTED' };
  }

  // Increment best-effort — quota enforcement doesn't need perfect accuracy.
  await db.batch([
    db.prepare(
      `INSERT INTO search_quota_ledger (day, query_count) VALUES (?, 1)
       ON CONFLICT (day) DO UPDATE SET query_count = query_count + 1`,
    ).bind(day),
    db.prepare(
      `INSERT INTO search_quota_ip_ledger (bucket, client_ip, query_count) VALUES (?, ?, 1)
       ON CONFLICT (bucket, client_ip) DO UPDATE SET query_count = query_count + 1`,
    ).bind(bucket, clientIp),
  ]).catch(() => { /* best-effort */ });

  return { allowed: true };
}
