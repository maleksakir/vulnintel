import { applyD1Migrations, reset } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { checkAndIncrementQuota } from '../src/lib/server/quota';

// `RATE_LIMITER` is mocked for determinism (the real Workers-native limiter
// is a 500/60s token bucket — exhausting it for real would be slow and
// flaky in CI). D1 (`search_quota_ledger`, `search_quota_ip_ledger`) runs
// for real against workerd.

const DAY = '2026-10-27';
const BUCKET = '2026-10-27-12'; // YYYY-MM-DD-HH matching the fake clock below
const IP = '203.0.113.5';

describe('checkAndIncrementQuota', () => {
  beforeEach(async () => {
    // `reset()` (afterEach, below) wipes the whole simulated D1 instance,
    // schema included — `setupFiles` only applies migrations once per test
    // file, so each test re-applies them itself. `applyD1Migrations` is
    // idempotent, so this is a no-op the very first time.
    await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
    vi.useFakeTimers();
    vi.setSystemTime(new Date(`${DAY}T12:00:00.000Z`));
  });

  afterEach(async () => {
    vi.useRealTimers();
    vi.restoreAllMocks();
    await reset();
  });

  it('rate-limiter rejection short-circuits before any D1 call', async () => {
    vi.spyOn(env.RATE_LIMITER, 'limit').mockResolvedValue({ success: false });
    const dbPrepare = vi.spyOn(env.DB, 'prepare');

    const result = await checkAndIncrementQuota(env.DB, env.RATE_LIMITER, IP);

    expect(result).toEqual({ allowed: false, reason: 'RATE_LIMITED' });
    expect(dbPrepare).not.toHaveBeenCalled();
  });

  it('enforces the per-IP hourly cap (RATE_LIMITED) before the org-wide read, without writing an increment', async () => {
    vi.spyOn(env.RATE_LIMITER, 'limit').mockResolvedValue({ success: true });
    await env.DB.prepare(
      'INSERT INTO search_quota_ip_ledger (bucket, client_ip, query_count) VALUES (?, ?, ?)',
    )
      .bind(BUCKET, IP, 500)
      .run();

    const dbPrepare = vi.spyOn(env.DB, 'prepare');
    const result = await checkAndIncrementQuota(env.DB, env.RATE_LIMITER, IP);

    expect(result).toEqual({ allowed: false, reason: 'RATE_LIMITED' });
    // Only the per-IP read ran — the org-wide read is never reached, and no
    // increment is written.
    const sql = dbPrepare.mock.calls.map(([s]) => s);
    expect(sql).toHaveLength(1);
    expect(sql[0]).toMatch(/SELECT query_count FROM search_quota_ip_ledger/i);

    const row = await env.DB.prepare(
      'SELECT query_count FROM search_quota_ip_ledger WHERE bucket = ? AND client_ip = ?',
    )
      .bind(BUCKET, IP)
      .first<{ query_count: number }>();
    expect(row?.query_count).toBe(500); // unchanged
  });

  it('a different IP in the same hour is unaffected by another IP hitting its cap', async () => {
    vi.spyOn(env.RATE_LIMITER, 'limit').mockResolvedValue({ success: true });
    await env.DB.prepare(
      'INSERT INTO search_quota_ip_ledger (bucket, client_ip, query_count) VALUES (?, ?, ?)',
    )
      .bind(BUCKET, IP, 500)
      .run();

    const result = await checkAndIncrementQuota(env.DB, env.RATE_LIMITER, '203.0.113.99');
    expect(result).toEqual({ allowed: true, dailyCount: 0 });

    const row = await env.DB.prepare(
      'SELECT query_count FROM search_quota_ip_ledger WHERE bucket = ? AND client_ip = ?',
    )
      .bind(BUCKET, '203.0.113.99')
      .first<{ query_count: number }>();
    expect(row?.query_count).toBe(1); // its own fresh counter
  });

  it('enforces the org-wide daily quota once exhausted, without writing an increment', async () => {
    vi.spyOn(env.RATE_LIMITER, 'limit').mockResolvedValue({ success: true });
    await env.DB.prepare('INSERT INTO search_quota_ledger (day, query_count) VALUES (?, ?)')
      .bind(DAY, 50_000)
      .run();

    const result = await checkAndIncrementQuota(env.DB, env.RATE_LIMITER, IP);

    expect(result).toEqual({
      allowed: false,
      reason: 'GLOBAL_QUOTA_EXHAUSTED',
      dailyCount: 50_000,
    });
    // The org ledger is not incremented past the cap.
    const org = await env.DB.prepare('SELECT query_count FROM search_quota_ledger WHERE day = ?')
      .bind(DAY)
      .first<{ query_count: number }>();
    expect(org?.query_count).toBe(50_000); // unchanged
    // And the per-IP counter is not incremented either (rejected before write).
    const ip = await env.DB.prepare(
      'SELECT query_count FROM search_quota_ip_ledger WHERE bucket = ? AND client_ip = ?',
    )
      .bind(BUCKET, IP)
      .first<{ query_count: number }>();
    expect(ip).toBeNull();
  });

  it('allows the request and increments BOTH ledgers when under all caps', async () => {
    vi.spyOn(env.RATE_LIMITER, 'limit').mockResolvedValue({ success: true });

    const result = await checkAndIncrementQuota(env.DB, env.RATE_LIMITER, IP);

    expect(result).toEqual({ allowed: true, dailyCount: 0 });

    const org = await env.DB.prepare('SELECT query_count FROM search_quota_ledger WHERE day = ?')
      .bind(DAY)
      .first<{ query_count: number }>();
    expect(org?.query_count).toBe(1);

    const ip = await env.DB.prepare(
      'SELECT query_count FROM search_quota_ip_ledger WHERE bucket = ? AND client_ip = ?',
    )
      .bind(BUCKET, IP)
      .first<{ query_count: number }>();
    expect(ip?.query_count).toBe(1);
  });

  it('increments existing rows rather than overwriting them', async () => {
    vi.spyOn(env.RATE_LIMITER, 'limit').mockResolvedValue({ success: true });
    await env.DB.prepare('INSERT INTO search_quota_ledger (day, query_count) VALUES (?, ?)')
      .bind(DAY, 41)
      .run();
    await env.DB.prepare(
      'INSERT INTO search_quota_ip_ledger (bucket, client_ip, query_count) VALUES (?, ?, ?)',
    )
      .bind(BUCKET, IP, 7)
      .run();

    const result = await checkAndIncrementQuota(env.DB, env.RATE_LIMITER, IP);

    expect(result).toEqual({ allowed: true, dailyCount: 41 });
    const org = await env.DB.prepare('SELECT query_count FROM search_quota_ledger WHERE day = ?')
      .bind(DAY)
      .first<{ query_count: number }>();
    expect(org?.query_count).toBe(42);
    const ip = await env.DB.prepare(
      'SELECT query_count FROM search_quota_ip_ledger WHERE bucket = ? AND client_ip = ?',
    )
      .bind(BUCKET, IP)
      .first<{ query_count: number }>();
    expect(ip?.query_count).toBe(8);
  });
});
