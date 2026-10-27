import { applyD1Migrations, reset } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { checkAndIncrementQuota } from '../src/lib/server/quota';

// `RATE_LIMITER` is mocked for determinism (the real Workers-native limiter
// is a 500/60s token bucket — exhausting it for real would be slow and
// flaky in CI). D1 (`search_quota_ledger`) runs for real against workerd.

const DAY = '2026-10-27';

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

    const result = await checkAndIncrementQuota(env.DB, env.RATE_LIMITER, '203.0.113.5');

    expect(result).toEqual({ allowed: false, reason: 'RATE_LIMITED' });
    expect(dbPrepare).not.toHaveBeenCalled();
  });

  it('enforces the org-wide daily quota once exhausted, without writing an increment', async () => {
    vi.spyOn(env.RATE_LIMITER, 'limit').mockResolvedValue({ success: true });
    await env.DB.prepare('INSERT INTO search_quota_ledger (day, query_count) VALUES (?, ?)')
      .bind(DAY, 50_000)
      .run();

    const dbPrepare = vi.spyOn(env.DB, 'prepare');
    const result = await checkAndIncrementQuota(env.DB, env.RATE_LIMITER, '203.0.113.6');

    expect(result).toEqual({ allowed: false, reason: 'GLOBAL_QUOTA_EXHAUSTED' });
    // Only the read happened — no attempt to increment past the cap.
    expect(dbPrepare).toHaveBeenCalledTimes(1);
    expect(dbPrepare.mock.calls[0]?.[0]).toMatch(/^\s*SELECT/i);

    const row = await env.DB.prepare('SELECT query_count FROM search_quota_ledger WHERE day = ?')
      .bind(DAY)
      .first<{ query_count: number }>();
    expect(row?.query_count).toBe(50_000); // unchanged
  });

  it('allows the request and writes the increment to D1 when under quota', async () => {
    vi.spyOn(env.RATE_LIMITER, 'limit').mockResolvedValue({ success: true });

    const dbPrepare = vi.spyOn(env.DB, 'prepare');
    const result = await checkAndIncrementQuota(env.DB, env.RATE_LIMITER, '203.0.113.7');

    expect(result).toEqual({ allowed: true });
    const writeSql = dbPrepare.mock.calls.map(([sql]) => sql).filter((sql) => /^\s*INSERT/i.test(sql));
    expect(writeSql).toHaveLength(1);
    expect(writeSql[0]).toMatch(/INSERT INTO search_quota_ledger/i);

    const row = await env.DB.prepare('SELECT query_count FROM search_quota_ledger WHERE day = ?')
      .bind(DAY)
      .first<{ query_count: number }>();
    expect(row?.query_count).toBe(1);
  });

  it('increments an existing day row rather than overwriting it', async () => {
    vi.spyOn(env.RATE_LIMITER, 'limit').mockResolvedValue({ success: true });
    await env.DB.prepare('INSERT INTO search_quota_ledger (day, query_count) VALUES (?, ?)')
      .bind(DAY, 41)
      .run();

    const result = await checkAndIncrementQuota(env.DB, env.RATE_LIMITER, '203.0.113.8');

    expect(result).toEqual({ allowed: true });
    const row = await env.DB.prepare('SELECT query_count FROM search_quota_ledger WHERE day = ?')
      .bind(DAY)
      .first<{ query_count: number }>();
    expect(row?.query_count).toBe(42);
  });
});
