import { afterEach, describe, expect, it, vi } from 'vitest';
import { dispatchWatchlistNotifications } from '../src/lib/server/watchlistNotify';
import { testEnv, useCleanBindings } from './helpers';

// Watchlist notifier (lib/server/watchlistNotify.ts). Stubs global fetch (the
// webhook POST) — same approach as the OSV/producer tests — against real
// local D1 for the match/webhook state.

const now = Date.now();

async function seedWatchlistWithWebhook(id: number, url: string): Promise<void> {
  await testEnv.DB.batch([
    testEnv.DB.prepare(
      `INSERT INTO watchlist (watchlist_id, name, created_at, updated_at) VALUES (?, 'w', ?, ?)`,
    ).bind(id, now, now),
    testEnv.DB.prepare(
      `INSERT INTO watchlist_webhook (watchlist_id, kind, url, enabled, created_at)
       VALUES (?, 'generic', ?, 1, ?)`,
    ).bind(id, url, now),
  ]);
}

async function seedMatch(wlId: number, cveId: string, status = 'NEW'): Promise<void> {
  // A cve row so the digest join has data; and the match itself.
  await testEnv.DB.batch([
    testEnv.DB.prepare(
      `INSERT OR IGNORE INTO cve (cve_id, published_at, last_modified_at, description, severity,
                        source, text_hash, state_hash, ingested_at)
       VALUES (?, ?, ?, 'd', 'HIGH', 'NVD', 'h', 'h', ?)`,
    ).bind(cveId, now, now, now),
    testEnv.DB.prepare(
      `INSERT INTO watchlist_match (watchlist_id, cve_id, status, first_matched_at, status_updated_at)
       VALUES (?, ?, ?, ?, ?)`,
    ).bind(wlId, cveId, status, now, now),
  ]);
}

async function notifiedAt(wlId: number, cveId: string): Promise<number | null> {
  const row = await testEnv.DB.prepare(
    `SELECT notified_at FROM watchlist_match WHERE watchlist_id = ? AND cve_id = ?`,
  )
    .bind(wlId, cveId)
    .first<{ notified_at: number | null }>();
  return row?.notified_at ?? null;
}

describe('dispatchWatchlistNotifications', () => {
  useCleanBindings();

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('POSTs a digest for new matches and stamps notified_at', async () => {
    await seedWatchlistWithWebhook(1, 'https://hooks.example.com/a');
    await seedMatch(1, 'CVE-2026-0001');
    await seedMatch(1, 'CVE-2026-0002');

    const fetchSpy = vi.fn(async () => new Response('ok', { status: 200 }));
    vi.stubGlobal('fetch', fetchSpy);

    const result = await dispatchWatchlistNotifications(testEnv);

    expect(result.webhooksDispatched).toBe(1);
    expect(result.matchesNotified).toBe(2);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://hooks.example.com/a');
    const payload = JSON.parse(init.body as string) as { matches: { cveId: string }[] };
    expect(payload.matches.map((m) => m.cveId).sort()).toEqual(['CVE-2026-0001', 'CVE-2026-0002']);

    expect(await notifiedAt(1, 'CVE-2026-0001')).not.toBeNull();
    expect(await notifiedAt(1, 'CVE-2026-0002')).not.toBeNull();
  });

  it('is idempotent: an already-notified match is not re-sent', async () => {
    await seedWatchlistWithWebhook(2, 'https://hooks.example.com/b');
    await seedMatch(2, 'CVE-2026-1001');

    const fetchSpy = vi.fn(async () => new Response('ok', { status: 200 }));
    vi.stubGlobal('fetch', fetchSpy);

    await dispatchWatchlistNotifications(testEnv);
    expect(fetchSpy).toHaveBeenCalledTimes(1);

    // Second run: nothing new → no POST.
    await dispatchWatchlistNotifications(testEnv);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it('a failed POST leaves notified_at NULL so the next run retries', async () => {
    await seedWatchlistWithWebhook(3, 'https://hooks.example.com/c');
    await seedMatch(3, 'CVE-2026-2001');

    const failing = vi.fn(async () => new Response('boom', { status: 500 }));
    vi.stubGlobal('fetch', failing);
    const first = await dispatchWatchlistNotifications(testEnv);
    expect(first.matchesNotified).toBe(0);
    expect(await notifiedAt(3, 'CVE-2026-2001')).toBeNull();

    // Webhook recovers → retried and stamped.
    const ok = vi.fn(async () => new Response('ok', { status: 200 }));
    vi.stubGlobal('fetch', ok);
    const second = await dispatchWatchlistNotifications(testEnv);
    expect(second.matchesNotified).toBe(1);
    expect(await notifiedAt(3, 'CVE-2026-2001')).not.toBeNull();
  });

  it('only notifies still-NEW matches — a triaged match is excluded', async () => {
    await seedWatchlistWithWebhook(4, 'https://hooks.example.com/d');
    await seedMatch(4, 'CVE-2026-3001', 'RESOLVED');

    const fetchSpy = vi.fn(async () => new Response('ok', { status: 200 }));
    vi.stubGlobal('fetch', fetchSpy);
    const result = await dispatchWatchlistNotifications(testEnv);
    expect(result.matchesNotified).toBe(0);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('a disabled webhook is skipped', async () => {
    await testEnv.DB.prepare(
      `INSERT INTO watchlist (watchlist_id, name, created_at, updated_at) VALUES (5, 'w', ?, ?)`,
    )
      .bind(now, now)
      .run();
    await testEnv.DB.prepare(
      `INSERT INTO watchlist_webhook (watchlist_id, kind, url, enabled, created_at)
       VALUES (5, 'generic', 'https://hooks.example.com/e', 0, ?)`,
    )
      .bind(now)
      .run();
    await seedMatch(5, 'CVE-2026-4001');

    const fetchSpy = vi.fn(async () => new Response('ok', { status: 200 }));
    vi.stubGlobal('fetch', fetchSpy);
    const result = await dispatchWatchlistNotifications(testEnv);
    expect(result.webhooksDispatched).toBe(0);
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
