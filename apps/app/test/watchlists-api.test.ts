import { applyD1Migrations, reset, SELF } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import type { WatchlistDetailResponse, WatchlistListResponse } from '@threat-lens/contracts';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

// Read-side watchlist API, through the real built worker (workerd + real local
// D1) via SELF.fetch — same harness as ssr-caching.test.ts. Matches are
// normally materialized by the ingest worker's reconciliation engine; here we
// seed watchlist_match directly to isolate the read API under test.

const now = Date.now();

// The watchlist read surface is operator-only (what we monitor is a map of
// what we run), so every GET carries the admin bearer. ADMIN_BEARER =
// 'test-admin-token' (vitest.config.ts).
const AUTH = { Authorization: 'Bearer test-admin-token' };

async function seedCve(cveId: string, severity = 'HIGH', kev = false): Promise<void> {
  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO cve (cve_id, published_at, last_modified_at, description, severity, source,
                        text_hash, state_hash, ingested_at)
       VALUES (?, ?, ?, 'desc', ?, 'NVD', 'h', 'h', ?)`,
    ).bind(cveId, now, now, severity, now),
    env.DB.prepare(
      `INSERT INTO cve_state (cve_id, kev_listed, epss_percentile, state_updated_at)
       VALUES (?, ?, ?, ?)`,
    ).bind(cveId, kev ? 1 : 0, 0.9, now),
  ]);
}

async function seedWatchlist(id: number, name: string): Promise<void> {
  await env.DB.prepare(
    `INSERT INTO watchlist (watchlist_id, name, description, created_at, updated_at)
     VALUES (?, ?, 'test wl', ?, ?)`,
  )
    .bind(id, name, now, now)
    .run();
}

async function seedSubscription(
  wlId: number,
  vendor: string,
  product: string | null,
): Promise<void> {
  await env.DB.prepare(
    `INSERT INTO watchlist_subscription (watchlist_id, vendor, product, created_at)
     VALUES (?, ?, ?, ?)`,
  )
    .bind(wlId, vendor, product, now)
    .run();
}

async function seedMatch(
  wlId: number,
  cveId: string,
  status: string,
  statusUpdatedAt: number,
): Promise<void> {
  await env.DB.prepare(
    `INSERT INTO watchlist_match (watchlist_id, cve_id, status, first_matched_at, status_updated_at)
     VALUES (?, ?, ?, ?, ?)`,
  )
    .bind(wlId, cveId, status, now, statusUpdatedAt)
    .run();
}

describe('watchlists read API', { timeout: 30_000 }, () => {
  beforeEach(async () => {
    await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
  });
  afterEach(async () => {
    await reset();
  });

  it('rejects reads without the admin bearer', async () => {
    await seedWatchlist(1, 'Perimeter');
    expect((await SELF.fetch('http://localhost/api/watchlists')).status).toBe(403);
    expect((await SELF.fetch('http://localhost/api/watchlists/1')).status).toBe(403);

    const page = await SELF.fetch('http://localhost/watchlists');
    expect(page.status).toBe(200);
    expect(await page.text()).toContain('Operator sign-in required');

    // The detail page has no body to render alongside a prompt, so it 403s.
    const detailPage = await SELF.fetch('http://localhost/watchlists/1');
    expect(detailPage.status).toBe(403);
  });

  it('GET /api/watchlists returns summaries with subscription + per-status match counts', async () => {
    await seedWatchlist(1, 'Perimeter');
    await seedSubscription(1, 'acme', null);
    await seedSubscription(1, 'globex', 'router');
    await seedCve('CVE-2026-0001');
    await seedCve('CVE-2026-0002');
    await seedMatch(1, 'CVE-2026-0001', 'NEW', now);
    await seedMatch(1, 'CVE-2026-0002', 'RESOLVED', now);

    const res = await SELF.fetch('http://localhost/api/watchlists', { headers: AUTH });
    expect(res.status).toBe(200);
    const body = (await res.json()) as WatchlistListResponse;

    expect(body.watchlists).toHaveLength(1);
    const wl = body.watchlists[0]!;
    expect(wl.name).toBe('Perimeter');
    expect(wl.subscriptionCount).toBe(2);
    expect(wl.matchCounts.NEW).toBe(1);
    expect(wl.matchCounts.RESOLVED).toBe(1);
    expect(wl.matchCounts.TRIAGING).toBe(0);
  });

  it('GET /api/watchlists/[id] returns subscriptions + matches joined to CVE data', async () => {
    await seedWatchlist(7, 'Core');
    await seedSubscription(7, 'acme', 'widget');
    await seedCve('CVE-2026-1001', 'CRITICAL', true);
    await seedMatch(7, 'CVE-2026-1001', 'NEW', now);

    const res = await SELF.fetch('http://localhost/api/watchlists/7', { headers: AUTH });
    expect(res.status).toBe(200);
    const body = (await res.json()) as WatchlistDetailResponse;

    expect(body.name).toBe('Core');
    expect(body.subscriptions).toHaveLength(1);
    expect(body.subscriptions[0]).toMatchObject({ vendor: 'acme', product: 'widget' });
    expect(body.matches).toHaveLength(1);
    expect(body.matches[0]).toMatchObject({
      cveId: 'CVE-2026-1001',
      status: 'NEW',
      severity: 'CRITICAL',
      kevListed: true,
    });
  });

  it('GET /api/watchlists/[id]?status=NEW filters matches to that status only', async () => {
    await seedWatchlist(3, 'Filtered');
    await seedCve('CVE-2026-2001');
    await seedCve('CVE-2026-2002');
    await seedMatch(3, 'CVE-2026-2001', 'NEW', now);
    await seedMatch(3, 'CVE-2026-2002', 'IGNORED', now);

    const res = await SELF.fetch('http://localhost/api/watchlists/3?status=NEW', { headers: AUTH });
    const body = (await res.json()) as WatchlistDetailResponse;
    expect(body.matches.map((m) => m.cveId)).toEqual(['CVE-2026-2001']);
    // Counts reflect ALL statuses regardless of the filter.
    expect(body.matchCounts.NEW).toBe(1);
    expect(body.matchCounts.IGNORED).toBe(1);
  });

  it('GET /api/watchlists/[id] 404s for a non-existent watchlist', async () => {
    const res = await SELF.fetch('http://localhost/api/watchlists/999', { headers: AUTH });
    expect(res.status).toBe(404);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe('WATCHLIST_NOT_FOUND');
  });

  it('GET /api/watchlists/[id] 400s on an invalid id', async () => {
    const res = await SELF.fetch('http://localhost/api/watchlists/not-a-number', { headers: AUTH });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe('VALIDATION_ERROR');
  });

  it('a match whose CVE has aged out still renders, with null severity', async () => {
    await seedWatchlist(5, 'Aged');
    // Match exists but no cve row (hard-deleted / aged out).
    await seedMatch(5, 'CVE-2020-9999', 'ACKNOWLEDGED', now);

    const res = await SELF.fetch('http://localhost/api/watchlists/5', { headers: AUTH });
    const body = (await res.json()) as WatchlistDetailResponse;
    expect(body.matches).toHaveLength(1);
    expect(body.matches[0]).toMatchObject({
      cveId: 'CVE-2020-9999',
      status: 'ACKNOWLEDGED',
      severity: null,
      cvssBase: null,
      kevListed: false,
    });
  });
});
