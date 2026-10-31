import { applyD1Migrations, reset, SELF } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import type { WatchlistDetailResponse, WatchlistListResponse } from '@threat-lens/contracts';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

// Admin-gated watchlist mutations, through the real built worker (SELF.fetch).
// ADMIN_BEARER is bound to 'test-admin-token' in vitest.config.ts.

const AUTH = { Authorization: 'Bearer test-admin-token', 'Content-Type': 'application/json' };
const now = Date.now();

async function seedCveWithCpe(cveId: string, vendor: string, product: string): Promise<void> {
  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO cve (cve_id, published_at, last_modified_at, description, severity, source,
                        text_hash, state_hash, ingested_at)
       VALUES (?, ?, ?, 'desc', 'HIGH', 'NVD', 'h', 'h', ?)`,
    ).bind(cveId, now, now, now),
    env.DB.prepare(
      `INSERT INTO cpe (cve_id, cpe_uri, part, vendor, product)
       VALUES (?, ?, 'a', ?, ?)`,
    ).bind(cveId, `cpe:2.3:a:${vendor}:${product}:*:*:*:*:*:*:*:*`, vendor, product),
  ]);
}

async function createWatchlistViaApi(name: string): Promise<number> {
  const res = await SELF.fetch('http://localhost/api/watchlists', {
    method: 'POST',
    headers: AUTH,
    body: JSON.stringify({ name }),
  });
  expect(res.status).toBe(201);
  return ((await res.json()) as { watchlistId: number }).watchlistId;
}

describe('watchlist mutations API', { timeout: 30_000 }, () => {
  beforeEach(async () => {
    await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
  });
  afterEach(async () => {
    await reset();
  });

  describe('admin auth gate', () => {
    it('rejects a create without the bearer token (403 UNAUTHORIZED)', async () => {
      const res = await SELF.fetch('http://localhost/api/watchlists', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'nope' }),
      });
      expect(res.status).toBe(403);
      expect(((await res.json()) as { error: { code: string } }).error.code).toBe('UNAUTHORIZED');
    });

    it('rejects a create with a wrong token', async () => {
      const res = await SELF.fetch('http://localhost/api/watchlists', {
        method: 'POST',
        headers: { Authorization: 'Bearer wrong', 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'nope' }),
      });
      expect(res.status).toBe(403);
    });
  });

  describe('watchlist CRUD', () => {
    it('creates, renames, and deletes a watchlist', async () => {
      const id = await createWatchlistViaApi('Perimeter');

      // Rename
      const patch = await SELF.fetch(`http://localhost/api/watchlists/${id}`, {
        method: 'PATCH',
        headers: AUTH,
        body: JSON.stringify({ name: 'Perimeter v2', description: 'edge' }),
      });
      expect(patch.status).toBe(200);

      const list = (await (
        await SELF.fetch('http://localhost/api/watchlists')
      ).json()) as WatchlistListResponse;
      expect(list.watchlists[0]?.name).toBe('Perimeter v2');
      expect(list.watchlists[0]?.description).toBe('edge');

      // Delete
      const del = await SELF.fetch(`http://localhost/api/watchlists/${id}`, {
        method: 'DELETE',
        headers: AUTH,
      });
      expect(del.status).toBe(200);
      const after = (await (
        await SELF.fetch('http://localhost/api/watchlists')
      ).json()) as WatchlistListResponse;
      expect(after.watchlists).toHaveLength(0);
    });

    it('rejects an empty name (validation)', async () => {
      const res = await SELF.fetch('http://localhost/api/watchlists', {
        method: 'POST',
        headers: AUTH,
        body: JSON.stringify({ name: '   ' }),
      });
      expect(res.status).toBe(400);
    });

    it('PATCH/DELETE on a missing watchlist 404s', async () => {
      const patch = await SELF.fetch('http://localhost/api/watchlists/999', {
        method: 'PATCH',
        headers: AUTH,
        body: JSON.stringify({ name: 'x' }),
      });
      expect(patch.status).toBe(404);
    });
  });

  describe('subscriptions', () => {
    it('adds a subscription and backfills matching CVEs immediately', async () => {
      const id = await createWatchlistViaApi('Core');
      await seedCveWithCpe('CVE-2026-0001', 'acme', 'widget');
      await seedCveWithCpe('CVE-2026-0002', 'acme', 'gadget');
      await seedCveWithCpe('CVE-2026-0003', 'globex', 'router');

      // vendor-only subscription → both acme CVEs backfill, globex doesn't.
      const res = await SELF.fetch(`http://localhost/api/watchlists/${id}/subscriptions`, {
        method: 'POST',
        headers: AUTH,
        body: JSON.stringify({ vendor: 'acme' }),
      });
      expect(res.status).toBe(201);
      const body = (await res.json()) as { subscriptionId: number; backfilledMatches: number };
      expect(body.backfilledMatches).toBe(2);

      const detail = (await (
        await SELF.fetch(`http://localhost/api/watchlists/${id}`)
      ).json()) as WatchlistDetailResponse;
      expect(detail.matches.map((m) => m.cveId).sort()).toEqual(['CVE-2026-0001', 'CVE-2026-0002']);
      expect(detail.matchCounts.NEW).toBe(2);
    });

    it('lowercases vendor/product so it matches NVD-normalized cpe rows', async () => {
      const id = await createWatchlistViaApi('Case');
      await seedCveWithCpe('CVE-2026-1001', 'apache', 'http_server');

      const res = await SELF.fetch(`http://localhost/api/watchlists/${id}/subscriptions`, {
        method: 'POST',
        headers: AUTH,
        body: JSON.stringify({ vendor: 'APACHE', product: 'HTTP_Server' }),
      });
      const body = (await res.json()) as { backfilledMatches: number };
      expect(body.backfilledMatches).toBe(1);
    });

    it('removes a subscription (leaving already-matched CVEs in place)', async () => {
      const id = await createWatchlistViaApi('Removable');
      await seedCveWithCpe('CVE-2026-2001', 'acme', 'widget');
      const addRes = await SELF.fetch(`http://localhost/api/watchlists/${id}/subscriptions`, {
        method: 'POST',
        headers: AUTH,
        body: JSON.stringify({ vendor: 'acme' }),
      });
      const subId = ((await addRes.json()) as { subscriptionId: number }).subscriptionId;

      const del = await SELF.fetch(`http://localhost/api/watchlists/${id}/subscriptions/${subId}`, {
        method: 'DELETE',
        headers: AUTH,
      });
      expect(del.status).toBe(200);

      const detail = (await (
        await SELF.fetch(`http://localhost/api/watchlists/${id}`)
      ).json()) as WatchlistDetailResponse;
      expect(detail.subscriptions).toHaveLength(0);
      // The already-materialized match survives the subscription removal.
      expect(detail.matches).toHaveLength(1);
    });
  });

  describe('match triage', () => {
    it('changes a match status', async () => {
      const id = await createWatchlistViaApi('Triage');
      await seedCveWithCpe('CVE-2026-3001', 'acme', 'widget');
      await SELF.fetch(`http://localhost/api/watchlists/${id}/subscriptions`, {
        method: 'POST',
        headers: AUTH,
        body: JSON.stringify({ vendor: 'acme' }),
      });

      const res = await SELF.fetch(`http://localhost/api/watchlists/${id}/matches/CVE-2026-3001`, {
        method: 'PATCH',
        headers: AUTH,
        body: JSON.stringify({ status: 'RESOLVED', note: 'patched' }),
      });
      expect(res.status).toBe(200);

      const detail = (await (
        await SELF.fetch(`http://localhost/api/watchlists/${id}?status=RESOLVED`)
      ).json()) as WatchlistDetailResponse;
      expect(detail.matches).toHaveLength(1);
      expect(detail.matches[0]).toMatchObject({
        cveId: 'CVE-2026-3001',
        status: 'RESOLVED',
        note: 'patched',
      });
    });

    it('rejects an invalid status', async () => {
      const id = await createWatchlistViaApi('Bad');
      await seedCveWithCpe('CVE-2026-4001', 'acme', 'widget');
      await SELF.fetch(`http://localhost/api/watchlists/${id}/subscriptions`, {
        method: 'POST',
        headers: AUTH,
        body: JSON.stringify({ vendor: 'acme' }),
      });
      const res = await SELF.fetch(`http://localhost/api/watchlists/${id}/matches/CVE-2026-4001`, {
        method: 'PATCH',
        headers: AUTH,
        body: JSON.stringify({ status: 'BOGUS' }),
      });
      expect(res.status).toBe(400);
    });
  });

  describe('webhooks', () => {
    it('adds and removes a webhook, surfaced in the detail response', async () => {
      const id = await createWatchlistViaApi('Alerted');

      const add = await SELF.fetch(`http://localhost/api/watchlists/${id}/webhooks`, {
        method: 'POST',
        headers: AUTH,
        body: JSON.stringify({ url: 'https://hooks.example.com/abc', kind: 'slack' }),
      });
      expect(add.status).toBe(201);
      const webhookId = ((await add.json()) as { webhookId: number }).webhookId;

      let detail = (await (
        await SELF.fetch(`http://localhost/api/watchlists/${id}`)
      ).json()) as WatchlistDetailResponse;
      expect(detail.webhooks).toHaveLength(1);
      expect(detail.webhooks[0]).toMatchObject({ kind: 'slack', enabled: true });

      const del = await SELF.fetch(`http://localhost/api/watchlists/${id}/webhooks/${webhookId}`, {
        method: 'DELETE',
        headers: AUTH,
      });
      expect(del.status).toBe(200);
      detail = (await (
        await SELF.fetch(`http://localhost/api/watchlists/${id}`)
      ).json()) as WatchlistDetailResponse;
      expect(detail.webhooks).toHaveLength(0);
    });

    it('rejects a non-https webhook URL', async () => {
      const id = await createWatchlistViaApi('Insecure');
      const res = await SELF.fetch(`http://localhost/api/watchlists/${id}/webhooks`, {
        method: 'POST',
        headers: AUTH,
        body: JSON.stringify({ url: 'http://insecure.example.com/x' }),
      });
      expect(res.status).toBe(400);
    });
  });
});
