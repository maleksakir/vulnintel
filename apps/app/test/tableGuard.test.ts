import { applyD1Migrations, reset, SELF } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

// The watchlists / assets / remediation feature tables are created by
// migrations 0009-0012. On 2026-11-02 those could not be applied to
// production for a full UTC day (D1 daily WRITE cap exhausted) while the
// Worker was already deployed, and all three feature pages 500'd because they
// SELECT from tables that did not exist. These pin the degrade-to-empty
// behaviour (lib/server/tableGuard.ts) so a deploy-ahead-of-migration can't
// 500 a live page again.

const AUTH = { Authorization: 'Bearer test-admin-token' };

async function dropFeatureTables(): Promise<void> {
  await env.DB.batch([
    env.DB.prepare('DROP TABLE IF EXISTS watchlist_match'),
    env.DB.prepare('DROP TABLE IF EXISTS watchlist_subscription'),
    env.DB.prepare('DROP TABLE IF EXISTS watchlist_webhook'),
    env.DB.prepare('DROP TABLE IF EXISTS watchlist'),
    env.DB.prepare('DROP TABLE IF EXISTS asset_component_match'),
    env.DB.prepare('DROP TABLE IF EXISTS asset_component'),
    env.DB.prepare('DROP TABLE IF EXISTS asset'),
    env.DB.prepare('DROP TABLE IF EXISTS cve_risk_acceptance'),
  ]);
}

describe('feature pages when the migration has not been applied', { timeout: 30_000 }, () => {
  beforeEach(async () => {
    await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
    await dropFeatureTables();
  });
  afterEach(async () => {
    await reset();
  });

  it('GET /api/watchlists returns an empty list, not a 500', async () => {
    const res = await SELF.fetch('http://localhost/api/watchlists', { headers: AUTH });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ watchlists: [] });
  });

  it('GET /api/assets returns an empty list, not a 500', async () => {
    const res = await SELF.fetch('http://localhost/api/assets', { headers: AUTH });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ assets: [] });
  });

  it('GET /api/remediation returns an empty list, not a 500', async () => {
    const res = await SELF.fetch('http://localhost/api/remediation', { headers: AUTH });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ acceptances: [] });
  });

  it('the /watchlists page renders the finishing-setup notice instead of 500ing', async () => {
    const res = await SELF.fetch('http://localhost/watchlists?token=test-admin-token', {
      redirect: 'manual',
    });
    // First hit redirects to set the session cookie; follow it with the cookie.
    const cookie = res.headers.get('set-cookie')?.split(';')[0] ?? '';
    const page = await SELF.fetch('http://localhost/watchlists', { headers: { cookie } });
    expect(page.status).toBe(200);
    expect(await page.text()).toContain('finishing setup');
  });

  it('a mutation against a missing table still fails loudly (not swallowed)', async () => {
    // readOrEmpty is reads-only by design; a create must not silently succeed
    // against a table that doesn't exist.
    const res = await SELF.fetch('http://localhost/api/watchlists', {
      method: 'POST',
      headers: { ...AUTH, 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'should fail' }),
    });
    expect(res.status).toBeGreaterThanOrEqual(500);
  });
});
