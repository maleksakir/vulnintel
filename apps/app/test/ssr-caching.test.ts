import { applyD1Migrations, reset, SELF } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

// SSR read-path caching, exercised through the real built worker (workerd,
// real local D1 + KV) via SELF.fetch — same harness as dashboard-ssr.test.ts.
//
// These three page loaders (/cve/[id], /threat-intel, /affected-products)
// previously hit D1 directly on every SSR render with no KV cache — the same
// uncached-SSR read-amplification shape that twice exhausted the free-tier
// 5M/day D1 read quota (homepage 2026-10-29). Each now shares its API
// sibling's KV key so a page view and an API fetch reuse one cached entry.
//
// The test for "is it actually cached" is behavioral and deployment-faithful:
// prime the cache with one load, delete the underlying D1 row, then load
// again — a still-successful second load proves the second render was served
// from KV, not D1. (We never assert via spies here; SELF.fetch runs the real
// worker, so observable behavior is the only honest signal.)

const now = Date.now();

async function seedCve(cveId: string, opts: { kev?: boolean } = {}): Promise<void> {
  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO cve (cve_id, published_at, last_modified_at, description, severity,
                        source, text_hash, state_hash, ingested_at)
       VALUES (?, ?, ?, ?, 'HIGH', 'NVD', 'h', 'h', ?)`,
    ).bind(cveId, now, now, `Test record for ${cveId}`, now),
    env.DB.prepare(
      `INSERT INTO cpe (cve_id, cpe_uri, part, vendor, product)
       VALUES (?, ?, 'a', 'acme', 'widget')`,
    ).bind(cveId, `cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*`),
    env.DB.prepare(
      `INSERT INTO cve_state (cve_id, kev_listed, kev_date_added, kev_required_action, state_updated_at)
       VALUES (?, ?, ?, ?, ?)`,
    ).bind(cveId, opts.kev ? 1 : 0, opts.kev ? now : null, opts.kev ? 'Patch' : null, now),
  ]);
}

describe('SSR read-path caching', { timeout: 30_000 }, () => {
  beforeEach(async () => {
    await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
  });

  afterEach(async () => {
    await reset();
  });

  describe('GET /cve/[id]', () => {
    it('serves a second render from the shared cve:<id> KV key after the D1 row is gone', async () => {
      const cveId = 'CVE-2026-40001';
      await seedCve(cveId);

      const first = await SELF.fetch(`http://localhost/cve/${cveId}`);
      expect(first.status).toBe(200);
      expect(await first.text()).toContain(cveId);

      // The page loader shares `cve:<id>` with /api/cve/[id]; priming it here
      // means the row can vanish from D1 and the cached render still works.
      const cached = await env.CACHE.get(`cve:${cveId}`, 'json');
      expect(cached).not.toBeNull();

      await env.DB.prepare('DELETE FROM cve WHERE cve_id = ?').bind(cveId).run();

      const second = await SELF.fetch(`http://localhost/cve/${cveId}`);
      expect(second.status).toBe(200); // served from KV, not D1
      expect(await second.text()).toContain(cveId);
    });

    it('does NOT cache a 404 — a miss for a not-yet-ingested CVE must stay uncached', async () => {
      const cveId = 'CVE-2026-49999';
      const res = await SELF.fetch(`http://localhost/cve/${cveId}`);
      expect(res.status).toBe(404);

      // Nothing written to KV: a cached null would otherwise linger up to the
      // full TTL after the CVE later lands (ingest skips invalidation on a
      // brand-new CVE), which is exactly the bug the hand-rolled read avoids.
      const cached = await env.CACHE.get(`cve:${cveId}`, 'json');
      expect(cached).toBeNull();
    });
  });

  describe('GET /affected-products', () => {
    it('caches the unfiltered default view under one stable key, and serves it from KV after D1 is emptied', async () => {
      await seedCve('CVE-2026-41001');
      await seedCve('CVE-2026-41002');

      const first = await SELF.fetch('http://localhost/affected-products');
      expect(first.status).toBe(200);
      expect(await first.text()).toContain('acme');

      const cached = await env.CACHE.get('affected:products:default', 'json');
      expect(cached).not.toBeNull();

      // Wipe the source rows; the default view must still render from KV.
      await env.DB.prepare('DELETE FROM cpe').run();
      await env.DB.prepare('DELETE FROM cve').run();

      const second = await SELF.fetch('http://localhost/affected-products');
      expect(second.status).toBe(200);
      expect(await second.text()).toContain('acme'); // from cache
    });

    it('does NOT cache a filtered (vendor) view — avoids per-param KV key sprawl', async () => {
      await seedCve('CVE-2026-41010');

      const res = await SELF.fetch('http://localhost/affected-products?vendor=acme');
      expect(res.status).toBe(200);

      // A filtered query must never populate the default-view key, and must
      // not mint its own key either (the KV-write-storm shape we're avoiding).
      const defaultKey = await env.CACHE.get('affected:products:default', 'json');
      expect(defaultKey).toBeNull();
      const list = await env.CACHE.list({ prefix: 'affected:products' });
      expect(list.keys).toHaveLength(0);
    });
  });

  describe('GET /threat-intel', () => {
    it('caches the first KEV page under the shared threat:kev:list key', async () => {
      await seedCve('CVE-2026-42001', { kev: true });

      const res = await SELF.fetch('http://localhost/threat-intel?tab=kev');
      expect(res.status).toBe(200);

      const cached = await env.CACHE.get('threat:kev:list', 'json');
      expect(cached).not.toBeNull();
    });

    it('does NOT cache a cursor (paginated) KEV load', async () => {
      await seedCve('CVE-2026-42002', { kev: true });

      // A bogus-but-well-formed cursor still routes down the uncached path.
      const cursor = btoa(String(now + 1));
      const res = await SELF.fetch(`http://localhost/threat-intel?tab=kev&cursor=${cursor}`);
      expect(res.status).toBe(200);

      // The cursor path must not have populated the first-page key.
      const cached = await env.CACHE.get('threat:kev:list', 'json');
      expect(cached).toBeNull();
    });
  });
});
