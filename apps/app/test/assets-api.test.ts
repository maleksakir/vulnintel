import { applyD1Migrations, reset, SELF } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import type {
  AssetDetailResponse,
  AssetListResponse,
  SbomImportResult,
} from '@threat-lens/contracts';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

// Asset inventory + SBOM import/match, through the real built worker
// (SELF.fetch). ADMIN_BEARER = 'test-admin-token' (vitest.config.ts).

const AUTH = { Authorization: 'Bearer test-admin-token', 'Content-Type': 'application/json' };
const now = Date.now();

async function seedCve(cveId: string, severity = 'HIGH', kev = false): Promise<void> {
  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO cve (cve_id, published_at, last_modified_at, description, severity, cvss_base,
                        source, text_hash, state_hash, ingested_at)
       VALUES (?, ?, ?, 'desc', ?, 7.5, 'NVD', 'h', 'h', ?)`,
    ).bind(cveId, now, now, severity, now),
    env.DB.prepare(
      `INSERT INTO cve_state (cve_id, kev_listed, state_updated_at) VALUES (?, ?, ?)`,
    ).bind(cveId, kev ? 1 : 0, now),
  ]);
}

async function seedOsvAffected(
  cveId: string,
  ecosystem: string,
  pkg: string,
  purl: string,
): Promise<void> {
  await env.DB.prepare(
    `INSERT INTO cve_osv_affected (cve_id, osv_id, ecosystem, package_name, purl, ranges_json)
     VALUES (?, ?, ?, ?, ?, '[]')`,
  )
    .bind(cveId, `GHSA-${cveId}`, ecosystem, pkg, purl)
    .run();
}

async function seedCpe(cveId: string, vendor: string, product: string): Promise<void> {
  await env.DB.prepare(
    `INSERT INTO cpe (cve_id, cpe_uri, part, vendor, product)
     VALUES (?, ?, 'a', ?, ?)`,
  )
    .bind(cveId, `cpe:2.3:a:${vendor}:${product}:*:*:*:*:*:*:*:*`, vendor, product)
    .run();
}

async function createAsset(name: string): Promise<number> {
  const res = await SELF.fetch('http://localhost/api/assets', {
    method: 'POST',
    headers: AUTH,
    body: JSON.stringify({ name }),
  });
  expect(res.status).toBe(201);
  return ((await res.json()) as { assetId: number }).assetId;
}

describe('assets + SBOM import', { timeout: 30_000 }, () => {
  beforeEach(async () => {
    await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
  });
  afterEach(async () => {
    await reset();
  });

  it('rejects asset creation without the admin token', async () => {
    const res = await SELF.fetch('http://localhost/api/assets', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'x' }),
    });
    expect(res.status).toBe(403);
  });

  it('rejects READS without the admin token — the inventory is not public', async () => {
    // Asset names and SBOM contents describe our own systems; shipping them
    // read-open on a public origin is a target map (security review
    // 2026-10-31, finding #2).
    const assetId = await createAsset('private');

    const list = await SELF.fetch('http://localhost/api/assets');
    expect(list.status).toBe(403);

    const detail = await SELF.fetch(`http://localhost/api/assets/${assetId}`);
    expect(detail.status).toBe(403);

    // A wrong token is rejected the same way as none at all.
    const wrong = await SELF.fetch('http://localhost/api/assets', {
      headers: { Authorization: 'Bearer not-the-token' },
    });
    expect(wrong.status).toBe(403);
  });

  it('gates the SSR pages too, without touching D1', async () => {
    const page = await SELF.fetch('http://localhost/assets');
    expect(page.status).toBe(200); // renders the sign-in prompt, not the data
    const html = await page.text();
    expect(html).toContain('Operator sign-in required');
    expect(html).not.toContain('Asset Inventory');

    // Signing in with ?token= sets the session cookie and redirects without it.
    const signIn = await SELF.fetch('http://localhost/assets?token=test-admin-token', {
      redirect: 'manual',
    });
    expect(signIn.status).toBe(303);
    expect(signIn.headers.get('location')).toBe('/assets');
    const cookie = signIn.headers.get('set-cookie') ?? '';
    expect(cookie).toContain('admin_session=');
    expect(cookie).toContain('HttpOnly');
    expect(cookie).toContain('Path=/');

    // A bad token redirects identically but sets no session.
    const bad = await SELF.fetch('http://localhost/assets?token=wrong', { redirect: 'manual' });
    expect(bad.status).toBe(303);
    expect(bad.headers.get('set-cookie')).toBeNull();
  });

  it('imports a CycloneDX SBOM and matches components PURL-first', async () => {
    // A CVE linked to log4j-core via OSV (PURL path). Seeded EXACTLY as the
    // ingest pipeline writes it (apps/ingest/src/pipelines/osvPatch.ts stores
    // `pkg.ecosystem` raw, so Maven is capitalized, and OSV's Maven package
    // names are `groupId:artifactId`). Matching against a lowercased
    // 'maven' / bare 'log4j-core' fixture passed while being unable to match
    // one real ingested row.
    await seedCve('CVE-2021-44228', 'CRITICAL', true);
    await seedOsvAffected(
      'CVE-2021-44228',
      'Maven',
      'org.apache.logging.log4j:log4j-core',
      'pkg:maven/org.apache.logging.log4j/log4j-core',
    );

    const assetId = await createAsset('billing-api');
    const sbom = {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      components: [
        {
          type: 'library',
          name: 'log4j-core',
          version: '2.14.1',
          purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
        },
        { type: 'library', name: 'safe-lib', version: '1.0', purl: 'pkg:npm/safe-lib@1.0' },
      ],
    };
    const imp = await SELF.fetch(`http://localhost/api/assets/${assetId}/import`, {
      method: 'POST',
      headers: AUTH,
      body: JSON.stringify(sbom),
    });
    expect(imp.status).toBe(200);
    const result = (await imp.json()) as SbomImportResult;
    expect(result.componentsImported).toBe(2);
    expect(result.matchesFound).toBe(1);

    const detail = (await (
      await SELF.fetch(`http://localhost/api/assets/${assetId}`, { headers: AUTH })
    ).json()) as AssetDetailResponse;
    expect(detail.componentCount).toBe(2);
    expect(detail.cves).toHaveLength(1);
    expect(detail.cves[0]).toMatchObject({
      cveId: 'CVE-2021-44228',
      matchVia: 'PURL',
      severity: 'CRITICAL',
      kevListed: true,
    });
    // The matched component is flagged; the safe one isn't.
    const log4j = detail.components.find((c) => c.name === 'log4j-core');
    const safe = detail.components.find((c) => c.name === 'safe-lib');
    expect(log4j?.cveCount).toBe(1);
    expect(safe?.cveCount).toBe(0);
  });

  it('falls back to CPE vendor/product from an explicit cpe field', async () => {
    // CVE only reachable via cpe (no OSV row). CPE identity comes from the
    // component's own `cpe` field — never guessed from the purl namespace,
    // which is a groupId/scope and never equals an NVD CPE vendor.
    await seedCve('CVE-2026-5555', 'HIGH');
    await seedCpe('CVE-2026-5555', 'acme', 'widget');

    const assetId = await createAsset('cpe-fallback');
    const sbom = {
      bomFormat: 'CycloneDX',
      components: [
        {
          type: 'library',
          name: 'widget',
          version: '1.0',
          purl: 'pkg:generic/acme/widget@1.0',
          cpe: 'cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*',
        },
      ],
    };
    await SELF.fetch(`http://localhost/api/assets/${assetId}/import`, {
      method: 'POST',
      headers: AUTH,
      body: JSON.stringify(sbom),
    });

    const detail = (await (
      await SELF.fetch(`http://localhost/api/assets/${assetId}`, { headers: AUTH })
    ).json()) as AssetDetailResponse;
    expect(detail.cves).toHaveLength(1);
    expect(detail.cves[0]).toMatchObject({ cveId: 'CVE-2026-5555', matchVia: 'CPE' });
  });

  it('re-importing replaces the component set (idempotent)', async () => {
    const assetId = await createAsset('reimport');
    const sbom1 = {
      bomFormat: 'CycloneDX',
      components: [
        { name: 'a', version: '1', purl: 'pkg:npm/a@1' },
        { name: 'b', version: '1', purl: 'pkg:npm/b@1' },
      ],
    };
    await SELF.fetch(`http://localhost/api/assets/${assetId}/import`, {
      method: 'POST',
      headers: AUTH,
      body: JSON.stringify(sbom1),
    });
    // Second import has only one component.
    const sbom2 = {
      bomFormat: 'CycloneDX',
      components: [{ name: 'a', version: '2', purl: 'pkg:npm/a@2' }],
    };
    const imp = await SELF.fetch(`http://localhost/api/assets/${assetId}/import`, {
      method: 'POST',
      headers: AUTH,
      body: JSON.stringify(sbom2),
    });
    const result = (await imp.json()) as SbomImportResult;
    expect(result.componentsImported).toBe(1);

    const detail = (await (
      await SELF.fetch(`http://localhost/api/assets/${assetId}`, { headers: AUTH })
    ).json()) as AssetDetailResponse;
    expect(detail.componentCount).toBe(1);
    expect(detail.components.map((c) => c.name)).toEqual(['a']);
  });

  it('lists assets with vulnerability counts and 404s a missing asset', async () => {
    await seedCve('CVE-2026-0001');
    await seedOsvAffected('CVE-2026-0001', 'npm', 'left-pad', 'pkg:npm/left-pad@1.0.0');
    const assetId = await createAsset('counted');
    await SELF.fetch(`http://localhost/api/assets/${assetId}/import`, {
      method: 'POST',
      headers: AUTH,
      body: JSON.stringify({
        bomFormat: 'CycloneDX',
        components: [{ name: 'left-pad', version: '1.0.0', purl: 'pkg:npm/left-pad@1.0.0' }],
      }),
    });

    const list = (await (
      await SELF.fetch('http://localhost/api/assets', { headers: AUTH })
    ).json()) as AssetListResponse;
    expect(list.assets[0]).toMatchObject({
      name: 'counted',
      vulnerableCveCount: 1,
      vulnerableComponentCount: 1,
    });

    const missing = await SELF.fetch('http://localhost/api/assets/999', { headers: AUTH });
    expect(missing.status).toBe(404);
    expect(((await missing.json()) as { error: { code: string } }).error.code).toBe(
      'ASSET_NOT_FOUND',
    );
  });

  it('does not match a component already on a version OSV lists as fixed', async () => {
    await seedCve('CVE-2026-6001', 'HIGH');
    await env.DB.prepare(
      `INSERT INTO cve_osv_affected
         (cve_id, osv_id, ecosystem, package_name, purl, ranges_json, fixed_versions)
       VALUES ('CVE-2026-6001', 'GHSA-fixed', 'npm', 'patched-lib', 'pkg:npm/patched-lib', '[]', '2.0.1,3.0.0')`,
    ).run();

    const assetId = await createAsset('already-patched');
    await SELF.fetch(`http://localhost/api/assets/${assetId}/import`, {
      method: 'POST',
      headers: AUTH,
      body: JSON.stringify({
        bomFormat: 'CycloneDX',
        components: [
          { name: 'patched-lib', version: '2.0.1', purl: 'pkg:npm/patched-lib@2.0.1' },
          { name: 'patched-lib', version: '1.9.0', purl: 'pkg:npm/patched-lib@1.9.0' },
        ],
      }),
    });

    const detail = (await (
      await SELF.fetch(`http://localhost/api/assets/${assetId}`, { headers: AUTH })
    ).json()) as AssetDetailResponse;
    // Only the 1.9.0 component is reported; 2.0.1 is a listed fixed version.
    expect(detail.cves).toHaveLength(1);
    expect(detail.cves[0]).toMatchObject({ cveId: 'CVE-2026-6001', componentVersion: '1.9.0' });
  });

  it('reports a component CRITICAL when it has both CRITICAL and NONE CVEs', async () => {
    // MAX(c.severity) sorted alphabetically, so 'NONE' beat 'CRITICAL'.
    await seedCve('CVE-2026-7001', 'CRITICAL');
    await seedCve('CVE-2026-7002', 'NONE');
    await seedOsvAffected('CVE-2026-7001', 'npm', 'mixed-sev', 'pkg:npm/mixed-sev');
    await seedOsvAffected('CVE-2026-7002', 'npm', 'mixed-sev', 'pkg:npm/mixed-sev');

    const assetId = await createAsset('severity-rank');
    await SELF.fetch(`http://localhost/api/assets/${assetId}/import`, {
      method: 'POST',
      headers: AUTH,
      body: JSON.stringify({
        bomFormat: 'CycloneDX',
        components: [{ name: 'mixed-sev', version: '1.0.0', purl: 'pkg:npm/mixed-sev@1.0.0' }],
      }),
    });

    const detail = (await (
      await SELF.fetch(`http://localhost/api/assets/${assetId}`, { headers: AUTH })
    ).json()) as AssetDetailResponse;
    expect(detail.components[0]?.maxSeverity).toBe('CRITICAL');
  });

  it('falls back to the first page on a corrupt cursor instead of 500ing', async () => {
    const assetId = await createAsset('bad-cursor');
    const res = await SELF.fetch(`http://localhost/api/assets/${assetId}?cursor=%%%not-base64`, {
      headers: AUTH,
    });
    expect(res.status).toBe(200);
  });

  it('rejects a non-CycloneDX SBOM', async () => {
    const assetId = await createAsset('bad-sbom');
    const res = await SELF.fetch(`http://localhost/api/assets/${assetId}/import`, {
      method: 'POST',
      headers: AUTH,
      body: JSON.stringify({ bomFormat: 'SPDX', components: [] }),
    });
    expect(res.status).toBe(400);
  });
});
