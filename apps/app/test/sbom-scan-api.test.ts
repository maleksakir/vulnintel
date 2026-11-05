import { applyD1Migrations, reset, SELF } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import type { SbomScanResponse } from '@threat-lens/contracts';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

// End-to-end SBOM scan API (POST /api/sbom/scan), through the real built
// worker (workerd + real local D1) via SELF.fetch. Public (no auth); seeds a
// CVE + an OSV affected package, then uploads a CycloneDX SBOM referencing
// that package and asserts the match + enrichment.

const now = Date.now();

async function seedCve(cveId: string, severity = 'CRITICAL', kev = false): Promise<void> {
  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO cve (cve_id, published_at, last_modified_at, description, severity, source,
                        cvss_base, text_hash, state_hash, ingested_at)
       VALUES (?, ?, ?, 'desc', ?, 'NVD', 9.8, 'h', 'h', ?)`,
    ).bind(cveId, now, now, severity, now),
    env.DB.prepare(
      `INSERT INTO cve_state (cve_id, kev_listed, epss_percentile, state_updated_at)
       VALUES (?, ?, ?, ?)`,
    ).bind(cveId, kev ? 1 : 0, 0.97, now),
  ]);
}

async function seedOsvAffected(cveId: string, ecosystem: string, pkg: string): Promise<void> {
  await env.DB.prepare(
    `INSERT INTO cve_osv_affected (cve_id, osv_id, ecosystem, package_name, purl, ranges_json, fixed_versions)
     VALUES (?, ?, ?, ?, NULL, '[]', '2.0.0')`,
  )
    .bind(cveId, `GHSA-${cveId}`, ecosystem, pkg)
    .run();
}

function cyclonedx(
  components: Array<{ name: string; version?: string; purl?: string; cpe?: string }>,
) {
  return JSON.stringify({
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    components: components.map((c) => ({ type: 'library', ...c })),
  });
}

describe('POST /api/sbom/scan', { timeout: 30_000 }, () => {
  beforeEach(async () => {
    await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
  });
  afterEach(async () => {
    await reset();
  });

  it('matches a component by PURL against OSV and enriches the CVE', async () => {
    await seedCve('CVE-2026-70001', 'CRITICAL', true);
    await seedOsvAffected('CVE-2026-70001', 'npm', 'left-pad');

    const res = await SELF.fetch('http://localhost/api/sbom/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: cyclonedx([
        { name: 'left-pad', version: '1.0.0', purl: 'pkg:npm/left-pad@1.0.0' },
        { name: 'safe-dep', version: '3.0.0', purl: 'pkg:npm/safe-dep@3.0.0' },
      ]),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as SbomScanResponse;

    expect(body.componentsScanned).toBe(2);
    expect(body.vulnerableComponents).toBe(1);
    expect(body.totalCves).toBe(1);

    // Vulnerable component sorts first.
    const vuln = body.components[0];
    expect(vuln?.name).toBe('left-pad');
    expect(vuln?.cves).toHaveLength(1);
    expect(vuln?.cves[0]?.cveId).toBe('CVE-2026-70001');
    expect(vuln?.cves[0]?.matchVia).toBe('PURL');
    expect(vuln?.cves[0]?.severity).toBe('CRITICAL');
    expect(vuln?.cves[0]?.cvssBase).toBe(9.8);
    expect(vuln?.cves[0]?.kevListed).toBe(true);
    expect(vuln?.hasKev).toBe(true);
    expect(vuln?.maxSeverity).toBe('CRITICAL');

    // Clean component carries no CVEs.
    const clean = body.components.find((c) => c.name === 'safe-dep');
    expect(clean?.cves).toHaveLength(0);
  });

  it('excludes a component already on a fixed version', async () => {
    await seedCve('CVE-2026-70002');
    await seedOsvAffected('CVE-2026-70002', 'npm', 'patched-lib'); // fixed_versions = '2.0.0'

    const res = await SELF.fetch('http://localhost/api/sbom/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      // On the fixed version 2.0.0 → not affected.
      body: cyclonedx([
        { name: 'patched-lib', version: '2.0.0', purl: 'pkg:npm/patched-lib@2.0.0' },
      ]),
    });
    const body = (await res.json()) as SbomScanResponse;
    expect(body.vulnerableComponents).toBe(0);
  });

  it('rejects a non-CycloneDX body with 400', async () => {
    const res = await SELF.fetch('http://localhost/api/sbom/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ not: 'a bom' }),
    });
    expect(res.status).toBe(400);
  });

  it('rejects invalid JSON with 400', async () => {
    const res = await SELF.fetch('http://localhost/api/sbom/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{ not json',
    });
    expect(res.status).toBe(400);
  });
});
