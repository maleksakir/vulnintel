import { applyD1Migrations, reset, SELF } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import type { RiskAcceptanceListResponse } from '@threat-lens/contracts';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

// Risk-acceptance (remediation) API via SELF.fetch. ADMIN_BEARER =
// 'test-admin-token' (vitest.config.ts).

const AUTH = { Authorization: 'Bearer test-admin-token', 'Content-Type': 'application/json' };

function future(daysFromNow: number): string {
  return new Date(Date.now() + daysFromNow * 86_400_000).toISOString();
}

describe('remediation / risk acceptance API', { timeout: 30_000 }, () => {
  beforeEach(async () => {
    await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
  });
  afterEach(async () => {
    await reset();
  });

  it('accepts a CVE with a future expiry and lists it as active', async () => {
    const res = await SELF.fetch('http://localhost/api/remediation/CVE-2026-0001', {
      method: 'PUT',
      headers: AUTH,
      body: JSON.stringify({
        justification: 'compensating control in place',
        expiresAt: future(30),
      }),
    });
    expect(res.status).toBe(200);

    const list = (await (
      await SELF.fetch('http://localhost/api/remediation')
    ).json()) as RiskAcceptanceListResponse;
    expect(list.acceptances).toHaveLength(1);
    expect(list.acceptances[0]).toMatchObject({
      cveId: 'CVE-2026-0001',
      justification: 'compensating control in place',
      active: true,
    });
  });

  it('requires admin auth to accept', async () => {
    const res = await SELF.fetch('http://localhost/api/remediation/CVE-2026-0002', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ justification: 'x', expiresAt: future(10) }),
    });
    expect(res.status).toBe(403);
  });

  it('rejects a missing or past expiry (expiry is mandatory + future)', async () => {
    const noExpiry = await SELF.fetch('http://localhost/api/remediation/CVE-2026-0003', {
      method: 'PUT',
      headers: AUTH,
      body: JSON.stringify({ justification: 'x' }),
    });
    expect(noExpiry.status).toBe(400);

    const past = await SELF.fetch('http://localhost/api/remediation/CVE-2026-0003', {
      method: 'PUT',
      headers: AUTH,
      body: JSON.stringify({ justification: 'x', expiresAt: future(-5) }),
    });
    expect(past.status).toBe(400);
  });

  it('rejects an empty justification (a written reason is mandatory)', async () => {
    const res = await SELF.fetch('http://localhost/api/remediation/CVE-2026-0004', {
      method: 'PUT',
      headers: AUTH,
      body: JSON.stringify({ justification: '   ', expiresAt: future(10) }),
    });
    expect(res.status).toBe(400);
  });

  it('an already-expired acceptance (seeded directly) reads as inactive — auto-reactivation', async () => {
    // Seed a row that expired yesterday.
    const past = Date.now() - 86_400_000;
    await env.DB.prepare(
      `INSERT INTO cve_risk_acceptance
         (cve_id, justification, accepted_by, accepted_at, expires_at, created_at, updated_at)
       VALUES ('CVE-2025-9999', 'old', NULL, ?, ?, ?, ?)`,
    )
      .bind(past - 1000, past, past - 1000, past - 1000)
      .run();

    const list = (await (
      await SELF.fetch('http://localhost/api/remediation')
    ).json()) as RiskAcceptanceListResponse;
    const row = list.acceptances.find((a) => a.cveId === 'CVE-2025-9999');
    expect(row).toBeDefined();
    expect(row!.active).toBe(false); // expired → auto-reactivated
  });

  it('revokes an acceptance (admin), 404 when none exists', async () => {
    await SELF.fetch('http://localhost/api/remediation/CVE-2026-0005', {
      method: 'PUT',
      headers: AUTH,
      body: JSON.stringify({ justification: 'temp', expiresAt: future(5) }),
    });
    const del = await SELF.fetch('http://localhost/api/remediation/CVE-2026-0005', {
      method: 'DELETE',
      headers: AUTH,
    });
    expect(del.status).toBe(200);

    const again = await SELF.fetch('http://localhost/api/remediation/CVE-2026-0005', {
      method: 'DELETE',
      headers: AUTH,
    });
    expect(again.status).toBe(404);
  });

  it('a watchlist match for an actively-accepted CVE is flagged riskAccepted', async () => {
    // Seed a watchlist + match, then accept the CVE.
    const nowMs = Date.now();
    await env.DB.prepare(
      `INSERT INTO watchlist (watchlist_id, name, created_at, updated_at) VALUES (1, 'w', ?, ?)`,
    )
      .bind(nowMs, nowMs)
      .run();
    await env.DB.prepare(
      `INSERT INTO cve (cve_id, published_at, last_modified_at, description, severity, source, text_hash, state_hash, ingested_at)
       VALUES ('CVE-2026-7777', ?, ?, 'd', 'HIGH', 'NVD', 'h', 'h', ?)`,
    )
      .bind(nowMs, nowMs, nowMs)
      .run();
    await env.DB.prepare(
      `INSERT INTO watchlist_match (watchlist_id, cve_id, status, first_matched_at, status_updated_at)
       VALUES (1, 'CVE-2026-7777', 'NEW', ?, ?)`,
    )
      .bind(nowMs, nowMs)
      .run();

    await SELF.fetch('http://localhost/api/remediation/CVE-2026-7777', {
      method: 'PUT',
      headers: AUTH,
      body: JSON.stringify({ justification: 'accepted', expiresAt: future(30) }),
    });

    const detail = (await (await SELF.fetch('http://localhost/api/watchlists/1')).json()) as {
      matches: { cveId: string; riskAccepted: boolean }[];
    };
    const m = detail.matches.find((x) => x.cveId === 'CVE-2026-7777');
    expect(m?.riskAccepted).toBe(true);
  });
});
