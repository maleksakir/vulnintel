import type { RiskAcceptance, RiskAcceptanceListResponse } from '@threat-lens/contracts';

// Risk-acceptance (remediation) queries. `active` is always derived from
// expires_at vs now at read time — an expired acceptance auto-reactivates
// with no background job.

interface AcceptanceRow {
  cve_id: string;
  justification: string;
  accepted_by: string | null;
  accepted_at: number;
  expires_at: number;
}

function toAcceptance(r: AcceptanceRow, now: number): RiskAcceptance {
  return {
    cveId: r.cve_id,
    justification: r.justification,
    acceptedBy: r.accepted_by,
    acceptedAt: new Date(r.accepted_at).toISOString(),
    expiresAt: new Date(r.expires_at).toISOString(),
    active: r.expires_at > now,
  };
}

/** GET /api/remediation — all acceptances (active first, then recently
 *  expired), newest expiry first. */
export async function getRiskAcceptances(db: D1Database): Promise<RiskAcceptanceListResponse> {
  const now = Date.now();
  const res = await db
    .prepare(
      `SELECT cve_id, justification, accepted_by, accepted_at, expires_at
       FROM cve_risk_acceptance
       ORDER BY expires_at DESC`,
    )
    .all<AcceptanceRow>();
  return { acceptances: res.results.map((r) => toAcceptance(r, now)) };
}

/** The set of CVE IDs currently under an ACTIVE acceptance — used to demote
 *  them in watchlist/asset views. Bounded (acceptances are a small
 *  human-managed set), one indexed read. */
export async function getActivelyAcceptedCveIds(db: D1Database): Promise<Set<string>> {
  const now = Date.now();
  const res = await db
    .prepare(`SELECT cve_id FROM cve_risk_acceptance WHERE expires_at > ?`)
    .bind(now)
    .all<{ cve_id: string }>();
  return new Set(res.results.map((r) => r.cve_id));
}

/** Fetch a single acceptance (or null). */
export async function getRiskAcceptance(
  db: D1Database,
  cveId: string,
): Promise<RiskAcceptance | null> {
  const row = await db
    .prepare(
      `SELECT cve_id, justification, accepted_by, accepted_at, expires_at
       FROM cve_risk_acceptance WHERE cve_id = ?`,
    )
    .bind(cveId)
    .first<AcceptanceRow>();
  return row ? toAcceptance(row, Date.now()) : null;
}

/** Create or extend (upsert) a risk acceptance. */
export async function upsertRiskAcceptance(
  db: D1Database,
  cveId: string,
  justification: string,
  expiresAtMs: number,
  acceptedBy: string | null,
): Promise<void> {
  const now = Date.now();
  await db
    .prepare(
      `INSERT INTO cve_risk_acceptance
         (cve_id, justification, accepted_by, accepted_at, expires_at, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (cve_id) DO UPDATE SET
         justification = excluded.justification,
         accepted_by   = excluded.accepted_by,
         accepted_at   = excluded.accepted_at,
         expires_at    = excluded.expires_at,
         updated_at    = excluded.updated_at`,
    )
    .bind(cveId, justification, acceptedBy, now, expiresAtMs, now, now)
    .run();
}

/** Revoke an acceptance (re-activate the CVE immediately). Returns false if
 *  none existed. */
export async function revokeRiskAcceptance(db: D1Database, cveId: string): Promise<boolean> {
  const res = await db
    .prepare(`DELETE FROM cve_risk_acceptance WHERE cve_id = ?`)
    .bind(cveId)
    .run();
  return (res.meta.changes ?? 0) > 0;
}
