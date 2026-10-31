/**
 * Remediation / risk-acceptance contracts (Phase 4). Backed by
 * migrations/0012_remediation.sql. TYPE-ONLY.
 *
 * A CVE can be risk-accepted for a bounded time with a justification; while
 * active it's demoted in watchlist/asset views, and it auto-reactivates on
 * expiry (DefectDojo model — expiry is mandatory). Global per CVE,
 * single-tenant (same reasoning as watchlists/assets).
 */

/** A risk-acceptance decision for a CVE. `active` is derived (expiresAt > now)
 *  so an expired acceptance auto-reactivates with no background job. */
export interface RiskAcceptance {
  cveId: string;
  justification: string;
  acceptedBy: string | null;
  acceptedAt: string; // ISO 8601
  expiresAt: string; // ISO 8601
  active: boolean;
}

/** GET /api/remediation — all current (and recently-expired) acceptances. */
export interface RiskAcceptanceListResponse {
  acceptances: RiskAcceptance[];
}

/** PUT /api/remediation/[cveId] — create or extend a risk acceptance. */
export interface AcceptRiskRequest {
  justification: string;
  /** ISO 8601 expiry (required, must be in the future). */
  expiresAt: string;
  acceptedBy?: string;
}
