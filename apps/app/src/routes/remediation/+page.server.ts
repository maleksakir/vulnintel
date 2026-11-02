import { adminPageGate } from '$lib/server/adminSession';
import { getRiskAcceptances } from '$lib/server/queries/remediation';
import { readOrEmpty } from '$lib/server/tableGuard';
import type { PageServerLoad } from './$types';

// Remediation overview — all risk acceptances (active + recently expired).
// Operator-only: this is the register of CVEs we've decided not to patch, so
// it's gated before any D1 read (see $lib/server/adminSession.ts).
export const load: PageServerLoad = async ({ url, platform, cookies }) => {
  const env = platform?.env;
  if (!adminPageGate(url, cookies, env?.ADMIN_BEARER)) {
    return { authed: false, acceptances: [] };
  }

  const db = env?.DB;
  if (!db) return { authed: true, acceptances: [] };
  // cve_risk_acceptance is added by migration 0012 (see tableGuard.ts).
  const { data, schemaReady } = await readOrEmpty(() => getRiskAcceptances(db), {
    acceptances: [],
  });
  return { authed: true, acceptances: data.acceptances, schemaReady };
};
