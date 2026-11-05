// Deterministic triage priority for a CVE. Pure, zero AI, zero neuron cost —
// computed at read time from fields already fetched. Advisory only: it RANKS
// CVEs so the most actionable surface first. Drives the CVE-detail
// intelligence panel (via cveToScoringFields + computePriority).
//
// The model is intentionally simple and explainable (the "rationale" is just
// the factors that fired), mirroring how SOC teams actually prioritise:
// active exploitation (KEV) dominates, then probability of exploitation
// (EPSS), then intrinsic severity (CVSS/severity).

export type PriorityBand = 'CRITICAL' | 'HIGH' | 'MODERATE' | 'LOW';

export interface PriorityResult {
  score: number; // 0–100
  band: PriorityBand;
  rationale: string;
}

// Weight ceilings — sum to 100. KEV is the single strongest signal (a CVE
// CISA has confirmed is being exploited in the wild), so it alone can lift an
// otherwise-moderate CVE into HIGH territory.
const KEV_WEIGHT = 40;
const EPSS_WEIGHT = 30;
const CVSS_WEIGHT = 25;
const SEVERITY_FLOOR_WEIGHT = 5; // ensures a CRITICAL with no EPSS data still ranks

/**
 * The minimal field set the score needs. A CVE detail satisfies this via
 * `cveToScoringFields`.
 */
export interface PriorityScoringFields {
  kevListed: boolean;
  epssPercentile: number | null;
  cvssBase: number | null;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE' | null;
}

/**
 * Compute the deterministic priority. Returns null only when there is no
 * underlying CVE data to score (an aged-out match whose CVE was hard-deleted).
 */
export function computePriority(m: PriorityScoringFields): PriorityResult | null {
  // No CVE row behind the match (aged out) → nothing to score. We detect this
  // the same way the read layer does: a match with no severity AND no cvss AND
  // not KEV AND no EPSS is an orphaned (aged-out) match.
  const hasData =
    m.severity !== null || m.cvssBase !== null || m.kevListed || m.epssPercentile !== null;
  if (!hasData) return null;

  const factors: string[] = [];
  let score = 0;

  if (m.kevListed) {
    score += KEV_WEIGHT;
    factors.push('KEV-listed (actively exploited)');
  }

  if (m.epssPercentile !== null) {
    // epssPercentile is 0–1; scale linearly into the EPSS weight.
    const epssPts = Math.round(m.epssPercentile * EPSS_WEIGHT);
    score += epssPts;
    if (m.epssPercentile >= 0.5) {
      factors.push(`EPSS ${(m.epssPercentile * 100).toFixed(0)}th pct`);
    }
  }

  if (m.cvssBase !== null) {
    // cvssBase is 0–10; scale into the CVSS weight.
    score += Math.round((m.cvssBase / 10) * CVSS_WEIGHT);
    factors.push(`CVSS ${m.cvssBase.toFixed(1)}`);
  }

  if (m.severity === 'CRITICAL') {
    score += SEVERITY_FLOOR_WEIGHT;
  }

  score = Math.max(0, Math.min(100, score));

  if (factors.length === 0) {
    // Scored (e.g. a non-critical severity with no CVSS/EPSS/KEV) but nothing
    // notable fired — give an honest baseline rationale.
    factors.push(m.severity ? `${m.severity} severity` : 'limited signal');
  }

  return {
    score,
    band: bandFor(score, m.kevListed),
    rationale: factors.join('; '),
  };
}

function bandFor(score: number, kevListed: boolean): PriorityBand {
  // KEV always lands at least HIGH regardless of the numeric score — an
  // actively-exploited CVE should never be shown as LOW/MODERATE even if its
  // CVSS/EPSS happen to be unremarkable.
  if (score >= 75 || (kevListed && score >= 60)) return 'CRITICAL';
  if (score >= 50 || kevListed) return 'HIGH';
  if (score >= 25) return 'MODERATE';
  return 'LOW';
}

/**
 * Adapt a CVE-detail record's fields to the scoring shape, so the CVE detail
 * page can show its priority — the "what do I fix first, and why" signal, on
 * the page a researcher lands on from a search.
 */
export function cveToScoringFields(detail: {
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';
  cvss: { base: number } | null;
  state: { kevListed: boolean; epssPercentile: number | null };
}): PriorityScoringFields {
  return {
    kevListed: detail.state.kevListed,
    epssPercentile: detail.state.epssPercentile,
    cvssBase: detail.cvss?.base ?? null,
    severity: detail.severity,
  };
}
