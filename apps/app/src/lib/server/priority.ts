import type { WatchlistMatch } from '@threat-lens/contracts';

// Deterministic triage priority for a watchlist match. Pure, zero AI, zero
// neuron cost — computed at read time from fields already fetched for the
// match. Advisory only: it RANKS matches so the most actionable surface
// first, it never auto-triages (that stays a human decision via the status
// pipeline).
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

type MatchScoringFields = Pick<
  WatchlistMatch,
  'kevListed' | 'epssPercentile' | 'cvssBase' | 'severity'
>;

/**
 * Compute the deterministic priority. Returns null only when there is no
 * underlying CVE data to score (an aged-out match whose CVE was hard-deleted).
 */
export function computePriority(m: MatchScoringFields): PriorityResult | null {
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

/** Enrich a WatchlistMatch with its computed priority fields. */
export function withPriority(m: WatchlistMatch): WatchlistMatch {
  const p = computePriority(m);
  return {
    ...m,
    priorityScore: p?.score ?? null,
    priorityBand: p?.band ?? null,
    priorityRationale: p?.rationale ?? null,
  };
}
