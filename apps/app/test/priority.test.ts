import { describe, expect, it } from 'vitest';
import {
  computePriority,
  cveToScoringFields,
  type PriorityScoringFields,
} from '../src/lib/server/priority';

// Pure deterministic priority scoring — no bindings, no AI, no I/O.

function f(partial: Partial<PriorityScoringFields>): PriorityScoringFields {
  return {
    kevListed: false,
    epssPercentile: null,
    cvssBase: null,
    severity: null,
    ...partial,
  };
}

describe('computePriority', () => {
  it('returns null for an aged-out match (no CVE data at all)', () => {
    expect(computePriority(f({}))).toBeNull();
  });

  it('KEV-listed always lands at least HIGH, even with otherwise low signal', () => {
    const p = computePriority(f({ kevListed: true, cvssBase: 2.0, severity: 'LOW' }));
    expect(p).not.toBeNull();
    expect(p?.band === 'HIGH' || p?.band === 'CRITICAL').toBe(true);
    expect(p?.rationale).toContain('KEV-listed');
  });

  it('a CRITICAL actively-exploited high-EPSS CVE scores CRITICAL band', () => {
    const p = computePriority(
      f({ kevListed: true, epssPercentile: 0.98, cvssBase: 9.8, severity: 'CRITICAL' }),
    );
    expect(p?.band).toBe('CRITICAL');
    expect(p?.score).toBeGreaterThanOrEqual(75);
    expect(p?.rationale).toContain('EPSS 98th pct');
    expect(p?.rationale).toContain('CVSS 9.8');
  });

  it('score is bounded 0–100', () => {
    const p = computePriority(
      f({ kevListed: true, epssPercentile: 1, cvssBase: 10, severity: 'CRITICAL' }),
    );
    expect(p?.score).toBeLessThanOrEqual(100);
    expect(p?.score).toBeGreaterThanOrEqual(0);
  });

  it('a low-severity, low-EPSS, non-KEV CVE lands LOW or MODERATE', () => {
    const p = computePriority(f({ epssPercentile: 0.05, cvssBase: 3.1, severity: 'LOW' }));
    expect(p?.band === 'LOW' || p?.band === 'MODERATE').toBe(true);
  });

  it('EPSS below 50th percentile is not called out in the rationale (noise reduction)', () => {
    const p = computePriority(f({ epssPercentile: 0.2, cvssBase: 5.0, severity: 'MEDIUM' }));
    expect(p?.rationale).not.toContain('EPSS');
    expect(p?.rationale).toContain('CVSS 5.0');
  });

  it('higher EPSS strictly increases the score, all else equal', () => {
    const lo = computePriority(f({ epssPercentile: 0.3, cvssBase: 7, severity: 'HIGH' }))!;
    const hi = computePriority(f({ epssPercentile: 0.9, cvssBase: 7, severity: 'HIGH' }))!;
    expect(hi.score).toBeGreaterThan(lo.score);
  });

  it('a KEV-listed critical scores high and non-null', () => {
    const p = computePriority(
      f({ severity: 'CRITICAL', cvssBase: 9.8, kevListed: true, epssPercentile: 0.95 }),
    );
    expect(p).not.toBeNull();
    expect(p!.score).toBeGreaterThan(0);
    expect(p!.band).not.toBeNull();
    expect(p!.rationale).toBeTruthy();
  });

  it('an aged-out CVE (no data) scores null', () => {
    const p = computePriority(f({}));
    expect(p).toBeNull();
  });
});

describe('cveToScoringFields (CVE-detail → priority)', () => {
  // The CVE detail page scores with this adapter. Pin that the mapping is
  // faithful and matches a direct scoring-fields call for the same CVE.
  it('maps a CVE detail into scoring fields and scores identically to a match', () => {
    const detail = {
      severity: 'CRITICAL' as const,
      cvss: { base: 9.8 },
      state: { kevListed: true, epssPercentile: 0.97 },
    };
    const fromDetail = computePriority(cveToScoringFields(detail));
    const fromMatch = computePriority(
      f({ kevListed: true, epssPercentile: 0.97, cvssBase: 9.8, severity: 'CRITICAL' }),
    );
    expect(fromDetail).toEqual(fromMatch);
    expect(fromDetail?.band).toBe('CRITICAL');
  });

  it('handles a CVE with no CVSS block (cvss null → cvssBase null)', () => {
    const detail = {
      severity: 'MEDIUM' as const,
      cvss: null,
      state: { kevListed: false, epssPercentile: 0.1 },
    };
    const p = computePriority(cveToScoringFields(detail));
    expect(p).not.toBeNull();
    expect(p?.rationale).not.toContain('CVSS');
  });
});
