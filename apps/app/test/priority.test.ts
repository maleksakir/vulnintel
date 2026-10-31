import type { WatchlistMatch } from '@threat-lens/contracts';
import { describe, expect, it } from 'vitest';
import { computePriority, withPriority } from '../src/lib/server/priority';

// Pure deterministic priority scoring — no bindings, no AI, no I/O.

type Fields = Pick<WatchlistMatch, 'kevListed' | 'epssPercentile' | 'cvssBase' | 'severity'>;

function f(partial: Partial<Fields>): Fields {
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
    expect(p!.band === 'HIGH' || p!.band === 'CRITICAL').toBe(true);
    expect(p!.rationale).toContain('KEV-listed');
  });

  it('a CRITICAL actively-exploited high-EPSS CVE scores CRITICAL band', () => {
    const p = computePriority(
      f({ kevListed: true, epssPercentile: 0.98, cvssBase: 9.8, severity: 'CRITICAL' }),
    );
    expect(p!.band).toBe('CRITICAL');
    expect(p!.score).toBeGreaterThanOrEqual(75);
    expect(p!.rationale).toContain('EPSS 98th pct');
    expect(p!.rationale).toContain('CVSS 9.8');
  });

  it('score is bounded 0–100', () => {
    const p = computePriority(
      f({ kevListed: true, epssPercentile: 1, cvssBase: 10, severity: 'CRITICAL' }),
    );
    expect(p!.score).toBeLessThanOrEqual(100);
    expect(p!.score).toBeGreaterThanOrEqual(0);
  });

  it('a low-severity, low-EPSS, non-KEV CVE lands LOW or MODERATE', () => {
    const p = computePriority(f({ epssPercentile: 0.05, cvssBase: 3.1, severity: 'LOW' }));
    expect(p!.band === 'LOW' || p!.band === 'MODERATE').toBe(true);
  });

  it('EPSS below 50th percentile is not called out in the rationale (noise reduction)', () => {
    const p = computePriority(f({ epssPercentile: 0.2, cvssBase: 5.0, severity: 'MEDIUM' }));
    expect(p!.rationale).not.toContain('EPSS');
    expect(p!.rationale).toContain('CVSS 5.0');
  });

  it('higher EPSS strictly increases the score, all else equal', () => {
    const lo = computePriority(f({ epssPercentile: 0.3, cvssBase: 7, severity: 'HIGH' }))!;
    const hi = computePriority(f({ epssPercentile: 0.9, cvssBase: 7, severity: 'HIGH' }))!;
    expect(hi.score).toBeGreaterThan(lo.score);
  });

  it('withPriority fills the three contract fields', () => {
    const base: WatchlistMatch = {
      cveId: 'CVE-2026-0001',
      status: 'NEW',
      note: null,
      firstMatchedAt: new Date().toISOString(),
      statusUpdatedAt: new Date().toISOString(),
      severity: 'CRITICAL',
      cvssBase: 9.8,
      kevListed: true,
      epssPercentile: 0.95,
      riskAccepted: false,
      priorityScore: null,
      priorityBand: null,
      priorityRationale: null,
    };
    const enriched = withPriority(base);
    expect(enriched.priorityScore).toBeGreaterThan(0);
    expect(enriched.priorityBand).not.toBeNull();
    expect(enriched.priorityRationale).toBeTruthy();
  });

  it('withPriority leaves an aged-out match null', () => {
    const base: WatchlistMatch = {
      cveId: 'CVE-2020-0001',
      status: 'ACKNOWLEDGED',
      note: null,
      firstMatchedAt: new Date().toISOString(),
      statusUpdatedAt: new Date().toISOString(),
      severity: null,
      cvssBase: null,
      kevListed: false,
      epssPercentile: null,
      riskAccepted: false,
      priorityScore: null,
      priorityBand: null,
      priorityRationale: null,
    };
    const enriched = withPriority(base);
    expect(enriched.priorityScore).toBeNull();
    expect(enriched.priorityBand).toBeNull();
  });
});
