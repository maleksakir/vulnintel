import { describe, expect, it } from 'vitest';
import { extractSsvcDecision } from '../src/adapters/nvd';

// Coverage for extractSsvcDecision (apps/ingest/src/adapters/nvd.ts), the
// SSVC half of today's two-part fix. This is pure parsing logic — no D1/KV/
// Queue bindings involved — so it's tested directly against the exported
// function rather than through the full fetchNvdDelta pipeline.

const CISA_ADP_SOURCE_ID = '134c704f-9b21-4f2e-91b3-4a467353bcc0';

function cisaEntry(options: Record<string, string>[], timestamp = '2024-04-17T04:00:13.543064Z') {
  return {
    source: CISA_ADP_SOURCE_ID,
    ssvcData: { timestamp, options },
  };
}

function otherEntry(role: 'CNA' | 'Supplier', options: Record<string, string>[]) {
  return {
    // Real NVD payloads give non-CISA entries a different source UUID per
    // org; the exact value never matters, only that it's NOT
    // CISA_ADP_SOURCE_ID.
    source: `11111111-1111-1111-1111-${role === 'CNA' ? '111111111111' : '222222222222'}`,
    role,
    ssvcData: {
      timestamp: '2024-01-01T00:00:00Z',
      options: options,
    },
  };
}

describe('extractSsvcDecision', () => {
  it('picks the CISA-ADP entry out of metrics.ssvcV203[] even when non-CISA entries (different source UUIDs, CNA/Supplier roles) are present and ordered differently', () => {
    const metrics = {
      ssvcV203: [
        otherEntry('Supplier', [{ exploitation: 'none' }]),
        otherEntry('CNA', [{ exploitation: 'poc' }, { automatable: 'no' }]),
        cisaEntry([
          { exploitation: 'active' },
          { automatable: 'yes' },
          { technicalImpact: 'total' },
        ]),
      ],
    };

    expect(extractSsvcDecision(metrics)).toEqual({
      exploitation: 'active',
      automatable: 'yes',
      technicalImpact: 'total',
      decidedAt: Date.parse('2024-04-17T04:00:13.543Z'),
    });
  });

  it('finds the CISA entry first in the array too (order-independent, not just "last wins")', () => {
    const metrics = {
      ssvcV203: [
        cisaEntry([{ exploitation: 'poc' }, { automatable: 'no' }, { technicalImpact: 'partial' }]),
        otherEntry('CNA', [{ exploitation: 'active' }]),
      ],
    };

    expect(extractSsvcDecision(metrics)?.exploitation).toBe('poc');
  });

  it('metrics present but no ssvcV\\d+ key at all: returns null, not a throw', () => {
    expect(extractSsvcDecision({ cvssMetricV31: [{ source: 'x', type: 'Primary' }] })).toBeNull();
  });

  it('metrics undefined entirely: returns null, not a throw', () => {
    expect(extractSsvcDecision(undefined)).toBeNull();
  });

  it('ssvcV203 present but contains no CISA-ADP entry (only CNA/Supplier roles): returns null', () => {
    const metrics = {
      ssvcV203: [
        otherEntry('CNA', [{ exploitation: 'active' }]),
        otherEntry('Supplier', [{ exploitation: 'active' }]),
      ],
    };
    expect(extractSsvcDecision(metrics)).toBeNull();
  });

  it('an unrecognized exploitation/automatable/technicalImpact value yields null for that specific field, not a throw or pass-through', () => {
    const metrics = {
      ssvcV203: [
        cisaEntry([
          { exploitation: 'catastrophic' }, // not in SSVC_EXPLOITATION_VALUES
          { automatable: 'maybe' }, // not in SSVC_AUTOMATABLE_VALUES
          { technicalImpact: 'total' }, // valid — proves only the bad fields are nulled
        ]),
      ],
    };

    expect(extractSsvcDecision(metrics)).toEqual({
      exploitation: null,
      automatable: null,
      technicalImpact: 'total',
      decidedAt: Date.parse('2024-04-17T04:00:13.543Z'),
    });
  });

  it('a decision point missing from options[] entirely yields null for that field', () => {
    const metrics = {
      ssvcV203: [cisaEntry([{ exploitation: 'active' }])], // automatable/technicalImpact absent
    };

    expect(extractSsvcDecision(metrics)).toEqual({
      exploitation: 'active',
      automatable: null,
      technicalImpact: null,
      decidedAt: Date.parse('2024-04-17T04:00:13.543Z'),
    });
  });

  it('multi-entry options[] arrays are searched by key, not array position (confirms it does not just read options[0])', () => {
    const metrics = {
      ssvcV203: [
        cisaEntry([
          { technicalImpact: 'partial' },
          { exploitation: 'active' },
          { automatable: 'yes' },
        ]),
      ],
    };

    expect(extractSsvcDecision(metrics)).toEqual({
      exploitation: 'active',
      automatable: 'yes',
      technicalImpact: 'partial',
      decidedAt: Date.parse('2024-04-17T04:00:13.543Z'),
    });
  });

  it('a future ssvcV204 key (not hardcoded ssvcV203) is still matched by the version-agnostic key pattern', () => {
    const metrics = {
      ssvcV204: [cisaEntry([{ exploitation: 'active' }, { automatable: 'yes' }])],
    };

    expect(extractSsvcDecision(metrics)?.exploitation).toBe('active');
  });

  it.each([
    ['microsecond-precision with Z suffix', '2024-04-17T04:00:13.543064Z'],
    ['offset-based with no sub-second component', '2024-04-17T04:00:13+00:00'],
  ])('parses the documented timestamp shape: %s', (_label, timestamp) => {
    const metrics = { ssvcV203: [cisaEntry([{ exploitation: 'active' }], timestamp)] };
    const result = extractSsvcDecision(metrics);
    expect(result?.decidedAt).not.toBeNull();
    expect(Number.isNaN(result?.decidedAt)).toBe(false);
    expect(result?.decidedAt).toBe(Date.parse(timestamp));
  });

  it('a malformed/garbage timestamp yields null for decidedAt, never NaN', () => {
    const metrics = {
      ssvcV203: [cisaEntry([{ exploitation: 'active' }], 'not-a-real-timestamp')],
    };
    const result = extractSsvcDecision(metrics);
    expect(result?.decidedAt).toBeNull();
  });

  it('a missing timestamp field yields null for decidedAt, never NaN', () => {
    const metrics = {
      ssvcV203: [
        {
          source: CISA_ADP_SOURCE_ID,
          ssvcData: { options: [{ exploitation: 'active' }] }, // no `timestamp` key at all
        },
      ],
    };
    const result = extractSsvcDecision(metrics);
    expect(result?.decidedAt).toBeNull();
  });
});
