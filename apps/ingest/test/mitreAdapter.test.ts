import { describe, expect, it } from 'vitest';
import { normalizeMitreCweSupplement } from '../src/adapters/mitre';

// Pure-function coverage for adapters/mitre.ts's normalizeMitreCweSupplement
// — no network involved (see test/mitreQueueConsumer.test.ts for the
// fetch-level integration coverage). This is the direct regression test for
// the free-text CWE fallback: the entire reason this adapter exists is a
// CNA that writes a CWE as free text in a description field with no
// structured `cweId` NVD's own parsing can pick up.

function mitreRecord(opts: {
  state?: string;
  cnaDescriptions?: Array<{ cweId?: string; description?: string }>;
  adp?: Array<{ descriptions: Array<{ cweId?: string; description?: string }> }>;
}) {
  return {
    cveMetadata: { state: opts.state ?? 'PUBLISHED' },
    containers: {
      cna: opts.cnaDescriptions
        ? { problemTypes: [{ descriptions: opts.cnaDescriptions }] }
        : undefined,
      adp: opts.adp?.map((a) => ({ problemTypes: [{ descriptions: a.descriptions }] })),
    },
  };
}

describe('normalizeMitreCweSupplement', () => {
  it('extracts a structured cweId when present', () => {
    const raw = mitreRecord({ cnaDescriptions: [{ cweId: 'CWE-79', description: 'XSS' }] });
    const result = normalizeMitreCweSupplement('CVE-2026-00001', raw);
    expect(result).toEqual({ cveId: 'CVE-2026-00001', outcome: 'OK', cwes: ['CWE-79'] });
  });

  it('falls back to free-text extraction against the literal "CWE-79 Cross-Site Scripting (XSS)" style description — the one case NVD cannot already parse', () => {
    const raw = mitreRecord({
      cnaDescriptions: [{ description: 'CWE-79 Cross-Site Scripting (XSS)' }],
    });
    const result = normalizeMitreCweSupplement('CVE-2026-00002', raw);
    expect(result.outcome).toBe('OK');
    expect(result.cwes).toEqual(['CWE-79']);
  });

  it('extracts from a free-text description with trailing punctuation immediately after the number (the `\\b` boundary, not a space)', () => {
    const raw = mitreRecord({ cnaDescriptions: [{ description: 'CWE-89: SQL Injection' }] });
    const result = normalizeMitreCweSupplement('CVE-2026-00003', raw);
    expect(result.cwes).toEqual(['CWE-89']);
  });

  it('prefers the structured cweId over free text when both are present on the same entry', () => {
    const raw = mitreRecord({
      cnaDescriptions: [{ cweId: 'CWE-79', description: 'CWE-89 something else entirely' }],
    });
    const result = normalizeMitreCweSupplement('CVE-2026-00004', raw);
    expect(result.cwes).toEqual(['CWE-79']);
  });

  it('ignores CWE-noinfo, NVD-CWE-* pseudo-IDs, and n/a — as both a structured cweId and as free text', () => {
    const raw = mitreRecord({
      cnaDescriptions: [
        { cweId: 'CWE-noinfo' },
        { cweId: 'NVD-CWE-noinfo' },
        { cweId: 'NVD-CWE-Other' },
        { description: 'CWE-noinfo' },
        { description: 'n/a' },
        { description: 'NVD-CWE-noinfo' },
      ],
    });
    const result = normalizeMitreCweSupplement('CVE-2026-00005', raw);
    expect(result.outcome).toBe('OK');
    expect(result.cwes).toEqual([]);
  });

  it('reads CWEs from every containers.adp[] entry in addition to containers.cna', () => {
    const raw = mitreRecord({
      cnaDescriptions: [{ cweId: 'CWE-79' }],
      adp: [
        { descriptions: [{ cweId: 'CWE-89' }] },
        { descriptions: [{ description: 'CWE-22 Path Traversal' }] },
      ],
    });
    const result = normalizeMitreCweSupplement('CVE-2026-00006', raw);
    expect(new Set(result.cwes)).toEqual(new Set(['CWE-79', 'CWE-89', 'CWE-22']));
  });

  it('deduplicates CWEs seen more than once across cna/adp', () => {
    const raw = mitreRecord({
      cnaDescriptions: [{ cweId: 'CWE-79' }],
      adp: [{ descriptions: [{ cweId: 'CWE-79' }] }],
    });
    const result = normalizeMitreCweSupplement('CVE-2026-00007', raw);
    expect(result.cwes).toEqual(['CWE-79']);
  });

  it('caps at 10 CWEs per CVE', () => {
    const raw = mitreRecord({
      cnaDescriptions: Array.from({ length: 15 }, (_, i) => ({ cweId: `CWE-${100 + i}` })),
    });
    const result = normalizeMitreCweSupplement('CVE-2026-00008', raw);
    expect(result.cwes).toHaveLength(10);
  });

  it('treats a REJECTED record state as "nothing to add", not an error', () => {
    const raw = mitreRecord({ state: 'REJECTED', cnaDescriptions: [{ cweId: 'CWE-79' }] });
    const result = normalizeMitreCweSupplement('CVE-2026-00009', raw);
    expect(result).toEqual({ cveId: 'CVE-2026-00009', outcome: 'REJECTED', cwes: [] });
  });

  it('returns MALFORMED for a non-object body without throwing', () => {
    expect(normalizeMitreCweSupplement('CVE-2026-00010', null)).toEqual({
      cveId: 'CVE-2026-00010',
      outcome: 'MALFORMED',
      cwes: [],
    });
    expect(normalizeMitreCweSupplement('CVE-2026-00011', 'not an object')).toEqual({
      cveId: 'CVE-2026-00011',
      outcome: 'MALFORMED',
      cwes: [],
    });
  });

  it('returns OK with an empty cwes list when containers/problemTypes are entirely absent (a published record with genuinely nothing to recover)', () => {
    const raw = { cveMetadata: { state: 'PUBLISHED' }, containers: {} };
    const result = normalizeMitreCweSupplement('CVE-2026-00012', raw);
    expect(result).toEqual({ cveId: 'CVE-2026-00012', outcome: 'OK', cwes: [] });
  });

  // ── Real-captured-shape regression tests ──────────────────────────────
  // These two fixtures are copied verbatim (field-for-field, `lang` key
  // included) from a live fetch of MITRE's real public single-record
  // endpoint (`GET /api/cve/{id}`) on 2026-10-30 — not invented. This is the
  // direct fix for the root cause the previous (now-removed) MITRE test
  // suite missed: its stub shape never matched MITRE's actual API contract,
  // which is part of why the original adapter bug went uncaught. Both real
  // records confirm the exact thing this adapter exists for: no `cweId`
  // field at all, only a free-text `description` carrying the CWE id.
  it('extracts "CWE-79" from the real captured CVE-2023-0062 CNA problemTypes shape (no cweId field, lang="en")', () => {
    const raw = {
      cveMetadata: { state: 'PUBLISHED' },
      containers: {
        cna: {
          problemTypes: [
            {
              descriptions: [
                { lang: 'en', description: 'CWE-79 Cross-Site Scripting (XSS)', type: 'CWE' },
              ],
            },
          ],
        },
      },
    };
    const result = normalizeMitreCweSupplement('CVE-2023-0062', raw);
    expect(result).toEqual({ cveId: 'CVE-2023-0062', outcome: 'OK', cwes: ['CWE-79'] });
  });

  it('extracts "CWE-918" from the real captured CVE-2026-15146 CNA problemTypes shape (no cweId field, lang="en")', () => {
    const raw = {
      cveMetadata: { state: 'PUBLISHED' },
      containers: {
        cna: {
          problemTypes: [
            {
              descriptions: [
                { lang: 'en', description: 'CWE-918 Server-Side Request Forgery (SSRF)' },
              ],
            },
          ],
        },
      },
    };
    const result = normalizeMitreCweSupplement('CVE-2026-15146', raw);
    expect(result).toEqual({ cveId: 'CVE-2026-15146', outcome: 'OK', cwes: ['CWE-918'] });
  });
});
