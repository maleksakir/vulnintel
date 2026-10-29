import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  fetchOsvModifiedSince,
  fetchOsvRecord,
  normalizeOsvRecord,
  OSV_ID_ALLOW,
} from '../src/adapters/osv';

function requestUrl(input: RequestInfo | URL): string {
  if (typeof input === 'string') return input;
  if (input instanceof URL) return input.href;
  return input.url;
}

describe('OSV_ID_ALLOW', () => {
  it('accepts well-formed GHSA ids', () => {
    expect(OSV_ID_ALLOW.test('GHSA-jf75-q64q-g65r')).toBe(true);
  });

  it('rejects everything else, including URL-injection attempts', () => {
    expect(OSV_ID_ALLOW.test('CVE-2026-12345')).toBe(false);
    expect(OSV_ID_ALLOW.test('GHSA-jf75-q64q')).toBe(false); // only 2 groups
    expect(OSV_ID_ALLOW.test('GHSA-JF75-Q64Q-G65R')).toBe(false); // uppercase
    expect(OSV_ID_ALLOW.test('GHSA-jf75-q64q-g65r/../../etc')).toBe(false);
    expect(OSV_ID_ALLOW.test('GHSA-jf75-q64q-g65r?x=1')).toBe(false);
  });
});

describe('normalizeOsvRecord', () => {
  it('normalizes a well-formed record, deduping + sorting CVE aliases', () => {
    const raw = {
      id: 'GHSA-jf75-q64q-g65r',
      modified: '2026-10-28T12:00:00.123456789Z',
      published: '2026-10-20T00:00:00Z',
      aliases: ['CVE-2026-50002', 'CVE-2026-50001', 'CVE-2026-50001', 'not-a-cve'],
      affected: [
        {
          package: { ecosystem: 'npm', name: 'left-pad-evil', purl: 'pkg:npm/left-pad-evil' },
          ranges: [
            {
              type: 'SEMVER',
              events: [{ introduced: '0' }, { fixed: '1.2.3' }],
            },
          ],
        },
      ],
    };

    const patch = normalizeOsvRecord(raw);
    expect(patch).toEqual({
      osvId: 'GHSA-jf75-q64q-g65r',
      modified: '2026-10-28T12:00:00.123456789Z',
      published: '2026-10-20T00:00:00Z',
      withdrawn: false,
      cveIds: ['CVE-2026-50001', 'CVE-2026-50002'],
      affected: [
        {
          ecosystem: 'npm',
          name: 'left-pad-evil',
          purl: 'pkg:npm/left-pad-evil',
          ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.2.3' }] }],
          fixedVersions: ['1.2.3'],
        },
      ],
    });
  });

  it('a record with no CVE-shaped alias normalizes to an empty cveIds array, not null', () => {
    const patch = normalizeOsvRecord({
      id: 'GHSA-jf75-q64q-g65r',
      modified: '2026-10-28T00:00:00Z',
      aliases: ['GHSA-other-advisory-id'],
      affected: [],
    });
    expect(patch?.cveIds).toEqual([]);
  });

  it('treats a non-empty `withdrawn` string as withdrawn=true', () => {
    const patch = normalizeOsvRecord({
      id: 'GHSA-jf75-q64q-g65r',
      modified: '2026-10-28T00:00:00Z',
      withdrawn: '2026-10-29T00:00:00Z',
      affected: [],
    });
    expect(patch?.withdrawn).toBe(true);
  });

  it('returns null for genuinely malformed input (missing id/modified)', () => {
    expect(normalizeOsvRecord(null)).toBeNull();
    expect(normalizeOsvRecord({})).toBeNull();
    expect(normalizeOsvRecord({ id: 'GHSA-jf75-q64q-g65r' })).toBeNull(); // no `modified`
    expect(
      normalizeOsvRecord({ id: 'not-a-ghsa-id', modified: '2026-10-28T00:00:00Z' }),
    ).toBeNull();
  });

  it('caps affected entries at 50', () => {
    const affected = Array.from({ length: 80 }, (_, i) => ({
      package: { ecosystem: 'npm', name: `pkg-${i}` },
      ranges: [],
    }));
    const patch = normalizeOsvRecord({
      id: 'GHSA-jf75-q64q-g65r',
      modified: '2026-10-28T00:00:00Z',
      affected,
    });
    expect(patch?.affected).toHaveLength(50);
  });

  it('drops a malformed affected entry (missing package.name) without failing the whole record', () => {
    const patch = normalizeOsvRecord({
      id: 'GHSA-jf75-q64q-g65r',
      modified: '2026-10-28T00:00:00Z',
      affected: [
        { package: { ecosystem: 'npm' }, ranges: [] }, // missing name
        { package: { ecosystem: 'npm', name: 'ok-pkg' }, ranges: [] },
      ],
    });
    expect(patch?.affected).toHaveLength(1);
    expect(patch?.affected[0]?.name).toBe('ok-pkg');
  });

  it('never throws on wildly unexpected top-level or nested shapes (fuzz-ish, adversarial inputs)', () => {
    const garbageInputs: unknown[] = [
      undefined,
      42,
      'just a string',
      [],
      [1, 2, 3],
      { id: 'GHSA-jf75-q64q-g65r', modified: 123 }, // modified is a number, not a string
      { id: 'GHSA-jf75-q64q-g65r', modified: '2026-10-28T00:00:00Z', aliases: 'not-an-array' },
      { id: 'GHSA-jf75-q64q-g65r', modified: '2026-10-28T00:00:00Z', affected: 'not-an-array' },
      {
        id: 'GHSA-jf75-q64q-g65r',
        modified: '2026-10-28T00:00:00Z',
        affected: [null, 42, 'oops', [], { package: 'not-an-object' }, { package: null }],
      },
      {
        id: 'GHSA-jf75-q64q-g65r',
        modified: '2026-10-28T00:00:00Z',
        affected: [
          {
            package: { ecosystem: 'npm', name: 'pkg' },
            ranges: 'not-an-array',
          },
          {
            package: { ecosystem: 'npm', name: 'pkg' },
            ranges: [
              null,
              42,
              { type: 'BOGUS_TYPE', events: [] },
              { type: 'SEMVER', events: 'nope' },
            ],
          },
          {
            package: { ecosystem: 'npm', name: 'pkg' },
            ranges: [{ type: 'SEMVER', events: [null, 42, { introduced: 123 }, { fixed: null }] }],
          },
        ],
      },
      { id: 'GHSA-jf75-q64q-g65r', modified: '2026-10-28T00:00:00Z', withdrawn: 42 },
      { id: 123, modified: '2026-10-28T00:00:00Z' },
      { id: null, modified: null },
    ];

    for (const raw of garbageInputs) {
      expect(() => normalizeOsvRecord(raw)).not.toThrow();
    }
  });
});

describe('normalizeOsvRecord — ranges performance (regression for O(n²) boundRangesJsonSize, security finding 1)', () => {
  it('stays fast and still correctly bounded when a single affected entry carries 10,000 ranges', () => {
    // The original bug: boundRangesJsonSize re-stringified the whole
    // remaining ranges array on every trim iteration (O(n²)) — reviewer
    // measured ~20s of synchronous CPU at n=8000. normalizeAffectedEntry
    // isn't exported, so this drives the same code path through the public
    // normalizeOsvRecord entry point instead.
    const hugeRanges = Array.from({ length: 10_000 }, (_, i) => ({
      type: 'SEMVER',
      events: [{ introduced: '0' }, { fixed: `1.0.${i}` }],
    }));
    const raw = {
      id: 'GHSA-jf75-q64q-g65r',
      modified: '2026-10-28T00:00:00Z',
      affected: [
        {
          package: { ecosystem: 'npm', name: 'huge-ranges-pkg' },
          ranges: hugeRanges,
        },
      ],
    };

    const start = performance.now();
    const patch = normalizeOsvRecord(raw);
    const elapsedMs = performance.now() - start;

    // Clearly fails against the old O(n²) behavior (single-digit-to-tens of
    // seconds at this n) and clearly passes a correctly-capped-and/or-O(n)
    // implementation (sub-millisecond in practice).
    expect(elapsedMs).toBeLessThan(500);

    // Still correctly bounded: OSV_MAX_RANGES_PER_AFFECTED (50) truncates
    // the input array before it ever reaches boundRangesJsonSize.
    expect(patch?.affected).toHaveLength(1);
    expect(patch?.affected[0]?.ranges.length).toBeGreaterThan(0);
    expect(patch?.affected[0]?.ranges.length).toBeLessThanOrEqual(50);
  });

  it('byte-budget trimming (RANGES_JSON_MAX_BYTES) still keeps the maximal leading prefix that fits — the O(n) rewrite is not just fast, its output is still correct', () => {
    // 50 ranges (at the OSV_MAX_RANGES_PER_AFFECTED cap) each padded large
    // enough that the serialized array exceeds RANGES_JSON_MAX_BYTES well
    // before all 50 are included, so the byte-budget trim (not the
    // count cap) is what's under test here.
    const padding = 'x'.repeat(300);
    const bigRanges = Array.from({ length: 50 }, () => ({
      type: 'GIT',
      repo: `https://example.com/${padding}`,
      events: [{ introduced: '0' }, { fixed: '1.0.0' }],
    }));
    const raw = {
      id: 'GHSA-jf75-q64q-g65r',
      modified: '2026-10-28T00:00:00Z',
      affected: [{ package: { ecosystem: 'npm', name: 'big-ranges-pkg' }, ranges: bigRanges }],
    };

    const patch = normalizeOsvRecord(raw);
    const kept = patch?.affected[0]?.ranges ?? [];

    expect(kept.length).toBeGreaterThan(0);
    expect(kept.length).toBeLessThan(50); // byte budget trimmed it, not just the 50-count cap

    const keptBytes = new TextEncoder().encode(JSON.stringify(kept)).length;
    expect(keptBytes).toBeLessThanOrEqual(8192); // RANGES_JSON_MAX_BYTES

    // Maximal prefix: including one more of the original (untrimmed)
    // ranges would have exceeded the budget — confirms the rewrite kept the
    // same "largest prefix that fits" semantics as the old implementation,
    // not merely a safe-but-wrong smaller subset.
    if (kept.length < bigRanges.length) {
      const oneMoreBytes = new TextEncoder().encode(
        JSON.stringify([...kept, bigRanges[kept.length]]),
      ).length;
      expect(oneMoreBytes).toBeGreaterThan(8192);
    }
  });
});

describe('fetchOsvModifiedSince', () => {
  beforeEach(() => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const url = requestUrl(input);
        if (url.includes('/npm/modified_id.csv')) {
          // Newest-first.
          const csv = [
            '2026-10-29T00:00:00.000000000Z,GHSA-aaaa-aaaa-aaaa',
            '2026-10-28T00:00:00.000000000Z,GHSA-bbbb-bbbb-bbbb',
            '2026-10-27T00:00:00.000000000Z,GHSA-cccc-cccc-cccc',
            '2026-10-20T00:00:00.000000000Z,GHSA-dddd-dddd-dddd',
          ].join('\n');
          return new Response(csv, { status: 200 });
        }
        throw new Error(`unexpected fetch() call in test: ${url}`);
      }),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('yields only entries newer than sinceMs, stopping at the first older-or-equal line', async () => {
    const sinceMs = Date.parse('2026-10-27T00:00:00.000Z');
    const out: string[] = [];
    for await (const entry of fetchOsvModifiedSince('npm', sinceMs, 100)) {
      out.push(entry.osvId);
    }
    expect(out).toEqual(['GHSA-aaaa-aaaa-aaaa', 'GHSA-bbbb-bbbb-bbbb']);
  });

  it('respects maxLines even when more entries would otherwise qualify', async () => {
    const sinceMs = Date.parse('2026-01-01T00:00:00.000Z'); // everything qualifies
    const out: string[] = [];
    for await (const entry of fetchOsvModifiedSince('npm', sinceMs, 2)) {
      out.push(entry.osvId);
    }
    expect(out).toHaveLength(2);
    expect(out).toEqual(['GHSA-aaaa-aaaa-aaaa', 'GHSA-bbbb-bbbb-bbbb']);
  });
});

describe('fetchOsvRecord', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('returns null on 404 (withdrawn/not found), not an error', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('not found', { status: 404 })),
    );
    const result = await fetchOsvRecord('GHSA-jf75-q64q-g65r');
    expect(result).toBeNull();
  });

  it('throws on a non-404 error status', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('oops', { status: 500 })),
    );
    await expect(fetchOsvRecord('GHSA-jf75-q64q-g65r')).rejects.toThrow();
  });

  it('refuses to fetch (never calls fetch()) for a malformed id, defending the URL interpolation', async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);
    await expect(fetchOsvRecord('not-a-ghsa-id; rm -rf')).rejects.toThrow(/malformed/i);
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
