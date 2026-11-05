import type { SbomComponentInput } from '@threat-lens/contracts';
import { describe, expect, it } from 'vitest';
import { scanSbom } from '../src/lib/server/sbomMatch';

// Regression guard for the stateless SBOM scan's D1 query budget.
//
// scanSbom must never run a query PER component — the matching is set-based
// (PURL names chunked at 100, CPE pairs at 50, CVE enrichment chunked at 100),
// so the query count is driven by chunk count, not component count. On the
// Free plan a Worker invocation is killed at its 51st D1 query, so a scan of a
// large SBOM must stay well under that.
//
// Counting against a fake D1 is deliberate: miniflare does NOT enforce the
// 50-query cap, so an end-to-end scan passes no matter how many queries it
// runs. The cap only exists in production, so the only way to test for it is
// to count. "One query" matches how the platform counts: every
// all()/first()/run() is one, and a db.batch() of any size is one.

type Row = Record<string, unknown>;

interface CountingDb {
  db: D1Database;
  queries: () => number;
  maxBoundParams: () => number;
}

function countingD1(rowsFor: (sql: string, params: unknown[]) => Row[]): CountingDb {
  let queries = 0;
  let maxBoundParams = 0;

  const prepare = (sql: string): D1PreparedStatement => {
    let bound: unknown[] = [];
    const stmt = {
      bind(...params: unknown[]) {
        bound = params;
        maxBoundParams = Math.max(maxBoundParams, params.length);
        return stmt;
      },
      async all() {
        queries++;
        return { results: rowsFor(sql, bound), success: true, meta: {} };
      },
      async first() {
        queries++;
        return rowsFor(sql, bound)[0] ?? null;
      },
      async run() {
        queries++;
        return { results: [], success: true, meta: { changes: 1 } };
      },
      async raw() {
        queries++;
        return [];
      },
    };
    return stmt as unknown as D1PreparedStatement;
  };

  const db = {
    prepare,
    async batch(stmts: D1PreparedStatement[]) {
      queries++;
      return stmts.map(() => ({ results: [], success: true, meta: {} }));
    },
    async exec() {
      queries++;
      return { count: 0, duration: 0 };
    },
    withSession() {
      throw new Error('not used');
    },
    dump() {
      throw new Error('not used');
    },
  };

  return {
    db: db as unknown as D1Database,
    queries: () => queries,
    maxBoundParams: () => maxBoundParams,
  };
}

function npmComponents(count: number): SbomComponentInput[] {
  return Array.from({ length: count }, (_, i) => ({
    name: `pkg-${i}`,
    version: '1.0.0',
    purl: `pkg:npm/pkg-${i}@1.0.0`,
    ecosystem: 'npm',
    cpeVendor: null,
    cpeProduct: null,
  }));
}

/** Every component resolves to exactly one vulnerable OSV package, and every
 *  matched CVE enriches to one row. */
function handlerFor(): (sql: string, params: unknown[]) => Row[] {
  return (sql: string, params: unknown[]): Row[] => {
    if (sql.includes('FROM cve_osv_affected')) {
      // params are the chunk's package names.
      return params
        .filter((p): p is string => typeof p === 'string')
        .map((name) => ({
          cve_id: `CVE-2026-${name.replace(/\D/g, '')}`,
          ecosystem: 'npm',
          package_name: name,
          fixed_versions: null,
        }));
    }
    if (sql.includes('FROM cve c LEFT JOIN cve_state')) {
      return params
        .filter((p): p is string => typeof p === 'string')
        .map((cveId) => ({
          cve_id: cveId,
          severity: 'HIGH',
          cvss_base: 7.5,
          kev_listed: 0,
          epss_percentile: 0.4,
          exploit_maturity: null,
        }));
    }
    return [];
  };
}

describe('scanSbom D1 query budget', () => {
  it('scans 60 components in well under the 50-query invocation cap', async () => {
    const components = npmComponents(60);
    const counting = countingD1(handlerFor());

    const result = await scanSbom(counting.db, components, 0);

    expect(result.componentsScanned).toBe(60);
    expect(result.vulnerableComponents).toBe(60);
    expect(counting.queries()).toBeLessThan(50);
    expect(counting.maxBoundParams()).toBeLessThanOrEqual(100);
  });

  it('stays under the cap at the 500-component ceiling, and never binds >100 params', async () => {
    const components = npmComponents(500);
    const counting = countingD1(handlerFor());

    const result = await scanSbom(counting.db, components, 0);

    expect(result.componentsScanned).toBe(500);
    // Query count must be driven by chunk count, not component count:
    //   500 PURL names / 100 = 5 reads
    //   500 CVEs enrichment / 100 = 5 reads
    //   (no CPE fallback — all matched via PURL)
    expect(counting.queries()).toBeLessThan(50);
    expect(counting.maxBoundParams()).toBeLessThanOrEqual(100);
  });

  it('performs ZERO writes (stateless scan — no batch/run inserts needed)', async () => {
    // A pure read path: the fake db.batch/run would still count, so just assert
    // the result is correct and the query count matches the read-only shape.
    const components = npmComponents(10);
    const counting = countingD1(handlerFor());
    const result = await scanSbom(counting.db, components, 0);
    expect(result.totalCves).toBe(10);
    // 1 PURL read + 1 enrichment read = 2 queries for 10 components.
    expect(counting.queries()).toBe(2);
  });
});
