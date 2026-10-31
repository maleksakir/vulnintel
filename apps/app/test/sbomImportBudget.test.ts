import type { AssetComponentInput } from '@threat-lens/contracts';
import { describe, expect, it } from 'vitest';
import { importSbom } from '../src/lib/server/queries/assetMutations';

// Regression guard for the SBOM import's D1 query budget.
//
// The first version of importSbom ran an INSERT…RETURNING plus one or two
// SELECTs *per component*. On the Free plan a Worker invocation is killed at
// its 51st D1 query, so any SBOM with 50+ components failed — and because the
// component DELETE had already committed, the asset was left holding a
// truncated inventory with no matches and no error. A 60-component SBOM is
// the smallest input that would have caught it.
//
// Counting against a fake D1 rather than the real one is deliberate: miniflare
// does NOT enforce the 50-query cap, so an end-to-end import through
// SELF.fetch passes no matter how many queries it runs. The cap only exists
// in production, so the only way to test for it is to count.
//
// "One query" here matches how the platform counts: every all()/first()/run()
// is one, and a db.batch() of any size is one.

type Row = Record<string, unknown>;

interface CountingDb {
  db: D1Database;
  queries: () => number;
  maxBoundParams: () => number;
  batchSizes: () => number[];
}

function countingD1(rowsFor: (sql: string, params: unknown[]) => Row[]): CountingDb {
  let queries = 0;
  let maxBoundParams = 0;
  const batchSizes: number[] = [];

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
      batchSizes.push(stmts.length);
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
    batchSizes: () => [...batchSizes],
  };
}

function npmComponents(count: number): AssetComponentInput[] {
  return Array.from({ length: count }, (_, i) => ({
    name: `pkg-${i}`,
    version: '1.0.0',
    purl: `pkg:npm/pkg-${i}@1.0.0`,
    ecosystem: 'npm',
    cpeVendor: null,
    cpeProduct: null,
  }));
}

/** Every component resolves to exactly one vulnerable OSV package. */
function handlerFor(components: AssetComponentInput[]) {
  return (sql: string, params: unknown[]): Row[] => {
    if (sql.includes('FROM asset_component WHERE asset_id')) {
      return components.map((c, i) => ({
        component_id: i + 1,
        version: c.version,
        purl: c.purl,
        ecosystem: c.ecosystem,
        cpe_vendor: c.cpeVendor,
        cpe_product: c.cpeProduct,
      }));
    }
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
    return [];
  };
}

describe('importSbom D1 query budget', () => {
  it('imports 60 components in well under the 50-query invocation cap', async () => {
    const components = npmComponents(60);
    const counting = countingD1(handlerFor(components));

    const result = await importSbom(counting.db, 1, components, 0);

    expect(result.componentsImported).toBe(60);
    expect(result.matchesFound).toBe(60);
    // The per-component version needed ~121 queries here and died at 51.
    expect(counting.queries()).toBeLessThan(50);
    expect(counting.maxBoundParams()).toBeLessThanOrEqual(100);
  });

  it('stays under the cap at the 500-component ceiling, and never binds >100 params', async () => {
    const components = npmComponents(500);
    const counting = countingD1(handlerFor(components));

    const result = await importSbom(counting.db, 1, components, 0);

    expect(result.componentsImported).toBe(500);
    // Query count must be driven by chunk count, not component count.
    expect(counting.queries()).toBeLessThan(50);
    // D1 rejects a statement binding more than 100 parameters.
    expect(counting.maxBoundParams()).toBeLessThanOrEqual(100);
  });

  it('puts the component DELETE in the same batch as the inserts', async () => {
    // A DELETE committed on its own ahead of the inserts is what left assets
    // with a truncated inventory when the invocation was killed mid-import.
    const components = npmComponents(3);
    const counting = countingD1(handlerFor(components));
    await importSbom(counting.db, 1, components, 0);

    // First batch = 1 DELETE + 3 INSERTs.
    expect(counting.batchSizes()[0]).toBe(4);
  });
});
