import { describe, expect, it } from 'vitest';
import { testEnv, useCleanBindings } from './helpers';

// Regression coverage for security finding 3 (migrations/0007_osv.sql's two
// CREATE TABLE statements): confirms the migration's own statements now
// read IF NOT EXISTS, and — the actual idempotency claim in the finding —
// that re-running the migration's SQL a second time against a D1 that
// already has this schema doesn't throw.
//
// Reads the migration via the `TEST_MIGRATIONS` binding (same source
// `applyD1Migrations` uses in test/helpers.ts's `useCleanBindings`) rather
// than `node:fs` directly: these tests run inside workerd, which only
// exposes a restricted node:fs compat shim with no general access to files
// on disk outside the worker bundle. `TEST_MIGRATIONS` is populated at
// Node.js config time (vitest.config.ts's `readD1Migrations`, which does
// use real `fs.readFileSync`) and injected as a plain data binding, with
// each migration's SQL already split into individual statements via
// wrangler's own `unstable_splitSqlQuery` — a more faithful statement split
// than a hand-rolled one here would be.
//
// `useCleanBindings()` already applies every migration once per test
// through the normal migration-tracking path, so by the time a test body
// runs, 0007's tables already exist. These tests additionally execute
// 0007's own statements directly (bypassing migration-tracking) to
// simulate re-applying it, e.g. an operator re-running a partially-failed
// migration by hand — the scenario the finding's "leftover table" comments
// in the migration file are themselves about.

/** Strips `-- ...` comment lines so a classifier regex matches only actual
 *  SQL, not a comment that happens to mention another statement kind by name
 *  (several of this migration's own comments say e.g. "same reasoning as
 *  the INSERT OR IGNORE seed row below"). */
function stripComments(sql: string): string {
  return sql
    .split('\n')
    .filter((line) => !line.trim().startsWith('--'))
    .join('\n')
    .trim();
}

function osv0007Statements(): string[] {
  const migration = testEnv.TEST_MIGRATIONS.find((m) => m.name.includes('0007_osv'));
  if (!migration) {
    throw new Error(
      `migration 0007_osv.sql not found in TEST_MIGRATIONS (names: ${testEnv.TEST_MIGRATIONS.map((m) => m.name).join(', ')})`,
    );
  }
  return migration.queries;
}

async function runStatements(statements: string[]): Promise<void> {
  for (const stmt of statements) {
    if (!stmt.trim()) continue;
    await testEnv.DB.prepare(stmt).run();
  }
}

describe('migrations/0007_osv.sql', () => {
  useCleanBindings();

  it('both osv_record_state and cve_osv_affected are declared CREATE TABLE IF NOT EXISTS (not a bare CREATE TABLE)', () => {
    const statements = osv0007Statements();

    const osvStateStmt = statements.find((s) =>
      /^CREATE TABLE.*osv_record_state\s*\(/is.test(stripComments(s)),
    );
    const affectedStmt = statements.find((s) =>
      /^CREATE TABLE.*cve_osv_affected\s*\(/is.test(stripComments(s)),
    );

    expect(osvStateStmt).toBeDefined();
    expect(affectedStmt).toBeDefined();
    expect(osvStateStmt).toMatch(/CREATE TABLE IF NOT EXISTS\s+osv_record_state/i);
    expect(affectedStmt).toMatch(/CREATE TABLE IF NOT EXISTS\s+cve_osv_affected/i);
  });

  it('re-running the migration a second time does not error on the two CREATE TABLE statements', async () => {
    const statements = osv0007Statements();
    // Each statement as split by wrangler's unstable_splitSqlQuery retains
    // its preceding `--` comment block, and more than one comment in this
    // file mentions other statement kinds by name — classify on the
    // comment-stripped text, not the raw string.
    const createTableStatements = statements.filter((s) => /^CREATE TABLE/i.test(stripComments(s)));
    expect(createTableStatements).toHaveLength(2); // sanity: both found, no more

    // Schema already exists (applied once via useCleanBindings' setup).
    // Re-running just the CREATE TABLE statements is the literal claim the
    // finding asked to be fixed and must not throw.
    await expect(runStatements(createTableStatements)).resolves.toBeUndefined();
  });

  it('re-running the migration a second time does not error on the INSERT OR IGNORE seed row, and does not duplicate it', async () => {
    const statements = osv0007Statements();
    const insertStatements = statements.filter((s) => /^INSERT OR IGNORE/i.test(stripComments(s)));
    expect(insertStatements).toHaveLength(1);

    await expect(runStatements(insertStatements)).resolves.toBeUndefined();

    const row = await testEnv.DB.prepare(
      `SELECT COUNT(*) AS n FROM ingest_run WHERE source = 'OSV'`,
    ).first<{ n: number }>();
    expect(row?.n).toBe(1); // still exactly one row, not duplicated
  });

  it('both CREATE INDEX statements are declared IF NOT EXISTS (closes the gap the CREATE TABLE fix alone left open)', () => {
    const statements = osv0007Statements();
    const indexStatements = statements.filter((s) => /^CREATE INDEX/i.test(stripComments(s)));
    expect(indexStatements).toHaveLength(2); // sanity: both found, no more

    for (const stmt of indexStatements) {
      expect(stmt).toMatch(/CREATE INDEX IF NOT EXISTS/i);
    }
  });

  it('re-running the ENTIRE migration file end to end a second time does not error', async () => {
    // The original gap: the CREATE TABLE IF NOT EXISTS fix alone didn't make
    // this migration safely re-runnable, because the two CREATE INDEX
    // statements (idx_osv_state_relink, idx_cve_osv_affected_osv) were still
    // bare and threw "index ... already exists" on a second apply — exactly
    // the operator-retries-a-partially-failed-run scenario this migration's
    // own leftover-schema comments describe. Both are now IF NOT EXISTS too,
    // so the whole file — not just the CREATE TABLE statements in isolation —
    // must be safe to run twice.
    const statements = osv0007Statements();

    await expect(runStatements(statements)).resolves.toBeUndefined();

    const row = await testEnv.DB.prepare(
      `SELECT COUNT(*) AS n FROM ingest_run WHERE source = 'OSV'`,
    ).first<{ n: number }>();
    expect(row?.n).toBe(1); // still exactly one row, not duplicated by the second pass either
  });
});
