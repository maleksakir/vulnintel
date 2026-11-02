// Read-side guard for features whose tables are added by a migration that may
// not have been applied yet.
//
// On 2026-11-02 the watchlists / assets / remediation migrations (0009-0012)
// could not be applied to production for a full UTC day because the account's
// D1 daily WRITE cap was exhausted, while the Worker deploy was unaffected.
// A deployed page that SELECTs from a not-yet-created table raises
// `no such table: …`, which SvelteKit turns into a 500 — so the three feature
// pages all 500'd on a live origin. Deploy order and migration order are
// independent in practice (same reasoning as getMetrics' rollup fallback), so
// the read side must tolerate the tables being absent and render an empty
// state instead of erroring.

/**
 * Run a read that targets a possibly-absent table.
 *
 * Returns `{ data, schemaReady: true }` normally, or
 * `{ data: fallback, schemaReady: false }` when the table does not exist yet,
 * so a page can render an empty state AND tell the operator the feature is
 * still initializing rather than silently showing "no data" as if it were
 * real emptiness.
 *
 * READS only. Mutations still fail loudly: writing to a missing table is a
 * real error an operator must see, not something to swallow.
 */
export async function readOrEmpty<T>(
  run: () => Promise<T>,
  fallback: T,
): Promise<{ data: T; schemaReady: boolean }> {
  try {
    return { data: await run(), schemaReady: true };
  } catch (err) {
    if (isMissingTable(err)) return { data: fallback, schemaReady: false };
    // Any OTHER read error is a real fault — a 500 is the honest response.
    throw err;
  }
}

function isMissingTable(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  return /no such table/i.test(msg);
}
