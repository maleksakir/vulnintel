import type { WatchlistMatchStatus } from '@threat-lens/contracts';

// Write-side watchlist operations (admin-gated). Kept separate from the
// read-side getWatchlists.ts. All timestamps unix ms.

const BACKFILL_VENDOR_LIMIT = 5000; // cap a single subscription's backfill scan

export async function createWatchlist(
  db: D1Database,
  name: string,
  description: string | undefined,
): Promise<number> {
  const now = Date.now();
  const row = await db
    .prepare(
      `INSERT INTO watchlist (name, description, created_at, updated_at)
       VALUES (?, ?, ?, ?) RETURNING watchlist_id`,
    )
    .bind(name, description ?? null, now, now)
    .first<{ watchlist_id: number }>();
  if (!row) throw new Error('watchlist insert returned no id');
  return row.watchlist_id;
}

/** Returns false if the watchlist doesn't exist. */
export async function updateWatchlist(
  db: D1Database,
  watchlistId: number,
  patch: { name?: string; description?: string | null },
): Promise<boolean> {
  const sets: string[] = [];
  const binds: unknown[] = [];
  if (patch.name !== undefined) {
    sets.push('name = ?');
    binds.push(patch.name);
  }
  if (patch.description !== undefined) {
    sets.push('description = ?');
    binds.push(patch.description);
  }
  sets.push('updated_at = ?');
  binds.push(Date.now());
  binds.push(watchlistId);

  const res = await db
    .prepare(`UPDATE watchlist SET ${sets.join(', ')} WHERE watchlist_id = ?`)
    .bind(...binds)
    .run();
  return (res.meta.changes ?? 0) > 0;
}

/** Returns false if the watchlist doesn't exist. CASCADE clears subs + matches. */
export async function deleteWatchlist(db: D1Database, watchlistId: number): Promise<boolean> {
  const res = await db
    .prepare(`DELETE FROM watchlist WHERE watchlist_id = ?`)
    .bind(watchlistId)
    .run();
  return (res.meta.changes ?? 0) > 0;
}

/** Confirms a watchlist exists (for 404s before a sub-resource mutation). */
export async function watchlistExists(db: D1Database, watchlistId: number): Promise<boolean> {
  const row = await db
    .prepare(`SELECT 1 AS x FROM watchlist WHERE watchlist_id = ?`)
    .bind(watchlistId)
    .first<{ x: number }>();
  return row !== null;
}

export interface AddSubscriptionResult {
  subscriptionId: number;
  backfilledMatches: number;
}

/**
 * Add a vendor/product subscription AND immediately backfill matches for it,
 * so the user sees affected CVEs right away rather than waiting for the next
 * reconciliation run to touch a modified CVE. The backfill is a one-shot
 * targeted scan bounded by BACKFILL_VENDOR_LIMIT (a single vendor's CPE rows),
 * independent of the incremental cursor the ingest engine uses.
 *
 * Idempotent on re-add (UNIQUE index); returns the existing row's id if the
 * exact (vendor, product) subscription already exists.
 */
export async function addSubscription(
  db: D1Database,
  watchlistId: number,
  vendor: string,
  product: string | null,
): Promise<AddSubscriptionResult> {
  const now = Date.now();

  // Upsert the subscription (the UNIQUE index treats NULL product as distinct
  // from any concrete product, which is the intended "all products" row).
  await db
    .prepare(
      `INSERT INTO watchlist_subscription (watchlist_id, vendor, product, created_at)
       VALUES (?, ?, ?, ?)
       ON CONFLICT (watchlist_id, vendor, product) DO NOTHING`,
    )
    .bind(watchlistId, vendor, product, now)
    .run();

  const subRow = await db
    .prepare(
      `SELECT subscription_id FROM watchlist_subscription
       WHERE watchlist_id = ? AND vendor = ? AND product IS ?`,
    )
    .bind(watchlistId, vendor, product)
    .first<{ subscription_id: number }>();
  if (!subRow) throw new Error('subscription upsert returned no id');

  // Targeted backfill: find CVEs whose CPEs match this subscription NOW, and
  // insert 'NEW' matches for any not already tracked. One read + one batched
  // write — bounded by BACKFILL_VENDOR_LIMIT, so a pathologically prolific
  // vendor can't blow the request's work budget (the remainder gets picked up
  // incrementally by the ingest reconciliation engine as those CVEs change).
  const productClause = product === null ? '' : 'AND p.product = ?';
  const binds: unknown[] = [vendor];
  if (product !== null) binds.push(product);
  binds.push(BACKFILL_VENDOR_LIMIT);

  const cveRes = await db
    .prepare(
      `SELECT DISTINCT p.cve_id
       FROM cpe p
       WHERE p.vendor = ? ${productClause}
       LIMIT ?`,
    )
    .bind(...binds)
    .all<{ cve_id: string }>();

  const cveIds = cveRes.results.map((r) => r.cve_id);
  if (cveIds.length === 0) return { subscriptionId: subRow.subscription_id, backfilledMatches: 0 };

  // Batched insert of matches (ON CONFLICT DO NOTHING preserves any existing
  // triage). db.batch counts as one query regardless of statement count.
  const WRITE_SUB_BATCH = 500;
  for (let i = 0; i < cveIds.length; i += WRITE_SUB_BATCH) {
    const chunk = cveIds.slice(i, i + WRITE_SUB_BATCH);
    await db.batch(
      chunk.map((cveId) =>
        db
          .prepare(
            `INSERT INTO watchlist_match
               (watchlist_id, cve_id, status, first_matched_at, status_updated_at)
             VALUES (?, ?, 'NEW', ?, ?)
             ON CONFLICT (watchlist_id, cve_id) DO NOTHING`,
          )
          .bind(watchlistId, cveId, now, now),
      ),
    );
  }

  return { subscriptionId: subRow.subscription_id, backfilledMatches: cveIds.length };
}

/** Returns false if the subscription doesn't exist on that watchlist.
 *  Leaves already-materialized matches in place (an analyst's triage history
 *  shouldn't vanish because a subscription was removed; stale matches age out
 *  with their CVEs). */
export async function removeSubscription(
  db: D1Database,
  watchlistId: number,
  subscriptionId: number,
): Promise<boolean> {
  const res = await db
    .prepare(`DELETE FROM watchlist_subscription WHERE subscription_id = ? AND watchlist_id = ?`)
    .bind(subscriptionId, watchlistId)
    .run();
  return (res.meta.changes ?? 0) > 0;
}

export async function addWebhook(
  db: D1Database,
  watchlistId: number,
  url: string,
  kind: 'generic' | 'slack',
): Promise<number> {
  const row = await db
    .prepare(
      `INSERT INTO watchlist_webhook (watchlist_id, kind, url, enabled, created_at)
       VALUES (?, ?, ?, 1, ?) RETURNING webhook_id`,
    )
    .bind(watchlistId, kind, url, Date.now())
    .first<{ webhook_id: number }>();
  if (!row) throw new Error('webhook insert returned no id');
  return row.webhook_id;
}

/** Returns false if the webhook doesn't exist on that watchlist. */
export async function removeWebhook(
  db: D1Database,
  watchlistId: number,
  webhookId: number,
): Promise<boolean> {
  const res = await db
    .prepare(`DELETE FROM watchlist_webhook WHERE webhook_id = ? AND watchlist_id = ?`)
    .bind(webhookId, watchlistId)
    .run();
  return (res.meta.changes ?? 0) > 0;
}

/** Update a match's triage status and/or note. Returns false if no such match. */
export async function updateMatch(
  db: D1Database,
  watchlistId: number,
  cveId: string,
  patch: { status?: WatchlistMatchStatus; note?: string | null },
): Promise<boolean> {
  const sets: string[] = [];
  const binds: unknown[] = [];
  if (patch.status !== undefined) {
    sets.push('status = ?', 'status_updated_at = ?');
    binds.push(patch.status, Date.now());
  }
  if (patch.note !== undefined) {
    sets.push('note = ?');
    binds.push(patch.note);
  }
  binds.push(watchlistId, cveId);

  const res = await db
    .prepare(`UPDATE watchlist_match SET ${sets.join(', ')} WHERE watchlist_id = ? AND cve_id = ?`)
    .bind(...binds)
    .run();
  return (res.meta.changes ?? 0) > 0;
}
