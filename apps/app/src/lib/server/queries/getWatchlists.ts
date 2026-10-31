import type {
  WatchlistDetailResponse,
  WatchlistListResponse,
  WatchlistMatch,
  WatchlistMatchCounts,
  WatchlistMatchStatus,
  WatchlistSubscription,
  WatchlistSummary,
} from '@threat-lens/contracts';

// Read-side queries for watchlists. All rows are materialized by the ingest
// worker's reconciliation engine (watchlist_match); these are cheap indexed
// reads, never the heavy cpe×cve join — that cost lives in the ingest
// consumer, by design (see the Phase 3 design doc).

const EMPTY_COUNTS: WatchlistMatchCounts = {
  NEW: 0,
  TRIAGING: 0,
  ACKNOWLEDGED: 0,
  RESOLVED: 0,
  IGNORED: 0,
};

const MATCH_PAGE_SIZE = 100;

interface WatchlistRow {
  watchlist_id: number;
  name: string;
  description: string | null;
  created_at: number;
  updated_at: number;
}

interface CountRow {
  watchlist_id: number;
  status: WatchlistMatchStatus;
  n: number;
}

interface SubscriptionRow {
  subscription_id: number;
  vendor: string;
  product: string | null;
  created_at: number;
}

interface MatchRow {
  cve_id: string;
  status: WatchlistMatchStatus;
  note: string | null;
  first_matched_at: number;
  status_updated_at: number;
  severity: string | null;
  cvss_base: number | null;
  kev_listed: number | null;
  epss_percentile: number | null;
}

function emptyCounts(): WatchlistMatchCounts {
  return { ...EMPTY_COUNTS };
}

/** GET /api/watchlists — all watchlists with subscription + per-status match
 *  counts. Two aggregate reads (watchlists, grouped counts) + one grouped
 *  subscription-count read, assembled in memory. Bounded by the number of
 *  watchlists (a human-managed, small set), not by match volume. */
export async function getWatchlists(db: D1Database): Promise<WatchlistListResponse> {
  const [wlRes, countRes, subRes] = await db.batch([
    db.prepare(
      `SELECT watchlist_id, name, description, created_at, updated_at
       FROM watchlist ORDER BY created_at ASC`,
    ),
    db.prepare(
      `SELECT watchlist_id, status, COUNT(*) AS n
       FROM watchlist_match GROUP BY watchlist_id, status`,
    ),
    db.prepare(
      `SELECT watchlist_id, COUNT(*) AS n
       FROM watchlist_subscription GROUP BY watchlist_id`,
    ),
  ]);

  const countsByWl = new Map<number, WatchlistMatchCounts>();
  for (const c of (countRes as D1Result<CountRow>).results) {
    let counts = countsByWl.get(c.watchlist_id);
    if (!counts) {
      counts = emptyCounts();
      countsByWl.set(c.watchlist_id, counts);
    }
    counts[c.status] = c.n;
  }

  const subCountByWl = new Map<number, number>();
  for (const s of (subRes as D1Result<{ watchlist_id: number; n: number }>).results) {
    subCountByWl.set(s.watchlist_id, s.n);
  }

  const watchlists: WatchlistSummary[] = (wlRes as D1Result<WatchlistRow>).results.map((w) => ({
    watchlistId: w.watchlist_id,
    name: w.name,
    description: w.description,
    createdAt: new Date(w.created_at).toISOString(),
    updatedAt: new Date(w.updated_at).toISOString(),
    subscriptionCount: subCountByWl.get(w.watchlist_id) ?? 0,
    matchCounts: countsByWl.get(w.watchlist_id) ?? emptyCounts(),
  }));

  return { watchlists };
}

/** GET /api/watchlists/[id] — one watchlist with its subscriptions and a page
 *  of matches (filterable by status, cursor-paginated by status_updated_at
 *  DESC). Returns null if the watchlist doesn't exist. */
export async function getWatchlistDetail(
  db: D1Database,
  watchlistId: number,
  opts: { status?: WatchlistMatchStatus; cursor?: string; limit?: number } = {},
): Promise<WatchlistDetailResponse | null> {
  const limit = Math.min(opts.limit ?? MATCH_PAGE_SIZE, MATCH_PAGE_SIZE);

  const wl = await db
    .prepare(
      `SELECT watchlist_id, name, description, created_at, updated_at
       FROM watchlist WHERE watchlist_id = ?`,
    )
    .bind(watchlistId)
    .first<WatchlistRow>();
  if (!wl) return null;

  // Subscriptions + per-status counts in one batch.
  const [subRes, countRes] = await db.batch([
    db
      .prepare(
        `SELECT subscription_id, vendor, product, created_at
         FROM watchlist_subscription WHERE watchlist_id = ?
         ORDER BY vendor ASC, product ASC`,
      )
      .bind(watchlistId),
    db
      .prepare(
        `SELECT watchlist_id, status, COUNT(*) AS n
         FROM watchlist_match WHERE watchlist_id = ? GROUP BY status`,
      )
      .bind(watchlistId),
  ]);

  const subscriptions: WatchlistSubscription[] = (subRes as D1Result<SubscriptionRow>).results.map(
    (s) => ({
      subscriptionId: s.subscription_id,
      vendor: s.vendor,
      product: s.product,
      createdAt: new Date(s.created_at).toISOString(),
    }),
  );

  const matchCounts = emptyCounts();
  for (const c of (countRes as D1Result<CountRow>).results) matchCounts[c.status] = c.n;

  // Decode cursor: base64 of the status_updated_at ms of the last row seen.
  let cursorMs: number | null = null;
  if (opts.cursor) {
    try {
      cursorMs = Number.parseInt(atob(opts.cursor), 10);
      if (!Number.isFinite(cursorMs)) cursorMs = null;
    } catch {
      cursorMs = null;
    }
  }

  const bindings: unknown[] = [watchlistId];
  const where: string[] = ['m.watchlist_id = ?'];
  if (opts.status) {
    where.push('m.status = ?');
    bindings.push(opts.status);
  }
  if (cursorMs !== null) {
    where.push('m.status_updated_at < ?');
    bindings.push(cursorMs);
  }
  bindings.push(limit + 1);

  // Matches joined to cve/cve_state for the denormalized summary. LEFT JOIN so
  // a match whose CVE has aged out (hard-deleted) still renders — with null
  // severity/cvss/etc. — rather than vanishing from the analyst's view.
  const matchRes = await db
    .prepare(
      `SELECT m.cve_id, m.status, m.note, m.first_matched_at, m.status_updated_at,
              c.severity, c.cvss_base,
              s.kev_listed, s.epss_percentile
       FROM watchlist_match m
       LEFT JOIN cve c ON c.cve_id = m.cve_id
       LEFT JOIN cve_state s ON s.cve_id = m.cve_id
       WHERE ${where.join(' AND ')}
       ORDER BY m.status_updated_at DESC
       LIMIT ?`,
    )
    .bind(...bindings)
    .all<MatchRow>();

  const rows = matchRes.results;
  const hasMore = rows.length > limit;
  const page = hasMore ? rows.slice(0, limit) : rows;

  const matches: WatchlistMatch[] = page.map((m) => ({
    cveId: m.cve_id,
    status: m.status,
    note: m.note,
    firstMatchedAt: new Date(m.first_matched_at).toISOString(),
    statusUpdatedAt: new Date(m.status_updated_at).toISOString(),
    severity: (m.severity as WatchlistMatch['severity']) ?? null,
    cvssBase: m.cvss_base,
    kevListed: m.kev_listed === 1,
    epssPercentile: m.epss_percentile,
  }));

  let nextCursor: string | null = null;
  if (hasMore) {
    const last = page[page.length - 1];
    if (last) nextCursor = btoa(String(last.status_updated_at));
  }

  return {
    watchlistId: wl.watchlist_id,
    name: wl.name,
    description: wl.description,
    createdAt: new Date(wl.created_at).toISOString(),
    updatedAt: new Date(wl.updated_at).toISOString(),
    subscriptions,
    matchCounts,
    matches,
    nextCursor,
  };
}
