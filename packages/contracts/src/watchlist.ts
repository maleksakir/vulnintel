/**
 * Watchlist contracts (Phase 3 — the core differentiator). Shared between the
 * app worker (API + UI) and the ingest worker (match reconciliation). Backed
 * by migrations/0009_watchlists.sql.
 *
 * TYPE-ONLY — no runtime code.
 *
 * Single-tenant by design: the spec locks IP-allowlist-only auth with no user
 * identity (docs/spec/00, 02), so there is no org/user to scope these to.
 * Multi-tenancy, if ever needed, is an additive column later — see the Phase 3
 * design doc and 0009's header.
 */

/** Triage status pipeline for a CVE matched into a watchlist. */
export type WatchlistMatchStatus = 'NEW' | 'TRIAGING' | 'ACKNOWLEDGED' | 'RESOLVED' | 'IGNORED';

/** Terminal statuses — a decided match; eligible for aging-tail cleanup once
 *  its CVE has been hard-deleted from the 24-month window. */
export const WATCHLIST_TERMINAL_STATUSES: readonly WatchlistMatchStatus[] = ['RESOLVED', 'IGNORED'];

/** A vendor/product subscription. `product: null` means "all products for
 *  this vendor". Vendor/product are stored lowercase to match NVD's
 *  normalization of `cpe.vendor`/`cpe.product`. */
export interface WatchlistSubscription {
  subscriptionId: number;
  vendor: string;
  product: string | null;
  createdAt: string; // ISO 8601 at the API boundary
}

/** One matched CVE's triage record within a watchlist. */
export interface WatchlistMatch {
  cveId: string;
  status: WatchlistMatchStatus;
  note: string | null;
  firstMatchedAt: string; // ISO 8601
  statusUpdatedAt: string; // ISO 8601
  /** Denormalized CVE summary for list rendering (from the cve row if it still
   *  exists; null when the CVE has aged out but the match was retained). */
  severity: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | null;
  cvssBase: number | null;
  kevListed: boolean;
  epssPercentile: number | null;
}

/** Per-status match counts for a watchlist (list-view badges). */
export interface WatchlistMatchCounts {
  NEW: number;
  TRIAGING: number;
  ACKNOWLEDGED: number;
  RESOLVED: number;
  IGNORED: number;
}

/** A watchlist as returned in the list view (summary form). */
export interface WatchlistSummary {
  watchlistId: number;
  name: string;
  description: string | null;
  createdAt: string; // ISO 8601
  updatedAt: string; // ISO 8601
  subscriptionCount: number;
  matchCounts: WatchlistMatchCounts;
}

/** GET /api/watchlists */
export interface WatchlistListResponse {
  watchlists: WatchlistSummary[];
}

/** GET /api/watchlists/[id] — full detail with subscriptions + a page of
 *  matches (cursor-paginated by status_updated_at DESC). */
export interface WatchlistDetailResponse {
  watchlistId: number;
  name: string;
  description: string | null;
  createdAt: string; // ISO 8601
  updatedAt: string; // ISO 8601
  subscriptions: WatchlistSubscription[];
  matchCounts: WatchlistMatchCounts;
  matches: WatchlistMatch[];
  nextCursor: string | null;
}

/** POST /api/watchlists */
export interface CreateWatchlistRequest {
  name: string;
  description?: string;
}

/** PATCH /api/watchlists/[id] */
export interface UpdateWatchlistRequest {
  name?: string;
  description?: string | null;
}

/** POST /api/watchlists/[id]/subscriptions */
export interface CreateSubscriptionRequest {
  vendor: string;
  product?: string | null;
}

/** PATCH /api/watchlists/[id]/matches/[cveId] */
export interface UpdateMatchRequest {
  status?: WatchlistMatchStatus;
  note?: string | null;
}
