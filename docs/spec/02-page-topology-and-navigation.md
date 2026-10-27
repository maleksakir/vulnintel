# Section 2 — Application Page Topology & Navigational Fabric (v2)

This section defines the SvelteKit 2 route layout, the data each route
consumes, the navigation graph between routes, and the per-route loading
and error patterns. It assumes the 24-month rolling history window with
hard-delete aging policy locked in the decision sheet.

---

## 2.1 Route Map

Five user-facing routes plus one admin route. All live under `apps/app`.

| Route                     | Purpose                                  | Primary data sources                          |
|---------------------------|------------------------------------------|-----------------------------------------------|
| `/`                       | Live Intelligence Dashboard              | Analytics Engine aggregates, D1 totals        |
| `/search`                 | Hybrid Search Portal                     | D1 FTS5, Vectorize, D1 join for hydration     |
| `/cve/[id]`               | Vulnerability Profile Detail             | D1 (cve + cwe + cpe + state + references)     |
| `/affected-products`      | Vendor Impact Matrix                     | D1 (cpe join with cve, paginated)             |
| `/threat-intel`           | Active Exploitation Monitor              | D1 (cve_state KEV + EPSS), Analytics Engine   |
| `/admin/health`           | Ingest health & operational status       | D1 (counts), KV (last-run markers)            |

The admin route is the only one protected by an additional `ADMIN_BEARER`
header check on top of the IP allowlist.

---

## 2.2 Page Architectural Profiles

### 2.2.1 `/` — Live Intelligence Dashboard

**Layout grid (12-column at desktop, 4-column at < 900px):**

- Row 1: four KPI cards — Total CVEs in window, Critical count, KEV-listed
  count, Mean EPSS percentile (last 7 days).
- Row 2: Severity distribution stacked bar (90-day) + Publication velocity
  line chart (90-day daily) side by side.
- Row 3: Top-10 vendors by CVE count (horizontal bar) + Top-10 vendors by
  KEV count (horizontal bar) side by side.
- Row 4: KEV inflow timeline (90-day) full width.

**Server `load`** returns only the four KPI scalars synchronously plus four
`Promise`s for the charts. Charts render placeholders until their data
resolves (streamed SSR pattern). KPI scalars are cached in KV for 5 minutes.

**Interactivity:** every chart slice, bar, and timeline marker is a clickable
link with a deterministic target route (see 2.3). No client-side filter
modals on this page — drilldowns happen on the destination route.

### 2.2.2 `/search` — Hybrid Search Portal

**Search pipeline (each query):**

1. Exact-match short circuit — input matches `^CVE-\d{4}-\d{4,7}$` →
   client-side redirect to `/cve/<id>`.
2. Server `load` invokes the shared `searchCves` query module (Section 5) directly with the parsed query, active filters, and environment bindings.
3. Server returns up to 50 results in one shot — no pagination cursor.
   Cursor-based pagination over fused vector + lexical results is unstable;
   we cap at 50 and tell the user to refine.

**Layout:**

- Top: Combobox (Bits UI primitive) with debounced submission (250 ms).
- Left rail: filter panel — severity multi-select, KEV toggle, vendor
  multi-select (suggestions from D1 distinct vendors), CVSS minimum slider,
  published-since date picker, "include description-only matches" toggle.
- Main: result list — each row shows CVE ID, severity badge, KEV/EPSS pills,
  CVSS, vendor, snippet of description with the matched FTS5 span
  highlighted.
- Footer: "Up to 50 results shown. Refine to narrow."

**URL state:** every filter and the query string serialise into the URL
query parameters so results are shareable. The browser back button restores
filter chips and scroll position via SvelteKit's `pageState`.

### 2.2.3 `/cve/[id]` — Vulnerability Profile Detail

**Validation:** the `id` param is matched against `^CVE-\d{4}-\d{4,7}$` in a
`+page.server.ts` `load` guard. Invalid ID → 400 with the standard error
boundary. If the CVE does not exist in the database (either never existed or aged-out), return `404 CVE_NOT_FOUND` with the standard error boundary, including a link to the NVD's canonical record for that CVE ID.

**Layout (single column, max-width 960px):**

- Sticky header band: CVE ID, severity badge, CVSS base score, KEV pill,
  EPSS percentile pill, published / last-modified timestamps.
- Body sections (Bits UI Tabs primitive):
  - **Overview** — full description, references list.
  - **CVSS** — vector breakdown table (AV, AC, PR, UI, S, C, I, A) with
    inline tooltips explaining each metric.
  - **CWE** — chain of weakness IDs with hover descriptions. If a CWE name is null, fall back to displaying the raw CWE ID and omit the hover tooltip description.
  - **Affected products** — table of CPE rows with vendor, product, version
    range; each row links to `/affected-products?vendor=...&product=...`.
  - **Provenance** — ingestion timestamps per source from `cve_source_provenance` table, embedding hash.

**Streaming SSR:** the header band and Overview tab render synchronously;
the CWE descriptions and CVSS tooltips hydrate from a streamed promise so
TTFB stays low even when the cwe table joins are slow.

### 2.2.4 `/affected-products` — Vendor Impact Matrix

**Layout:**

- Filter row: vendor combobox (server-suggested), product combobox
  (filtered by selected vendor), part selector (a/o/h), CVSS minimum.
- Main: paginated table sorted by latest CVE published. Columns: vendor,
  product, version range, CVE count, latest CVE ID, max severity.
- Pagination: cursor-based via D1 row IDs (stable). 50 rows per page.

**Why FTS5 here too:** vendor / product strings are lexically searched via
the same FTS5 virtual table the `/search` route uses, scoped to the
`cpe_search` index.

### 2.2.5 `/threat-intel` — Active Exploitation Monitor

**Two synchronised panels, switchable by Bits UI Tabs:**

- **KEV panel** (default): table of all CVEs with `kev_listed = 1` regardless
  of age (KEV entries are retained outside the 24-month window — see
  decision sheet). Columns: CVE ID, severity, vendor, KEV date added, KEV
  due date, required action snippet.
- **EPSS panel:** leaderboard of top-200 CVEs by EPSS score within the active
  window. Columns: CVE ID, severity, vendor, EPSS score, EPSS percentile,
  CVSS base.

**Velocity strip** above the panels: 30-day rolling count of new KEV entries
and 30-day mean EPSS shift, sourced from Analytics Engine.

### 2.2.6 `/admin/health`

**Access control:** The Svelte page loads and prompts the user to enter the admin token (stored in `sessionStorage`). The page then makes a client-side `fetch` to the JSON endpoint `/api/admin/health` (Section 5.2.7) passing the token in the `Authorization: Bearer <ADMIN_BEARER>` header. If the API returns a 403, the page renders a login prompt. The route is otherwise reachable only from the corp IP allowlist (Section 4).

**Content (read-only, no actions on this page):**

- Last successful ingest timestamp per source (NVD, MITRE, KEV, EPSS) with
  staleness colour coding (green < 26h, amber 26–48h, red > 48h).
- D1 row counts: cve, cpe, cve_state, cve_reference, cve_cwe.
- Vectorize index size (approximate, from last-run marker).
- Aging sweep last-run timestamp and number of records purged in the last
  sweep.
- Quarantine table size (records that failed normalization).
- Retry queue depth and DLQ depth.
- Active rate-limit blocks in the last hour, grouped by IP.

---

## 2.3 Inter-Page Navigation Matrix

All cross-route links use SvelteKit's `<a href="...">` with the framework's
client-side routing. The URL is the canonical state container; no global
client store is shared across routes.

| From → To                                | Trigger                                   | URL pattern                                                         |
|------------------------------------------|-------------------------------------------|---------------------------------------------------------------------|
| `/` → `/search`                          | Click on a severity bar segment           | `/search?severity=<level>`                                          |
| `/` → `/search`                          | Click on a vendor bar                     | `/search?vendor=<vendor>`                                           |
| `/` → `/threat-intel`                    | Click on KEV inflow timeline              | `/threat-intel?view=kev&since=<isoDate>`                            |
| `/search` → `/cve/[id]`                  | Click on a result row                     | `/cve/<id>`                                                         |
| `/search` → `/affected-products`         | Click a vendor chip in result row         | `/affected-products?vendor=<vendor>`                                |
| `/cve/[id]` → `/affected-products`       | Click on an affected product row          | `/affected-products?vendor=<v>&product=<p>`                         |
| `/cve/[id]` → `/search`                  | Click "more like this" affordance         | `/search?similarTo=<id>` (uses Vectorize neighbour query)           |
| `/affected-products` → `/cve/[id]`       | Click latest CVE ID in a row              | `/cve/<id>`                                                         |
| `/affected-products` → `/search`         | Click "show all CVEs for this vendor"     | `/search?vendor=<v>`                                                |
| `/threat-intel` → `/cve/[id]`            | Click on CVE ID in table                  | `/cve/<id>`                                                         |
| `/threat-intel` → `/search`              | Click "show in search context"            | `/search?kev=true&vendor=<v>`                                       |

**Back-button behaviour:** every list-to-detail transition captures the
scroll position in `history.state` so the back button restores it. Bits UI
combobox state and filter chip state are URL-driven, so they restore
deterministically without extra plumbing.

**Hash-fragment usage:** restricted to in-page tab selection on `/cve/[id]`
(e.g. `/cve/CVE-2026-12345#cwe`). The fragment is preserved through SvelteKit
navigation.

---

## 2.4 Layout Shell

A single root `+layout.svelte` owns the persistent UI chrome. It is the only
component that renders outside the page slot.

**Slots and regions:**

- Header band — logo, primary nav (Dashboard, Search, Affected Products,
  Threat Intel), theme toggle.
- Main `<slot />` — the active route's content.
- Toast region — Bits UI Toast container, anchored bottom-right; receives
  rate-limit warnings, ingestion-success notifications (admin only), and
  generic error toasts.
- Skip-link — first focusable element, jumps to `#main-content`.

**Reactive globals exposed via context (not stores):**

- `auditIdentity` — the IP-derived audit context (`cf-connecting-ip`,
  `cf-ray`). There is no user identity in the IP-only auth model.
- `theme` — `'light' | 'dark'`, persisted in `localStorage`.
- `rateLimitStatus` — populated from response headers on every fetch.

---

## 2.5 Loading & Streaming Patterns

### 2.5.1 Server `load` discipline

Every `+page.server.ts` `load` returns:

- Synchronous fields needed for first paint (header content, KPI scalars,
  initial 20 rows of a table).
- Promises in the streamed shape for secondary content (charts,
  computed-heavy panels, supplementary tabs).

This is the SvelteKit pattern that ships TTFB with the page header while the
client-side render awaits the streamed promises and progressively fills
their containers.

### 2.5.2 Client `load`

Used only for explicitly user-initiated fetches that should not delay first
paint: re-fetching a chart after a filter change, prefetching the next page
in a paginated table on hover, and live polling on `/admin/health`.

### 2.5.3 Skeleton states

Each placeholder is a pure-CSS skeleton block using a single shared utility
class `.skeleton` defined in `app.css`. No JavaScript animation library.

---

## 2.6 Error Boundaries

`+error.svelte` lives at the root and at each route. The root boundary
covers transport and unhandled errors; route boundaries cover route-specific
cases.

| Status / code              | Boundary content                                                                     |
|----------------------------|--------------------------------------------------------------------------------------|
| 400 `VALIDATION_ERROR`     | "Invalid input" with the failing field name. Back-to-previous-page button.           |
| 403 `FORBIDDEN_NETWORK`    | "This network is not on the access list. Contact security@…" Network detail hidden.  |
| 404 `CVE_NOT_FOUND`        | "CVE not found or outside active 24-month window." Search affordance + direct NVD link. |
| 429 `RATE_LIMITED`         | "Rate limit reached. Retry in N seconds." Live countdown bound to `retryAfterSeconds`.|
| 5xx `UPSTREAM_FAILURE`     | "A backend service is unavailable. Check `/admin/health`." Retry button.             |

**429 special case:** the toast region in the layout shell also surfaces a
toast when a non-blocking request (background prefetch, chart refresh) hits a
rate limit. The page itself remains usable.

---

## 2.7 Caching Strategy (per-route)

Caching uses two layers: the Cloudflare **Cache API** for SSR responses and
the **KV `CACHE` namespace** for shared computed payloads.

| Route                  | Cache layer | TTL        | Key pattern                              | Invalidation trigger                             |
|------------------------|-------------|------------|------------------------------------------|--------------------------------------------------|
| `/`                    | KV          | 5 min      | `dash:kpi:<window>`                      | Ingest worker writes a fresh KPI snapshot daily  |
| `/`                    | Cache API   | 60 s       | full URL                                 | Stale-while-revalidate                           |
| `/search`              | none        | —          | —                                        | Per-query, per-user — never cached               |
| `/cve/[id]`            | KV          | 1 h        | `cve:<id>`                               | Cleared by ingest worker on record update        |
| `/affected-products`   | Cache API   | 5 min      | full URL                                 | Stale-while-revalidate                           |
| `/threat-intel`        | KV          | 15 min     | `threat:kev:list` and `threat:epss:top`  | Cleared by KEV / EPSS sub-cron                   |
| `/admin/health`        | none        | —          | —                                        | Always live                                      |

**Cache invalidation hook:** the ingest worker maintains a side-channel KV
key per logical entity (`cve:<id>`, `dash:kpi:*`, `threat:*`). When a record
changes, it deletes the relevant keys at the end of its transaction. The app
worker therefore never serves a stale page for a record the ingest worker
has touched in the same minute.

---

## 2.8 Accessibility & Responsiveness Floor

- All Bits UI primitives are configured with their default ARIA wiring; we
  do not override `aria-*` attributes that the library sets unless adding
  additional context.
- Keyboard reachability: every interactive element is focusable and operable
  with `Tab`, `Shift+Tab`, `Enter`, `Space`, and `Escape`. Custom roving
  tabindex only inside hand-rolled `SortableTable` and `Pagination`.
- Colour contrast: the token layer (Section 1) defines pairs that meet WCAG
  AA at minimum. The dark theme is checked separately.
- Responsive floor: 1024 px wide. The app targets SOC analyst desktops; we
  do not optimise for phones. Tablets (768–1023 px) get a working but
  vertically stacked layout. Below 768 px, a "best viewed on desktop" banner
  is shown but the app remains operable.

---

## 2.9 Section 2 Deliverable Order

These steps execute inside Phase 5 of the master plan and assume Phases 1–4
are complete.

1. Build the root `+layout.svelte` with the persistent shell described in
   2.4. Verify the skip-link, theme toggle, and toast region work in
   isolation.
2. Implement `/` with placeholder data and the four-row grid. Wire the KPI
   cards to a stub returning fixed numbers, then to `/api/metrics/24h`.
3. Implement `/cve/[id]` with the streaming pattern in 2.2.3. Verify the
   sticky header renders before the body sections finish loading.
4. Implement `/search` with the hybrid pipeline. Verify exact-match
   short-circuit, FTS5 highlighting, and URL state restoration.
5. Implement `/affected-products` with cursor pagination.
6. Implement `/threat-intel` with the two-panel layout.
7. Implement `/admin/health`. Verify the admin bearer gate.
8. Author all six error boundary files.
9. Run the end-to-end navigation flow: `/` → severity click → `/search` →
   row click → `/cve/[id]` → vendor click → `/affected-products` → row click
   → `/cve/[id]` → back → back → back. Confirm scroll restoration and
   filter state restoration at every step.
