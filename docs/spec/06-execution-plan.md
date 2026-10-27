# Section 6 — Developer Agent Execution Plan (v2)

This section is the implementer's checklist. It sequences the work into
six phases with explicit goals, deliverables, acceptance criteria, and
exit gates. Each phase ends with a hard checkpoint; the next phase does
not begin until every acceptance criterion in the current phase passes.

The phases assume a single full-time implementer or pair. Effort estimates
are calendar-day ranges for a focused build, not optimistic floors.

---

## Phase 1 — Bootstrapping & Perimeter Lock

**Goal:** stand up an empty, IP-restricted shell of both workers with all
network controls in place before any application logic exists.

**Effort:** 3–5 days.

### Deliverables

1. Workspace skeleton per Section 1.1 (`pnpm-workspace.yaml`,
   `tsconfig.base.json`, `apps/app`, `apps/ingest`, `packages/contracts`).
2. SvelteKit 2 app scaffold in `apps/app` using `adapter-cloudflare`.
3. Empty cron worker in `apps/ingest` (`fetch`, `scheduled`, `queue`
   handlers stubbed).
4. Bits UI installed; one wrapper file per consumed primitive created in
   `apps/app/src/lib/ui/` (empty bodies).
5. Design token layer in `apps/app/src/app.css` (CSS custom properties for
   colour, type, spacing, radius, motion, z-index, in `:root` and
   `[data-theme="dark"]`).
6. Both `wrangler.toml` files (Section 1.4) with placeholder IDs.
7. Cloudflare IP List `corp_authorized_sources` created with bootstrap
   entries (Section 4.1.4).
8. Three WAF custom rules deployed (`allow_method_safe`,
   `block_method_unexpected`, `block_offlist_traffic`) per Section 4.2.2.
9. Two WAF rate-limit rules deployed (`rl_per_ip_general`,
   `rl_per_ip_admin`) per Section 4.3.1. The longer-window AI quotas
   (per-IP hourly, org-wide daily) are enforced inside the worker via
   the D1 ledger tables (Sections 3.1.1 and 5.3.7) — no WAF rule.
10. Super Bot Fight Mode + HSTS configured in dashboard (Pro plan
    feature; see Overview locked-decisions table).
11. `docs/spec/RESOURCES.md` containing all generated IDs (D1 placeholders,
    KV namespace ID, Vectorize index name, queue names, IP list ID, zone
    IDs).
12. `docs/network/whitelist-ledger.md` seeded.

### Acceptance criteria

- `pnpm install` succeeds with zero warnings.
- `wrangler deploy --dry-run` succeeds for both workers.
- From an in-list IP, `curl https://threatlens.<corp>.com/` returns the
  default SvelteKit landing page (200 OK).
- From an off-list IP (verifiable from a non-corp network), the same URL
  returns 403 with `code = "FORBIDDEN_NETWORK"` and the error envelope.
- `curl -X PUT https://threatlens.<corp>.com/` from in-list returns 405
  with `code = "METHOD_NOT_ALLOWED"`.
- A burst test issuing 31 requests in under a minute hits 429
  `RATE_LIMITED` on the 31st with `retryAfterSeconds` set.
- The ingest worker dashboard shows the five cron triggers scheduled.
- Bits UI imports compile without TS errors.

### Exit gate

Stage manager (you) confirms all seven acceptance checks above pass and
signs the entry in `docs/spec/PHASE_GATES.md`.

---

## Phase 2 — Storage Provisioning

**Goal:** apply the full D1 schema to production and staging, provision
Vectorize and Analytics Engine, and verify all bindings round-trip.

**Effort:** 2–3 days.

### Deliverables

1. Six migration files (`0001_core_tables.sql` through
   `0006_cwe_catalog_seed.sql` generated from `packages/contracts/src/cwe_catalog.json`) per Section 3.1.4.
2. Migrations applied to staging D1 via `wrangler d1 migrations apply`.
3. Migrations applied to production D1 once staging is validated.
4. Vectorize indexes created (prod + staging) per Section 3.2.1, and the six required metadata indexes (`severity`, `cvss_base`, `published_ms`, `kev_listed`, `epss_percentile`, `top_vendor`) created via Wrangler before any vectors are inserted (per Section 3.2.4).
5. Analytics Engine datasets created (prod + staging).
6. KV `CACHE` namespace created and bound to both workers.
7. Queues `cve-ingest-retry` and `cve-ingest-dlq` created.
8. All resource IDs filled into the two `wrangler.toml` files (replacing
   `REPLACE_AFTER_PROVISIONING` placeholders).
9. Five secrets configured per worker per environment
   (`NVD_API_KEY`, `ANALYTICS_QUERY_TOKEN`, `ADMIN_BEARER`, `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`).
10. A fixture script that seeds 100 representative CVEs covering every
    column, including one quarantined record and one record with all
    optional fields null.

### Acceptance criteria

- `PRAGMA table_info(<table>)` returns the expected schema for every
  table.
- `PRAGMA index_list(<table>)` confirms every index from Section 3.1.3
  exists.
- FTS5 round-trip: insert a CVE with the description "buffer overflow in
  HTTP parser", search `cve_search` for `parser`, get the row back with
  `<mark>parser</mark>` in the snippet.
- Vectorize accepts a synthetic 768-dim test vector via `insert` and
  returns it on `query` with cosine distance ~0.
- Analytics Engine accepts a canary `writeDataPoint` and the value is
  visible via the SQL HTTP API within 30 seconds.
- KV write and read succeed from both workers using their respective
  bindings.
- A test message sent to `cve-ingest-retry` from the ingest worker is
  received by the queue consumer stub.

### Exit gate

All eight verifications above pass on staging. Production D1 schema
matches staging exactly (compared via `sqlite_master` SELECT).

---

## Phase 3 — Ingestion Pipeline

**Goal:** implement and validate the end-to-end ingest path so that
real CVE data lands correctly in D1, Vectorize, KV, and Analytics.

**Effort:** 7–10 days.

### Deliverables

1. `packages/contracts/src/cve.ts` with `NormalizedCveRecord`,
   `NormalizedCpe`, `KevPatch`, `EpssPatch`, `Severity` (Section 5.1.3).
2. Source adapters in `apps/ingest/src/adapters/`:
   - `nvd.ts` (NVD CVE 2.0 API)
   - `mitre.ts` (MITRE CVE List v5)
   - `kev.ts` (CISA KEV)
   - `epss.ts` (FIRST EPSS)
   Each is a pure function with unit tests against a fixture of real
   payloads (committed to `apps/ingest/test/fixtures/`).
3. `processRecord(record, env, ctx)` covering the persistence sequence
   (Section 5.1.4), including the two-hash decision tree and quarantine
   path.
4. Per-worker `embed()` implementation in
   `apps/ingest/src/lib/server/embed.ts` matching the contract in
   Section 5.4.
5. `scheduled(event, env, ctx)` handler with the dispatch table in
   Section 5.1.1.
6. `runDailyFullDelta`, `runKevFastLane`, `runWeeklyReconciliation`,
   `runAgingSweep`, `runIpListPrune` implementations.
7. Queue consumer in the same worker, re-invoking `processRecord` on
   `RetryMessage` payloads.
8. Conformance test: invoke `embed()` from the ingest worker on a fixed
   string and compare against a snapshot vector committed to the test
   fixtures (allows detecting model drift or input drift).

### Acceptance criteria

- Triggering the daily cron in staging against a 50-record fixture
  results in:
  - 50 rows in `cve`, all CPE rows present, `cve_state` populated.
  - 50 vectors in Vectorize with correct metadata.
  - Five `INGEST` Analytics Engine events visible.
  - One `ingest_run` row with status `OK` and `records_processed = 50`.
- Re-triggering the same cron with the same payload produces zero new
  writes (no D1 changes, no AI calls, no Vectorize upserts) — confirms
  hash short-circuit works.
- Injecting one malformed record into the fixture produces one new row
  in `cve_quarantine` and 49 successful records — confirms partial-batch
  resilience.
- Forcing a Vectorize 5xx in the test harness for one record produces
  one `RetryMessage` in `cve-ingest-retry` and 49 successful records.
- The aging sweep correctly leaves KEV-listed records older than 24
  months intact while removing non-KEV records older than 24 months.
- The EPSS orphan path: send an EPSS update for an unknown CVE; verify one `cve_quarantine` row with `error_code = 'ORPHAN_STATE'` is written.
- The KEV orphan path: send a KEV update for an unknown CVE; verify that the worker triggers an upstream targeted fetch, inserts the base CVE record, and applies the KEV properties setting `kev_listed = 1` in `cve_state` inside a single atomic D1 transaction.

### Exit gate

Run the daily cron three times across a 24-hour period in staging. After
24 hours: zero unexpected DLQ messages, zero quarantine entries beyond
those intentionally seeded, `ingest_run` shows OK for every source.

---

## Phase 4 — Gateway API

**Goal:** implement the seven public API endpoints plus `/api/admin/health`
behind the perimeter, with full cache integration and audit logging.

**Effort:** 5–7 days.

### Deliverables

1. `apps/app/src/lib/server/validate/` — one type guard per endpoint.
2. `apps/app/src/lib/server/cacheRead.ts` — the KV-backed read-through
   helper.
3. `apps/app/src/lib/server/embed.ts` — the app worker's `embed()`
   implementation (matches ingest implementation byte-for-byte).
4. `apps/app/src/hooks.server.ts` — central audit log writer, request
   context, error envelope translation, cache header setter.
5. Seven `/api/*` server endpoints per Section 5.2:
   - `GET /api/cve/[id]`
   - `POST /api/search` (full hybrid pipeline including `similarTo`)
   - `GET /api/affected-products`
   - `GET /api/threat-intel/kev`
   - `GET /api/threat-intel/epss`
   - `GET /api/metrics/[window]`
6. `GET /api/admin/health` server endpoint with bearer gate.
7. Integration tests using `vitest` against the staging worker that
   assert response shapes, error envelopes, and audit log writes.

### Acceptance criteria

- Every endpoint returns a response matching its contract for the happy
  path against the Phase 3 seed data.
- `GET /api/cve/CVE-9999-99999` returns 404 with `code = "CVE_NOT_FOUND"`.
- `GET /api/cve/<id>` for a non-KEV CVE published >24 months ago (which was hard-deleted by the aging sweep) returns 404 with `code = "CVE_NOT_FOUND"`.
- `POST /api/search {query: "CVE-2026-12345"}` short-circuits to a single
  result with that exact id.
- `POST /api/search {query: "buffer overflow http"}` returns fused
  results with FTS5 snippets where the lexical layer matched, and
  fallback snippets where only the vector layer matched.
- `POST /api/search` with `vendor: ["apache", "nginx"]` returns only
  results whose CPE table contains one of those vendors.
- `POST /api/search` per-IP hourly quota exceeded → 429 envelope with
  correct `retryAfterSeconds`; org-wide daily quota exceeded → 503
  `GLOBAL_QUOTA_EXHAUSTED` envelope with correct `retryAfterSeconds`.
- `GET /api/admin/health` without bearer → 403; with valid bearer → 200 with
  populated counts.
- `audit_log` contains one row per audited request, with no rows for
  unaudited paths.
- KV cache hits avoid the underlying D1 query (verifiable by tail logs).
- Ingest worker updates to a CVE invalidate the corresponding KV cache
  key within the same minute.

### Exit gate

Run the full integration test suite green. Confirm tail logs show no
unexpected error logs during a 30-minute exercise.

---

## Phase 5 — SvelteKit UI

**Goal:** build the five user routes plus `/admin/health` with the
streaming patterns, error boundaries, and Bits UI primitives wired in.

**Effort:** 8–12 days.

### Deliverables

1. Root `+layout.svelte` with navigation, theme toggle, toast region,
   skip-link, and the `auditIdentity` context (Section 2.4).
2. Five Bits UI wrappers in `apps/app/src/lib/ui/` populated:
   `Modal.svelte`, `SearchCombobox.svelte`, `Tabs.svelte`,
   `Tooltip.svelte`, `Select.svelte`, `Toast.svelte`.
3. Hand-rolled primitives: `Accordion.svelte`, `Pagination.svelte`,
   `SortableTable.svelte`, `SkipLink.svelte`, `Badge.svelte`,
   `VisuallyHidden.svelte`.
4. Five route implementations:
   - `/` — four-row dashboard grid with streaming charts.
   - `/search` — combobox + filter rail + result list, exact-match
     short circuit, URL-driven state, `truncated` banner.
   - `/cve/[id]` — sticky header + tabbed body with streaming SSR.
   - `/affected-products` — filter row + cursor-paginated table.
   - `/threat-intel` — tabbed KEV / EPSS panels.
5. `/admin/health` route with bearer header check on the client side
   (token entered manually by admin, stored in `sessionStorage`).
6. Six error boundary files mapping every `ErrorEnvelope.code` to a
   contextual UI (Section 2.6).
7. CSS for every component, scoped, referencing only the token layer.
8. Light + dark theme verified across all pages.

### Acceptance criteria

- End-to-end navigation flow passes manually:
  `/` → click severity slice → `/search?severity=CRITICAL` (filter chip
  visible) → click row → `/cve/<id>` (header visible before body) →
  click vendor → `/affected-products?vendor=...` → click row →
  `/cve/<id>` → back → back → back returns to `/` with scroll restored
  at each step.
- Combobox keyboard navigation works (Tab to focus, ↓ to open, Enter
  to select, Esc to dismiss).
- Modal traps focus, restores focus on close, dismisses on Esc.
- Tab keyboard nav works on `/cve/[id]` body (←/→ to change tab,
  Enter/Space to activate when manual activation, automatic when
  configured).
- A 429 from `/api/search` triggers a toast (not a full-page error)
  when invoked from the page's background poll.
- A 403 from any route renders the full-page `FORBIDDEN_NETWORK`
  boundary.
- The `/cve/[id]` header renders to first paint (TTFB measured), with
  the body tabs filling in as their streamed promises resolve.
- Lighthouse score on staging: Performance ≥ 90, Accessibility ≥ 95,
  Best Practices ≥ 95, SEO N/A (private app).
- axe-core accessibility audit on every page: zero serious or critical
  issues.

### Exit gate

UAT walkthrough with one external reviewer; reviewer's punch list
either resolved or explicitly deferred with rationale in
`docs/spec/PHASE_GATES.md`.

---

## Phase 6 — Backfill & Production Cutover

**Goal:** load the 24-month historical CVE corpus, validate end-to-end
correctness at scale, and cut DNS to the production zone.

**Effort:** 3–5 days (excluding the backfill runtime itself).

### Deliverables

0. **Prerequisite — operator IP allowlisted.** The developer machine
   running `wrangler --remote` must have its public IP added to
   `corp_authorized_sources` before the backfill begins; otherwise the
   WAF returns 403 on every worker invocation and the script halts on
   the first checkpoint write. Add the IP under
   `purpose=backfill-operator;expires=<run+1 day>` so the entry
   auto-expires after the run.
1. `apps/ingest/scripts/backfill.ts` — a one-off script driven by
   Wrangler's `--remote --no-bundle` execution that:
    - Pulls the historical CVE corpus for the last 24 months via paginated NVD 2.0 API calls (using `resultsPerPage` and `startIndex`).
    - Streams records into `processRecord` with throttling
      (≤ 50 records/second to respect Workers AI quotas).
    - Checkpoints progress to a KV key `backfill:progress` so a crash
      resumes from the last completed pagination offset (`startIndex`).
    - Applies KEV and EPSS overlays as final passes after the main
      corpus is loaded.
2. A throttled production backfill run (executed once, monitored).
3. Post-backfill consistency check: `SELECT COUNT(*) FROM cve` matches
   the count of distinct CVE IDs in the source feeds (within an
   acceptance margin of <0.1% for known-bad records that quarantine).
4. Vectorize index count matches D1 count.
5. Dashboard `/api/metrics/24h` returns realistic numbers.
6. Cloudflare DNS records pointed at the production worker.
7. WAF and rate-limit rules promoted from staging zone to production
   zone.
8. Production smoke test from in-list IP: every page renders, every
   API endpoint returns plausible data, audit log shows entries.

### Acceptance criteria

- Backfill completes inside 4 hours of wall-clock time.
- Total Workers AI Neuron spend for backfill < $10.
- Total Vectorize write op spend for backfill < $5.
- Zero records in `cve-ingest-dlq` after backfill.
- `<0.5%` quarantine rate (i.e. < 400 quarantined records out of ~80k).
- Production smoke test passes end-to-end.
- A staging dashboard widget on `/admin/health` shows the active rate
  limit count, last ingest run, and quarantine size — all updating
  live.
- **Embedding model availability check:** verify
  `@cf/baai/bge-base-en-v1.5` is still on the active Workers AI models
  list and is NOT in any announced deprecation batch. If a deprecation
  date has been published, pause cutover and execute the BGE migration
  plan (see Risk Register row "BGE-base scheduled for deprecation").

### Exit gate

Ship announcement to the SOC team. First week of production operation
proceeds with the implementer on standby for hotfix turnaround.

---

## Cross-Cutting Engineering Standards

These apply throughout every phase.

### Testing

- **Unit tests** (`vitest`) for adapters, validators, hash functions,
  RRF fusion, time conversion helpers. Coverage target: 80% lines.
- **Integration tests** against the staging worker for every `/api/*`
  endpoint, asserting both happy and error paths.
- **Conformance tests** for cross-worker behaviour (embed parity,
  shared contract types).
- **No mocked databases.** Integration tests hit the real staging D1
  and a dedicated test Vectorize index. Mocks have repeatedly hidden
  schema drift in similar projects; the cost of a real test DB is the
  $5 staging tier.

### Code review

- Every change to `packages/contracts` requires explicit review (it is
  a shared API surface).
- Migrations are reviewed line-by-line before merge.
- Wrangler.toml diffs are flagged in PR descriptions.

### Branching

- `main` is always deployable to staging.
- Production deploys are tagged commits.
- No long-lived feature branches; PRs land within 48 hours of opening
  or are explicitly parked.

### Telemetry as a deliverable

- Every endpoint emits its own Analytics Engine events with timing and
  outcome. A feature is not "done" until its telemetry is visible on
  `/admin/health` or the dashboard.

### Documentation as a deliverable

- Every phase exit gate updates `docs/spec/PHASE_GATES.md` with a
  one-paragraph summary, evidence links (CI run, dashboard screenshots,
  audit log query), and any explicit deferrals.
- The six spec files in `docs/spec/` are kept in sync with reality;
  drift between spec and code is a bug.

---

## Phase Dependency Graph

```
Phase 1 ──┬─→ Phase 2 ──→ Phase 3 ──┬─→ Phase 4 ──→ Phase 5 ──→ Phase 6
          │                          │
          └──→ (Phase 4 can begin    │
               its scaffolding in    │
               parallel with         │
               Phase 3 once          │
               contracts are         │
               finalised) ───────────┘
```

Phases 1, 2, and 6 are strict serial gates. Phase 3 and the scaffolding
of Phase 4 can overlap once `packages/contracts` is finalised, because
the API gateway can be built against the eventual shapes even before
real data exists. Phase 5 cannot begin until Phase 4's endpoints are
returning realistic shapes (it can begin against fixture data after
Phase 4's first endpoint is shipped).

---

## Risk Register

| Risk                                                                                  | Likelihood | Impact   | Mitigation                                                                                       |
|---------------------------------------------------------------------------------------|------------|----------|--------------------------------------------------------------------------------------------------|
| Workers AI / Vectorize pricing changes mid-build                                      | Medium     | Medium   | Track monthly spend on `/admin/health`; rate-limit numbers are tunable without code changes.     |
| NVD API schema change                                                                 | Low        | High     | Adapter unit tests pinned against committed fixtures; failing tests block deploy.                |
| Cloudflare deprecates a binding type (e.g. legacy WAF rule format)                    | Low        | Medium   | `compatibility_date` pins behaviour; migration plan documented before bumping the date.          |
| BGE-base scheduled for deprecation (currently flagged "Planned deprecation" in Workers AI catalog) | Medium | High | Migration plan: switch source-text builder + embedder to `@cf/baai/bge-m3` (1024-dim). Re-provision a fresh Vectorize index at 1024 dims (dimensionality is fixed per index). Re-embed all ~80k CVEs in a controlled cutover window; cost estimate ~$1.50 incremental. Conformance test catches embedding drift at switch-over. |
| BGE-base embedding model is silently removed mid-cycle                                | Low        | High     | Phase 6 cutover gate verifies model availability; CI smoke test runs the embed conformance test daily to catch unscheduled removals.             |
| Corp VPN egress IP changes without notice                                             | Medium     | Low      | IP list ledger has `expires_at`; quarterly review catches stale entries.                         |
| Audit log table grows past D1 budget                                                  | Low        | Low      | Weekly purge keeps it bounded; metric on `audit_log` row count surfaced on health page.          |
| FTS5 + Vectorize fusion produces unhelpful rankings                                   | Medium     | Medium   | RRF `k` is tunable; Phase 5 UAT explicitly tests with real SOC user queries before cutover.      |
| Single implementer becomes unavailable mid-build                                      | Variable   | High     | Spec is fully written before any code; another implementer can resume from the latest phase gate.|
