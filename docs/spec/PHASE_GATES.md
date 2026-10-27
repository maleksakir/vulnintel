# Phase Exit Evidence Log

Each phase gate records the evidence produced before moving to the next phase.
A phase is considered complete only when all evidence items in its section are
checked and dated. Never mark a gate as passed before its evidence exists.

---

## Phase 1 — Bootstrap & Scaffolding

**Exit criteria (from §1.5):**

- [ ] `pnpm install` resolves cleanly with zero dependency errors.
  - Verified by: `pnpm install --frozen-lockfile` in CI (no output errors)
  - Date: _pending_

- [ ] `packages/contracts` compiles with `tsc --noEmit`.
  - Verified by: `pnpm --filter @threat-lens/contracts check`
  - Date: _pending_

- [ ] `apps/ingest` passes `tsc --noEmit`.
  - Verified by: `pnpm --filter @threat-lens/ingest check`
  - Date: _pending_

- [ ] `apps/app` passes `svelte-check`.
  - Verified by: `pnpm --filter @threat-lens/app check`
  - Date: _pending_

- [ ] `wrangler deploy --env staging --dry-run` succeeds for `apps/app`.
  - Verified by: dry-run output shows zero errors
  - Date: _pending_

- [ ] `wrangler deploy --env staging --dry-run` succeeds for `apps/ingest`.
  - Verified by: dry-run output shows zero errors
  - Date: _pending_

- [ ] All Cloudflare resource IDs in `docs/spec/RESOURCES.md` filled.
  - Verified by: no `REPLACE_AFTER_PROVISIONING` remaining in `wrangler.toml` files
  - Date: _pending_

- [ ] IP allowlist and WAF rules configured (§4 perimeter security).
  - Verified by: off-list IP receives `403 FORBIDDEN_NETWORK` from staging
  - Date: _pending_

**Notes:**
_Record any blockers, deviations, or decisions made during Phase 1 here._

---

## Phase 2 — Database Schema & Migrations

**Exit criteria:**

- [ ] All migrations in `migrations/` apply cleanly against prod and staging D1.
  - Verified by: `wrangler d1 migrations apply cve_prod_d1` exits 0
  - Date: _pending_

- [ ] Schema matches §3 (all tables, indexes, FTS5 virtual tables, triggers).
  - Verified by: `wrangler d1 execute cve_prod_d1 --command ".schema"` reviewed against spec
  - Date: _pending_

- [ ] FTS5 search returns results on a synthetic test row.
  - Date: _pending_

---

## Phase 3 — Ingest Pipeline

**Exit criteria (from §5.5 Phase 3):**

- [ ] Source adapters (nvd, mitre, kev, epss) produce correct `NormalizedCveRecord[]` on fixture inputs.
  - Verified by: unit tests pass (`pnpm --filter @threat-lens/ingest test`)
  - Date: _pending_

- [ ] `processRecord` persistence sequence (§5.1.4) commits correct rows in D1 and Vectorize.
  - Verified by: end-to-end smoke against staging with synthetic fixture dataset
  - Date: _pending_

- [ ] Retry queue consumer re-invokes `processRecord` correctly on VECTORIZE_ONLY and UPSERT_ALL.
  - Verified by: manual queue message injection in staging
  - Date: _pending_

- [ ] `runAgingSweep` deletes aged records from D1, Vectorize, and CACHE.
  - Verified by: staging smoke with a row whose `published_at` is artificially back-dated > 24 months
  - Date: _pending_

- [ ] `ingest_run` table populated after each cron trigger.
  - Date: _pending_

---

## Phase 4 — API Gateway

**Exit criteria (from §5.5 Phase 4):**

- [ ] All seven `/api/*` endpoints return correct response shapes for valid inputs.
  - Verified by: integration tests or manual curl from in-list IP
  - Date: _pending_

- [ ] `400 VALIDATION_ERROR` returned for invalid inputs on each endpoint.
  - Date: _pending_

- [ ] `403 FORBIDDEN_NETWORK` returned from off-list IP.
  - Date: _pending_

- [ ] `429 RATE_LIMITED` returned after per-IP hourly quota exhausted (§5.3.7).
  - Date: _pending_

- [ ] `audit_log` table receives one row per `/api/*` request.
  - Date: _pending_

- [ ] KV cache populated and invalidated correctly per §2.7 catalog.
  - Date: _pending_

---

## Phase 5 — UI

**Exit criteria (from §2.9):**

- [ ] Root layout with nav shell, theme toggle, and toast region renders without errors.
  - Date: _pending_

- [ ] `/` dashboard renders KPI cards and all four chart rows with skeleton states.
  - Date: _pending_

- [ ] `/search` exact-match short-circuit, FTS5 highlighting, and URL state restoration verified.
  - Date: _pending_

- [ ] `/cve/[id]` streaming SSR — header renders before body sections finish.
  - Date: _pending_

- [ ] `/affected-products` cursor pagination works across pages.
  - Date: _pending_

- [ ] `/threat-intel` KEV and EPSS panels render and switch correctly.
  - Date: _pending_

- [ ] `/admin/health` admin bearer gate enforced.
  - Date: _pending_

- [ ] Full navigation flow (§2.9 step 9) verified including scroll restoration.
  - Date: _pending_

- [ ] WCAG AA colour contrast verified for both light and dark themes.
  - Date: _pending_

---

## Phase 6 — Hardening & Production Cut-over

**Exit criteria:**

- [ ] Load test: 50 concurrent users, p95 < 500 ms on `/search` with hybrid pipeline active.
  - Date: _pending_

- [ ] Ingest worker processes a full NVD delta (≈ 250k records) without DLQ overflow.
  - Date: _pending_

- [ ] Aging sweep verified against production data window.
  - Date: _pending_

- [ ] All `REPLACE_AFTER_PROVISIONING` in wrangler.toml replaced with production IDs.
  - Date: _pending_

- [ ] DNS / routing cut-over from legacy VulnIntel stack completed.
  - Date: _pending_
