# Threat-Lens CVE Hub — Specification Overview

A production-grade vulnerability management single source of truth focused
on CVE lifecycle visualisation, deployed entirely on the Cloudflare
serverless ecosystem. Optimised for near-zero idle cost over a rolling
24-month window of CVE history.

This document is the **entry point** to the full specification. Read it
first, then proceed through the six sections in order. Each section is
self-contained and committable; together they form the buildable v2 spec.

---

## Locked Decisions

These were negotiated up-front and are referenced throughout the spec. Any
change to a locked decision is a spec change and requires re-validating
the downstream sections.

| Concern                | Decision                                                                                          |
|------------------------|---------------------------------------------------------------------------------------------------|
| Cloudflare plan        | Workers Paid ($5/mo) **plus Cloudflare Pro Zone Plan ($25/mo)**. Pro provides Super Bot Fight Mode and 2 custom WAF Rate Limiting rules (1-minute periods) — sufficient for the two remaining edge rules. IP Lists are available on all tiers. The longer-window AI quota (500/hour per IP, 50k/day global) is enforced **at the worker application level** via D1 ledger tables (Section 5.3.7), not WAF — this avoids the Business plan's 10-minute period cap and the Enterprise step-up entirely. |
| Authentication         | IP allowlist only. No SSO. Audit accountability via the `audit_log` D1 table.                     |
| Backfill budget        | Approved as needed (~$3–5 expected for Workers AI embeddings; $10 cap).                           |
| Headless UI primitive  | **Bits UI v2** (Svelte 5 native, ships zero CSS). Wrapped once in `apps/app/src/lib/ui/`.         |
| Worker topology        | Two workers with Separation of Duties: `threat-lens-app` (request, read-mostly) + `threat-lens-ingest` (cron, write). |
| History depth          | Rolling **24 months** (~60k–80k CVEs steady state).                                               |
| Aging policy           | **Hard delete** outside the window. KEV-listed CVEs are exempt and retained regardless of age.    |

---

## Non-Negotiable Engineering Rules

- **No CSS frameworks.** Tailwind, Bootstrap, Skeleton, UnoCSS, shadcn,
  Flowbite — none. Pure CSS custom properties + scoped component styles.
  Bits UI is the only UI dependency and ships zero CSS.
- **No mocked databases in integration tests.** Real staging D1 and a
  dedicated test Vectorize index.
- **`packages/contracts` is type-only.** Shared utilities live in each
  worker; their conformance is verified by a snapshot test.
- **The two workers never call each other over HTTP.** They share state
  only through D1, Vectorize, KV, and Queues.
- **Wrangler env blocks must be repeated.** `[env.staging]` does not
  inherit top-level bindings; every binding is re-declared.
- **All timestamps are unix ms in storage, ISO 8601 at the API boundary.**
- **The spec is the source of truth.** Drift between spec and code is a
  bug; reconcile by updating either the code or the spec, never both
  silently.

---

## Section Index

Read in order. Each section assumes the prior sections are in scope.

| §  | File                                                                       | What it covers                                                                                                                              |
|----|----------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------|
| 1  | [01-bootstrap-and-deployment.md](./01-bootstrap-and-deployment.md)         | Repository layout (pnpm workspace), Svelte 5 / SvelteKit 2 setup, TypeScript strict profile, CSS token layer, Bits UI integration, and both `wrangler.toml` files for the two workers. |
| 2  | [02-page-topology-and-navigation.md](./02-page-topology-and-navigation.md) | The five user routes (`/`, `/search`, `/cve/[id]`, `/affected-products`, `/threat-intel`) plus `/admin/health`, inter-route navigation matrix, streaming SSR pattern, per-route caching, and error boundaries. |
| 3  | [03-system-blueprints.md](./03-system-blueprints.md)                       | D1 relational schema (cve, cwe, cpe, state, quarantine, audit, metrics rollup), FTS5 virtual tables, Vectorize index spec with the two-hash re-embedding strategy, Analytics Engine event schema, KV `CACHE` key catalog, and Queue contracts. |
| 4  | [04-perimeter-security.md](./04-perimeter-security.md)                     | Cloudflare IP List `corp_authorized_sources`, WAF custom rule layer, three rate-limit rules plus one application-level daily quota ledger, and audit log integration. |
| 5  | [05-component-interactions.md](./05-component-interactions.md)             | Cron dispatch table, source adapters, persistence sequence, retry queue, aging sweep, the seven `/api/*` endpoints + `/api/admin/health` with full contracts, the hybrid search pipeline (exact → FTS5 → vector → RRF), and the SvelteKit loader split. |
| 6  | [06-execution-plan.md](./06-execution-plan.md)                             | Six-phase build plan with explicit deliverables, acceptance criteria, and exit gates per phase. Cross-cutting engineering standards. Phase dependency graph. Risk register.            |

---

## Quick Architecture Sketch

```
                       ┌──────────────────────────────────┐
                       │   Cloudflare Edge (WAF, RL, IP)  │
                       └──────────────────┬───────────────┘
                                          │ in-list IPs only
                                          ▼
┌───────────────────────────┐   ┌──────────────────────────┐
│  threat-lens-app          │   │  threat-lens-ingest      │
│  (SvelteKit on Workers)   │   │  (cron + queue only)     │
│  - request handling       │   │  - NVD / MITRE / KEV /   │
│  - hybrid search          │   │    EPSS adapters         │
│  - audit log writes       │   │  - aging sweep           │
│  - KV cache read-through  │   │  - retry consumer        │
│  - Workers AI (query)     │   │  - Workers AI (ingest)   │
│                           │   │  - KV cache invalidation │
└──────────┬────────────────┘   └────────────┬─────────────┘
           │                                 │
           └─────────────┬───────────────────┘
                         ▼
        ┌───────────────────────────────────────┐
        │  Shared state (no inter-worker RPC)   │
        │  • D1: cve, cpe, state, FTS5, audit   │
        │  • Vectorize: 768-dim cosine          │
        │  • KV CACHE: snapshots, invalidation  │
        │  • Analytics Engine: telemetry        │
        │  • Queues: retry + DLQ                │
        └───────────────────────────────────────┘
```

---

## Reading Order by Role

- **Implementer building the app:** §1 → §6 (phase 1) → §4 → §6 (phase 1 cont.) → §3 → §6 (phase 2) → §5 → §6 (phases 3–4) → §2 → §6 (phase 5) → §6 (phase 6).
- **Reviewer auditing the design:** §0 (this file) → §6 (locked decisions and risk register) → §4 (security posture) → §3 (data model) → §5 (contracts).
- **SOC analyst evaluating the UX:** §2 (pages) → §5 (API contracts to understand what's possible).
- **Operator preparing for cutover:** §6 (phase 6) → §4 (perimeter) → §3 (KV invalidation rules) → §2.2.6 (`/admin/health`).

---

## Versioning

- This spec is **v2**. It supersedes the v1 draft (not in git history; v1
  was a conversational artifact that was critiqued and rewritten).
- Any v3 begins with a new round of decisions captured at the top of this
  file. Prior locked decisions remain in git history.
