# @threat-lens/contracts

Shared TypeScript types for the Threat-Lens CVE Hub. **Type-only — zero runtime code.** Imported by both `threat-lens-app` and `threat-lens-ingest` as a workspace dependency.

## Purpose

This package is the single source of truth for all cross-worker data shapes. Both workers must conform to these types. Any divergence between a worker's implementation and these contracts is a bug.

## Modules

### `cve.ts` — Core domain types

Types used throughout the ingest pipeline and storage layer.

| Type | Description |
|------|-------------|
| `Severity` | `'CRITICAL' \| 'HIGH' \| 'MEDIUM' \| 'LOW' \| 'NONE'` |
| `IngestSource` | `'NVD' \| 'MITRE' \| 'KEV' \| 'EPSS' \| 'AGING'` |
| `NormalizedCpe` | CPE entry with vendor, product, version, and version bounds |
| `NormalizedCveRecord` | Full normalised CVE — the unit passed to `processRecord` |
| `KevPatch` | Fields updated when a KEV entry is applied |
| `EpssPatch` | Fields updated when an EPSS score is applied |
| `RetryMessage` | Queue message shape for `cve-ingest-retry` |

### `api.ts` — API gateway contracts

Request/response shapes for all seven `/api/*` endpoints.

| Type | Endpoint |
|------|----------|
| `ErrorCode` / `ErrorEnvelope` | All endpoints — error response shape |
| `CvssBlock` | Embedded in `CveDetailResponse` |
| `CpeRow` | Embedded in `CveDetailResponse` |
| `CveDetailResponse` | `GET /api/cve/:id` |
| `SearchRequest` / `SearchFilters` / `SearchResultItem` / `SearchResponse` | `POST /api/search` |
| `AffectedProductsRequest` / `AffectedProductRow` / `AffectedProductsResponse` | `GET /api/affected-products` |
| `KevListRow` / `KevListResponse` | `GET /api/threat-intel/kev` |
| `EpssListRow` / `EpssListResponse` | `GET /api/threat-intel/epss` |
| `MetricsWindow` / `MetricsKpis` / `MetricsSeries` / `MetricsResponse` | `GET /api/metrics/:window` |
| `IngestSourceStatus` / `IngestStaleness` / `HealthResponse` | `GET /api/admin/health` |

### `embed.ts` — Embedding constants

| Export | Value | Description |
|--------|-------|-------------|
| `EMBED_MODEL` | `'@cf/baai/bge-base-en-v1.5'` | Workers AI model used by both workers |
| `EMBED_MAX_CHARS` | `2048` | Input truncation limit before embedding |
| `EMBED_DIMENSIONS` | `768` | Vector dimensions — must match Vectorize index |
| `EmbedFn` | `type` | Function signature shared by app and ingest embed helpers |

## Import conventions

```ts
// Preferred: named imports from the package root
import type { NormalizedCveRecord, Severity } from '@threat-lens/contracts';
import type { CveDetailResponse, SearchRequest } from '@threat-lens/contracts';
import { EMBED_MODEL, EMBED_DIMENSIONS } from '@threat-lens/contracts';

// Also valid: sub-path imports for explicit module clarity
import type { NormalizedCveRecord } from '@threat-lens/contracts/cve';
import type { CveDetailResponse } from '@threat-lens/contracts/api';
import type { EmbedFn } from '@threat-lens/contracts/embed';
```

## Key conventions

- **All timestamps are unix milliseconds in storage, ISO 8601 strings at the API boundary.** Types in `api.ts` use `string` for dates; types in `cve.ts` use `number`.
- **`NormalizedCveRecord.cpes` is capped at 500 entries per CVE** during D1 write (batch 3).
- **`NormalizedCveRecord.references` is capped at 200 entries per CVE** during D1 write (batch 4).
- **`SearchRequest` requires exactly one of `query` or `similarTo`.** Validation is enforced in `validateSearchRequest`.

## Development

```sh
# Type-check
pnpm --filter @threat-lens/contracts check

# Build (emits .d.ts declarations only — no JS)
pnpm --filter @threat-lens/contracts build
```

This package has no test suite of its own. Conformance is verified by running `check` on both consuming workers — if both pass `tsc --noEmit`, the contracts are in sync.
