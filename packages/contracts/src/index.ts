/**
 * @threat-lens/contracts — shared TypeScript types for the Threat-Lens CVE Hub.
 *
 * This package is TYPE-ONLY. No runtime code lives here.
 * Both workers import from this package; the conformance test (Phase 3)
 * verifies that both consumers stay in sync with this source of truth.
 *
 * Import from the sub-path exports for tree-shaking clarity:
 *   import type { NormalizedCveRecord } from '@threat-lens/contracts/cve'
 *   import type { ErrorEnvelope } from '@threat-lens/contracts/api'
 *   import type { EmbedFn } from '@threat-lens/contracts/embed'
 */

export type {
  Severity,
  IngestSource,
  NormalizedCpe,
  NormalizedCveRecord,
  KevPatch,
  EpssPatch,
  RetryMessage,
} from './cve.js';

export type {
  ErrorCode,
  ErrorEnvelope,
  CvssBlock,
  CpeRow,
  CveDetailResponse,
  SearchFilters,
  SearchRequest,
  SearchResultItem,
  SearchResponse,
  AffectedProductsRequest,
  AffectedProductRow,
  AffectedProductsResponse,
  KevListRow,
  KevListResponse,
  EpssListRow,
  EpssListResponse,
  MetricsWindow,
  MetricsKpis,
  MetricsSeries,
  MetricsResponse,
  IngestSourceStatus,
  IngestStaleness,
  HealthResponse,
} from './api.js';

export type { EmbedFn } from './embed.js';
export { EMBED_MODEL, EMBED_MAX_CHARS, EMBED_DIMENSIONS } from './embed.js';
