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
  AffectedProductRow,
  AffectedProductsRequest,
  AffectedProductsResponse,
  CpeRow,
  CveDetailResponse,
  CvssBlock,
  EpssListResponse,
  EpssListRow,
  ErrorCode,
  ErrorEnvelope,
  HealthResponse,
  IngestSourceStatus,
  IngestStaleness,
  KevListResponse,
  KevListRow,
  MetricsKpis,
  MetricsResponse,
  MetricsSeries,
  MetricsWindow,
  SearchFilters,
  SearchRequest,
  SearchResponse,
  SearchResultItem,
} from './api.js';
export type {
  EpssPatch,
  EpssQueueMessage,
  IngestSource,
  KevPatch,
  NormalizedCpe,
  NormalizedCveRecord,
  OsvAffectedPackage,
  OsvFetchItem,
  OsvPatch,
  OsvQueueMessage,
  OsvRange,
  OsvRangeEvent,
  RetryMessage,
  Severity,
} from './cve.js';

export type { EmbedFn } from './embed.js';
export { EMBED_DIMENSIONS, EMBED_MAX_CHARS, EMBED_MODEL } from './embed.js';
