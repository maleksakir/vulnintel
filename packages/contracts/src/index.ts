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
  AffectedVersionRow,
  AffectedVersionsResponse,
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
  OsvAffectedPackageRow,
  SearchFilters,
  SearchInterpretation,
  SearchRequest,
  SearchResponse,
  SearchResultItem,
  SsvcBlock,
} from './api.js';
export type {
  EpssPatch,
  EpssQueueMessage,
  ExploitMaturity,
  ExploitQueueMessage,
  ExploitReference,
  ExploitSource,
  IngestSource,
  KevPatch,
  KevQueueMessage,
  MitreCweQueueMessage,
  NormalizedCpe,
  NormalizedCveRecord,
  NvdQueueMessage,
  OsvAffectedPackage,
  OsvFetchItem,
  OsvPatch,
  OsvQueueMessage,
  OsvRange,
  OsvRangeEvent,
  RetryMessage,
  Severity,
  SsvcDecision,
} from './cve.js';
export type { EmbedFn } from './embed.js';
export { EMBED_DIMENSIONS, EMBED_MAX_CHARS, EMBED_MODEL } from './embed.js';
export type {
  SbomComponentInput,
  SbomComponentResult,
  SbomCveMatch,
  SbomMatchVia,
  SbomScanResponse,
} from './sbom.js';
