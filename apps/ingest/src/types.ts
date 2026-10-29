import type { EpssQueueMessage, RetryMessage } from '@threat-lens/contracts';

/** Cloudflare bindings for the ingest worker — must match wrangler.toml exactly. */
export interface Env {
  // D1 database — write path for ingest, read path for provenance checks.
  DB: D1Database;
  // Vectorize index — upsert on text change, metadata-only upsert on state change.
  VECTORIZE: VectorizeIndex;
  // Analytics Engine — one event per record processed, one event per pipeline run.
  ANALYTICS: AnalyticsEngineDataset;
  // Workers AI — @cf/baai/bge-base-en-v1.5 for ingest-time embeddings.
  AI: Ai;
  // KV namespace — write-only intent: delete cache keys after record updates (§2.7).
  CACHE: KVNamespace;
  // Retry queue producer — enqueue failed per-record persistence (§5.1.4).
  RETRY_QUEUE: Queue<RetryMessage>;
  // EPSS queue producer — daily.ts enqueues fetched/chunked patches here
  // instead of writing them to D1 inline; pipelines/epssQueue.ts's consumer
  // does the actual D1 work, one message per invocation (see wrangler.toml).
  EPSS_QUEUE: Queue<EpssQueueMessage>;
  // Secrets (injected via `wrangler secret put`, never in wrangler.toml).
  NVD_API_KEY: string;
  CLOUDFLARE_API_TOKEN: string;
  CLOUDFLARE_ACCOUNT_ID: string;
}
