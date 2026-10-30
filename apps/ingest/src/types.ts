import type {
  EpssQueueMessage,
  NvdQueueMessage,
  OsvQueueMessage,
  RetryMessage,
} from '@threat-lens/contracts';

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
  // NVD queue producer — daily.ts's NVD section enqueues fetched,
  // size-aware-batched NormalizedCveRecords here instead of calling
  // processRecord() inline; pipelines/nvdQueue.ts's consumer does the
  // actual processRecord()/D1/Vectorize/AI work, one small bounded batch
  // per invocation (see wrangler.toml).
  NVD_QUEUE: Queue<NvdQueueMessage>;
  // OSV queue producer — carries both the lightweight daily OSV_DISCOVER
  // kick-off (sent from daily.ts, since OSV can't get its own Cron Trigger —
  // all 5 Workers Free slots are already used) and the per-record
  // OSV_FETCH work items; pipelines/osv.ts's runOsvDiscovery/
  // runOsvFetchBatch consume both from the same queue (see wrangler.toml).
  OSV_QUEUE: Queue<OsvQueueMessage>;
  // Secrets (injected via `wrangler secret put`, never in wrangler.toml).
  NVD_API_KEY: string;
  CLOUDFLARE_API_TOKEN: string;
  CLOUDFLARE_ACCOUNT_ID: string;
}
