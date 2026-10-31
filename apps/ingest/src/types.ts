import type {
  EpssQueueMessage,
  KevQueueMessage,
  MitreCweQueueMessage,
  NvdQueueMessage,
  OsvQueueMessage,
  RetryMessage,
  WatchlistQueueMessage,
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
  // KEV queue producer — kev.ts (the 6-hourly cron) enqueues fetched/chunked
  // CISA KEV catalog patches here instead of applying them to D1 inline;
  // pipelines/kevQueue.ts's consumer does the actual batched D1 work
  // (applyKevPatchBatch), one message per invocation (see wrangler.toml).
  KEV_QUEUE: Queue<KevQueueMessage>;
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
  // MITRE CWE gap-fill queue producer — daily.ts's NVD section enqueues
  // chunked CVE IDs here for any NVD record it saw with zero CWEs;
  // pipelines/mitreQueue.ts's consumer re-checks each one against MITRE's
  // public single-record endpoint and writes only CWE rows (never
  // cve/cve_state — see adapters/mitre.ts and pipelines/mitreQueue.ts).
  MITRE_QUEUE: Queue<MitreCweQueueMessage>;
  // Watchlist reconciliation queue producer — daily.ts sends a lightweight
  // WATCHLIST_RECONCILE kick-off (watchlists have no cron slot of their own);
  // pipelines/watchlistQueue.ts's consumer materializes vendor/product
  // matches into watchlist_match with its own fresh 50-D1-query budget (see
  // lib/server/watchlistReconcile.ts and wrangler.toml).
  WATCHLIST_QUEUE: Queue<WatchlistQueueMessage>;
  // Secrets (injected via `wrangler secret put`, never in wrangler.toml).
  NVD_API_KEY: string;
  CLOUDFLARE_API_TOKEN: string;
  CLOUDFLARE_ACCOUNT_ID: string;
  // OPTIONAL. When set, watchlist webhook digests carry an
  // `X-ThreatLens-Signature: sha256=<hmac>` header over the exact request
  // body so a receiver can verify origin and reject forged/replayed posts
  // (lib/server/watchlistNotify.ts). Unset means unsigned delivery, which is
  // why it's optional rather than required: an unconfigured deploy must still
  // notify. Set with `wrangler secret put WEBHOOK_SIGNING_SECRET`.
  WEBHOOK_SIGNING_SECRET?: string;
}
