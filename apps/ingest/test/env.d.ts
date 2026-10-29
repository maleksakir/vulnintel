import type { EpssQueueMessage, RetryMessage } from '@threat-lens/contracts';

// Augments the ambient `Cloudflare.Env` type that `cloudflare:workers`'s
// `env` export is typed against inside tests, so it matches this Worker's
// real wrangler.toml bindings plus the one test-only addition.
declare namespace Cloudflare {
  interface Env {
    DB: D1Database;
    VECTORIZE: VectorizeIndex;
    ANALYTICS: AnalyticsEngineDataset;
    AI: Ai;
    CACHE: KVNamespace;
    RETRY_QUEUE: Queue<RetryMessage>;
    EPSS_QUEUE: Queue<EpssQueueMessage>;
    // Defined in vitest.config.ts; only exists under test.
    TEST_MIGRATIONS: import('cloudflare:test').D1Migration[];
  }
}
