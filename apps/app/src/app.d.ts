// TypeScript environment declarations for the SvelteKit app worker.
// Cloudflare-specific bindings declared in wrangler.toml are typed here
// so that event.platform.env.DB etc. are fully type-checked.
// See: https://kit.svelte.dev/docs/types#app

declare global {
  namespace App {
    /**
     * Cloudflare Workers platform object injected by adapter-cloudflare.
     * Bindings must match the wrangler.toml declarations exactly.
     */
    interface Platform {
      env: {
        // D1 database — read-mostly access from the app worker
        DB: D1Database;
        // KV namespace — read-through cache for hot-path responses
        CACHE: KVNamespace;
        // Vectorize index — semantic search (768-dim cosine)
        VECTORIZE: VectorizeIndex;
        // Analytics Engine — telemetry events
        ANALYTICS: AnalyticsEngineDataset;
        // Workers AI — query-time embedding on /api/search
        AI: Ai;
        // Cloudflare REST API access for queue depth lookups
        CLOUDFLARE_API_TOKEN: string;
        CLOUDFLARE_ACCOUNT_ID: string;
        // Bearer token protecting /api/admin/health
        ADMIN_BEARER: string;
        // Analytics Engine SQL HTTP API token for metrics queries
        ANALYTICS_QUERY_TOKEN: string;
      };
      context: {
        /** Non-blocking async work — used for audit log writes. */
        waitUntil(promise: Promise<unknown>): void;
      };
      /** Cloudflare request metadata (geo, colo, tls, etc.) */
      cf: CfProperties;
    }

    /**
     * Values populated by hooks.server.ts and available to all server loads
     * and server endpoints via event.locals.
     */
    interface Locals {
      /** True client IP from CF-Connecting-IP header. */
      clientIp: string;
      /** Cloudflare Ray ID — used as requestId in audit_log. */
      cfRay: string;
    }

    /**
     * Error shape surfaced to +error.svelte via event.error.
     * Extends the base SvelteKit Error with envelope fields.
     */
    interface Error {
      code?: string;
      requestId?: string;
    }
  }
}

export {};
