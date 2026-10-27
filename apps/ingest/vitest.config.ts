import path from 'node:path';
import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-plugin';
import { defineConfig } from 'vitest/config';

export default defineConfig(async () => {
  // D1 schema lives at repo root (shared by both Workers); mirrors the
  // `migrations_dir = "../../migrations"` path in this package's wrangler.toml.
  const migrationsPath = path.join(import.meta.dirname, '..', '..', 'migrations');
  const migrations = await readD1Migrations(migrationsPath);

  return {
    plugins: [
      cloudflareTest({
        // Never proxy bindings to the real Cloudflare account (no API token
        // is available in this environment anyway — see CLAUDE.md). D1/KV/
        // Queues are simulated locally for real by workerd; AI/Vectorize
        // have no local simulator and are mocked per-test instead (see
        // test/helpers.ts), matching Cloudflare's own ai-vectorize fixture.
        remoteBindings: false,
        // Reuse the real, deployed wrangler.toml — not a parallel test-only
        // config — so these tests exercise the actual bindings this Worker
        // ships with.
        wrangler: { configPath: './wrangler.toml' },
        miniflare: {
          // Test-only binding so a setup file can apply the real D1 schema
          // before any test runs (see test/setup/apply-migrations.ts).
          bindings: { TEST_MIGRATIONS: migrations },
        },
      }),
    ],
    test: {
      setupFiles: ['./test/setup/apply-migrations.ts'],
    },
  };
});
