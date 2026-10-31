import path from 'node:path';
import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-plugin';
import { defineConfig } from 'vitest/config';

export default defineConfig(async () => {
  // Shared D1 schema at repo root — mirrors `migrations_dir = "../../migrations"`
  // in this package's wrangler.toml.
  const migrationsPath = path.join(import.meta.dirname, '..', '..', 'migrations');
  const migrations = await readD1Migrations(migrationsPath);

  return {
    plugins: [
      cloudflareTest({
        // Never proxy bindings to the real Cloudflare account (no API token
        // is available in this environment anyway — see CLAUDE.md).
        remoteBindings: false,
        // The real, deployed wrangler.toml (top-level/production bindings,
        // not [env.staging]) — D1/KV run for real against workerd; Vectorize
        // and Workers AI are mocked per-test where a test happens to touch them.
        wrangler: { configPath: './wrangler.toml' },
        miniflare: {
          // TEST_MIGRATIONS: applied by the setup file before each suite.
          // ADMIN_BEARER: a fixed test value so admin-gated mutation routes
          // (watchlist create/edit/etc.) can be exercised end to end; in
          // production this is a real `wrangler secret`, never committed.
          bindings: { TEST_MIGRATIONS: migrations, ADMIN_BEARER: 'test-admin-token' },
        },
      }),
    ],
    test: {
      setupFiles: ['./test/setup/apply-migrations.ts'],
    },
  };
});
