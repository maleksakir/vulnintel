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
          bindings: { TEST_MIGRATIONS: migrations },
        },
      }),
    ],
    test: {
      setupFiles: ['./test/setup/apply-migrations.ts'],
    },
  };
});
