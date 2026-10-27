import adapter from '@sveltejs/adapter-cloudflare';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/kit').Config} */
const config = {
  preprocess: vitePreprocess(),
  kit: {
    // Workers Static Assets mode — correct for adapter-cloudflare.
    // NOT the legacy adapter-cloudflare-workers and NOT Workers Sites.
    // See Section 1.4.3: [assets] binding, not [site].
    adapter: adapter({
      routes: {
        include: ['/*'],
        exclude: ['<all>'],
      },
    }),

    alias: {
      // Resolves @threat-lens/contracts to the workspace package source
      // without requiring a build step — Vite/bundler resolves .ts directly.
      '@threat-lens/contracts': '../../packages/contracts/src/index.ts',
      '@threat-lens/contracts/cve': '../../packages/contracts/src/cve.ts',
      '@threat-lens/contracts/api': '../../packages/contracts/src/api.ts',
      '@threat-lens/contracts/embed': '../../packages/contracts/src/embed.ts',
    },
  },
};

export default config;
