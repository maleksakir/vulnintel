<script lang="ts">
  import '../app.css';
  // Declares LayerChart's cascade-layer order (one `@layer` statement, no
  // rules). It must load before any LayerChart component CSS, or layer
  // precedence falls to bundler emit order and can differ between dev and
  // production builds — hence here, not in the chart components.
  import 'layerchart/core.css';
  import Toast from '$lib/ui/Toast.svelte';
  import type { ToastVariant } from '$lib/ui/Toast.svelte';
  import { setContext, untrack } from 'svelte';
  import { page } from '$app/stores';
  import type { LayoutData } from './$types';

  interface Props {
    data: LayoutData;
    children: import('svelte').Snippet;
  }

  let { data, children }: Props = $props();

  // --- Theme ---
  // Persisted in localStorage; initialised from data-theme on <html> (set in app.html).
  let theme = $state<'light' | 'dark'>('dark');

  $effect(() => {
    const stored = localStorage.getItem('theme') as 'light' | 'dark' | null;
    if (stored) theme = stored;
  });

  $effect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
  });

  function toggleTheme() {
    theme = theme === 'dark' ? 'light' : 'dark';
  }

  // --- Toast region (§2.4) ---
  type ToastItem = { id: string; variant: ToastVariant; title: string; description?: string; duration?: number };
  let toasts = $state<ToastItem[]>([]);

  function addToast(item: Omit<ToastItem, 'id'>) {
    const id = crypto.randomUUID();
    toasts = [...toasts, { ...item, id }];
  }

  function removeToast(id: string) {
    toasts = toasts.filter((t) => t.id !== id);
  }

  // --- Rate-limit status (populated from response headers on every fetch, §2.4) ---
  let rateLimitStatus = $state<{ remaining: number; resetAt: number | null }>({ remaining: 500, resetAt: null });

  // Expose to child routes via context (§2.4)
  setContext('addToast', addToast);
  setContext('rateLimitStatus', rateLimitStatus);
  setContext('auditIdentity', untrack(() => ({ clientIp: data.clientIp, cfRay: data.cfRay })));
</script>

<!-- Skip-link — first focusable element, jumps to #main-content (§2.4) -->
<a class="skip-link" href="#main-content">Skip to main content</a>

<header class="site-header">
  <nav class="site-nav" aria-label="Primary navigation">
    <a class="site-nav__logo" href="/" aria-label="Threat-Lens CVE Hub — home">
      <svg class="site-nav__logo-icon" width="22" height="22" viewBox="0 0 22 22" fill="none" aria-hidden="true">
        <path d="M11 2 3 5.5v6c0 4.1 3.4 7.9 8 9 4.6-1.1 8-4.9 8-9v-6L11 2Z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/>
        <circle cx="11" cy="11" r="3" stroke="currentColor" stroke-width="1.4"/>
        <circle cx="11" cy="11" r="1" fill="currentColor"/>
      </svg>
      <span>Threat-Lens</span>
    </a>

    <ul class="site-nav__links" role="list">
      <li><a href="/" aria-current={$page.url.pathname === '/' ? 'page' : undefined}>Dashboard</a></li>
      <li><a href="/search" aria-current={$page.url.pathname.startsWith('/search') ? 'page' : undefined}>Search</a></li>
      <li><a href="/affected-products" aria-current={$page.url.pathname.startsWith('/affected-products') ? 'page' : undefined}>Affected Products</a></li>
      <li><a href="/threat-intel" aria-current={$page.url.pathname.startsWith('/threat-intel') ? 'page' : undefined}>Threat Intel</a></li>
      <li><a href="/watchlists" aria-current={$page.url.pathname.startsWith('/watchlists') ? 'page' : undefined}>Watchlists</a></li>
      <li><a href="/assets" aria-current={$page.url.pathname.startsWith('/assets') ? 'page' : undefined}>Assets</a></li>
      <li><a href="/remediation" aria-current={$page.url.pathname.startsWith('/remediation') ? 'page' : undefined}>Remediation</a></li>
    </ul>

    <button
      class="site-nav__theme-toggle"
      aria-label="Switch to {theme === 'dark' ? 'light' : 'dark'} mode"
      onclick={toggleTheme}
      type="button"
    >
      {#if theme === 'dark'}
        <!-- Sun icon -->
        <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
          <circle cx="8" cy="8" r="3" stroke="currentColor" stroke-width="1.4"/>
          <path d="M8 1v2M8 13v2M1 8h2M13 8h2M3.1 3.1l1.4 1.4M11.5 11.5l1.4 1.4M11.5 3.1l-1.4 1.4M4.5 11.5l-1.4 1.4" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>
        </svg>
      {:else}
        <!-- Moon icon -->
        <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
          <path d="M13.5 9.5A6 6 0 0 1 6.5 2.5a5.5 5.5 0 1 0 7 7Z" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/>
        </svg>
      {/if}
    </button>
  </nav>
</header>

<main id="main-content" class="site-main" tabindex="-1">
  {@render children()}
</main>

<!-- Toast region — anchored bottom-right (§2.4) -->
<Toast toasts={toasts} onClose={removeToast} position="bottom-right" />

<!-- Desktop hint banner (< 768 px) — defined in app.css §12 -->
<div class="desktop-hint-banner" role="status" aria-live="polite">
  Threat-Lens is best viewed on a desktop or laptop screen.
</div>

<style>
  .skip-link {
    position: absolute;
    top: -100%;
    left: var(--space-4);
    padding: var(--space-2) var(--space-4);
    background: var(--color-surface-raised);
    border: 1px solid var(--color-border-default);
    border-radius: var(--radius-sm);
    font-size: var(--text-sm);
    z-index: var(--z-popover);
    transition: top var(--transition-colors);
  }

  .skip-link:focus-visible {
    top: var(--space-4);
  }

  .site-header {
    position: sticky;
    top: 0;
    height: var(--layout-nav-height);
    background: var(--color-surface-base);
    border-bottom: 1px solid var(--color-border-subtle);
    z-index: var(--z-header);
  }

  .site-nav {
    display: flex;
    align-items: center;
    gap: var(--space-6);
    height: 100%;
    max-width: calc(var(--layout-content-max) + var(--layout-page-gutter) * 2);
    margin-inline: auto;
    padding-inline: var(--layout-page-gutter);
  }

  .site-nav__logo {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    font-size: var(--text-base);
    font-weight: var(--weight-semibold);
    color: var(--color-text-primary);
    text-decoration: none;
    letter-spacing: var(--tracking-tight);
    flex-shrink: 0;
  }

  .site-nav__logo-icon {
    color: var(--color-brand-500);
    flex-shrink: 0;
  }

  .site-nav__links {
    display: flex;
    align-items: center;
    gap: var(--space-1);
    list-style: none;
    margin: 0;
    padding: 0;
    flex: 1;
  }

  .site-nav__links a {
    display: block;
    padding: var(--space-2) var(--space-3);
    font-size: var(--text-sm);
    font-weight: var(--weight-medium);
    color: var(--color-text-secondary);
    text-decoration: none;
    border-radius: var(--radius-sm);
    transition: var(--transition-colors);
  }

  .site-nav__links a:hover,
  .site-nav__links a[aria-current='page'] {
    color: var(--color-text-primary);
    background: var(--color-surface-elevated);
  }

  .site-nav__theme-toggle {
    margin-left: auto;
    flex-shrink: 0;
    width: var(--space-8);
    height: var(--space-8);
    border-radius: var(--radius-sm);
    font-size: var(--text-base);
    display: flex;
    align-items: center;
    justify-content: center;
    transition: var(--transition-colors);
  }

  .site-nav__theme-toggle:hover {
    background: var(--color-surface-elevated);
  }

  .site-main {
    flex: 1;
    min-height: calc(100dvh - var(--layout-nav-height));
    max-width: calc(var(--layout-content-max) + var(--layout-page-gutter) * 2);
    width: 100%;
    margin-inline: auto;
    padding-inline: var(--layout-page-gutter);
    padding-block: var(--layout-section-gap);
  }
</style>
