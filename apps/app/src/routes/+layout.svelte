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

  // --- Mobile navigation drawer ---
  // The nav collapses to a hamburger below the tablet breakpoint (≤900px).
  // Closed on every route change so a tap-through doesn't leave it open.
  let mobileNavOpen = $state(false);

  $effect(() => {
    // Touching $page.url.pathname makes this re-run on navigation.
    void $page.url.pathname;
    mobileNavOpen = false;
  });

  const NAV_LINKS = [
    { href: '/', label: 'Dashboard', match: (p: string) => p === '/' },
    { href: '/search', label: 'Search', match: (p: string) => p.startsWith('/search') },
    {
      href: '/affected-products',
      label: 'Affected Products',
      match: (p: string) => p.startsWith('/affected-products'),
    },
    { href: '/threat-intel', label: 'Threat Intel', match: (p: string) => p.startsWith('/threat-intel') },
    { href: '/sbom', label: 'SBOM Scan', match: (p: string) => p.startsWith('/sbom') },
  ];

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
      {#each NAV_LINKS as link}
        <li>
          <a href={link.href} aria-current={link.match($page.url.pathname) ? 'page' : undefined}>
            {link.label}
          </a>
        </li>
      {/each}
    </ul>

    <div class="site-nav__actions">
      <button
        class="site-nav__theme-toggle"
        aria-label="Switch to {theme === 'dark' ? 'light' : 'dark'} mode"
        onclick={toggleTheme}
        type="button"
      >
        {#if theme === 'dark'}
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
            <circle cx="8" cy="8" r="3" stroke="currentColor" stroke-width="1.4"/>
            <path d="M8 1v2M8 13v2M1 8h2M13 8h2M3.1 3.1l1.4 1.4M11.5 11.5l1.4 1.4M11.5 3.1l-1.4 1.4M4.5 11.5l-1.4 1.4" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>
          </svg>
        {:else}
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
            <path d="M13.5 9.5A6 6 0 0 1 6.5 2.5a5.5 5.5 0 1 0 7 7Z" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/>
          </svg>
        {/if}
      </button>

      <!-- Hamburger — only visible ≤900px via CSS -->
      <button
        class="site-nav__burger"
        aria-label="{mobileNavOpen ? 'Close' : 'Open'} navigation menu"
        aria-expanded={mobileNavOpen}
        aria-controls="mobile-nav"
        onclick={() => (mobileNavOpen = !mobileNavOpen)}
        type="button"
      >
        {#if mobileNavOpen}
          <svg width="20" height="20" viewBox="0 0 20 20" fill="none" aria-hidden="true">
            <path d="M5 5l10 10M15 5L5 15" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
          </svg>
        {:else}
          <svg width="20" height="20" viewBox="0 0 20 20" fill="none" aria-hidden="true">
            <path d="M3 6h14M3 10h14M3 14h14" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
          </svg>
        {/if}
      </button>
    </div>
  </nav>

  <!-- Mobile drawer -->
  {#if mobileNavOpen}
    <div class="mobile-nav-backdrop" onclick={() => (mobileNavOpen = false)} aria-hidden="true"></div>
    <nav id="mobile-nav" class="mobile-nav" aria-label="Mobile navigation">
      <ul role="list">
        {#each NAV_LINKS as link}
          <li>
            <a href={link.href} aria-current={link.match($page.url.pathname) ? 'page' : undefined}>
              {link.label}
            </a>
          </li>
        {/each}
      </ul>
    </nav>
  {/if}
</header>

<main id="main-content" class="site-main" tabindex="-1">
  {@render children()}
</main>

<!-- Footer with signature -->
<footer class="site-footer">
  <div class="site-footer__inner">
    <span class="site-footer__brand">Threat-Lens</span>
    <span class="site-footer__sep" aria-hidden="true">·</span>
    <span class="site-footer__by">
      Engineered by <a href="https://github.com/maleksakir" rel="author noopener" target="_blank">Sakir Malek</a>
    </span>
  </div>
</footer>

<!-- Toast region — anchored bottom-right (§2.4) -->
<Toast toasts={toasts} onClose={removeToast} position="bottom-right" />

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
    /* Glassy translucent bar over a hairline cyan underglow — the
       operator-console chrome. */
    background: var(--color-surface-glass);
    backdrop-filter: blur(12px) saturate(140%);
    -webkit-backdrop-filter: blur(12px) saturate(140%);
    border-bottom: 1px solid var(--color-border-default);
    box-shadow: 0 1px 0 hsl(188 92% 52% / 0.08);
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
    font-family: var(--font-mono);
    font-size: var(--text-base);
    font-weight: var(--weight-semibold);
    color: var(--color-text-primary);
    text-decoration: none;
    letter-spacing: var(--tracking-tight);
    flex-shrink: 0;
  }

  .site-nav__logo:hover {
    text-decoration: none;
    color: var(--color-brand-text);
  }

  .site-nav__logo-icon {
    color: var(--color-brand-default);
    flex-shrink: 0;
    filter: drop-shadow(0 0 6px hsl(188 92% 52% / 0.5));
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
    position: relative;
    display: block;
    padding: var(--space-2) var(--space-3);
    font-size: var(--text-sm);
    font-weight: var(--weight-medium);
    color: var(--color-text-secondary);
    text-decoration: none;
    border-radius: var(--radius-sm);
    transition: var(--transition-colors);
  }

  .site-nav__links a:hover {
    color: var(--color-text-primary);
    background: var(--color-surface-elevated);
    text-decoration: none;
  }

  /* Active route: cyan text + a glowing underline bar, like a selected
     channel on a console. */
  .site-nav__links a[aria-current='page'] {
    color: var(--color-brand-text);
    background: var(--color-brand-subtle);
  }
  .site-nav__links a[aria-current='page']::after {
    content: '';
    position: absolute;
    left: var(--space-3);
    right: var(--space-3);
    bottom: calc(-1 * var(--space-2) - 1px);
    height: 2px;
    background: var(--color-brand-default);
    box-shadow: 0 0 8px hsl(188 92% 52% / 0.7);
    border-radius: var(--radius-full);
  }

  .site-nav__actions {
    margin-left: auto;
    display: flex;
    align-items: center;
    gap: var(--space-1);
    flex-shrink: 0;
  }

  .site-nav__theme-toggle,
  .site-nav__burger {
    flex-shrink: 0;
    width: var(--space-8);
    height: var(--space-8);
    border-radius: var(--radius-sm);
    color: var(--color-text-secondary);
    display: flex;
    align-items: center;
    justify-content: center;
    transition: var(--transition-colors);
  }

  .site-nav__theme-toggle:hover,
  .site-nav__burger:hover {
    background: var(--color-surface-elevated);
    color: var(--color-brand-text);
  }

  /* Hamburger is desktop-hidden; shown ≤900px. */
  .site-nav__burger {
    display: none;
  }

  /* ── Mobile drawer ──────────────────────────────────────────────────────── */
  .mobile-nav-backdrop {
    position: fixed;
    inset: var(--layout-nav-height) 0 0;
    background: hsl(210 40% 3% / 0.6);
    backdrop-filter: blur(2px);
    z-index: calc(var(--z-header) - 1);
  }
  .mobile-nav {
    position: fixed;
    top: var(--layout-nav-height);
    left: 0;
    right: 0;
    z-index: var(--z-header);
    background: var(--color-surface-raised);
    border-bottom: 1px solid var(--color-border-default);
    box-shadow: var(--shadow-lg), 0 1px 0 hsl(188 92% 52% / 0.12);
    animation: mobile-nav-in var(--duration-normal) var(--ease-out);
  }
  @keyframes mobile-nav-in {
    from { opacity: 0; transform: translateY(-8px); }
    to   { opacity: 1; transform: translateY(0); }
  }
  .mobile-nav ul {
    list-style: none;
    margin: 0;
    padding: var(--space-2);
    display: flex;
    flex-direction: column;
    gap: var(--space-0_5);
  }
  .mobile-nav a {
    display: block;
    padding: var(--space-3) var(--space-4);
    font-family: var(--font-mono);
    font-size: var(--text-sm);
    letter-spacing: var(--tracking-wide);
    color: var(--color-text-secondary);
    text-decoration: none;
    border-radius: var(--radius-md);
    border-left: 2px solid transparent;
    transition: var(--transition-colors);
  }
  .mobile-nav a:hover {
    background: var(--color-surface-elevated);
    color: var(--color-text-primary);
    text-decoration: none;
  }
  .mobile-nav a[aria-current='page'] {
    color: var(--color-brand-text);
    background: var(--color-brand-subtle);
    border-left-color: var(--color-brand-default);
  }

  @media (prefers-reduced-motion: reduce) {
    .mobile-nav { animation: none; }
  }

  /* ── Footer ─────────────────────────────────────────────────────────────── */
  .site-footer {
    border-top: 1px solid var(--color-border-subtle);
    background: var(--color-surface-sunken);
    margin-top: var(--space-8);
  }
  .site-footer__inner {
    max-width: calc(var(--layout-content-max) + var(--layout-page-gutter) * 2);
    margin-inline: auto;
    padding: var(--space-5) var(--layout-page-gutter);
    display: flex;
    align-items: center;
    gap: var(--space-2);
    flex-wrap: wrap;
    font-size: var(--text-xs);
    color: var(--color-text-tertiary);
  }
  .site-footer__brand {
    font-family: var(--font-mono);
    font-weight: var(--weight-semibold);
    letter-spacing: var(--tracking-wide);
    color: var(--color-brand-text);
  }
  .site-footer__sep { opacity: 0.5; }
  .site-footer__by a {
    color: var(--color-text-secondary);
    font-weight: var(--weight-medium);
    text-decoration: none;
    border-bottom: 1px dotted var(--color-border-strong);
    transition: var(--transition-colors);
  }
  .site-footer__by a:hover {
    color: var(--color-brand-text);
    border-bottom-color: var(--color-brand-default);
    text-decoration: none;
  }

  /* ── Responsive: collapse inline nav to the hamburger ≤900px ──────────────── */
  @media (max-width: 900px) {
    .site-nav__links {
      display: none;
    }
    .site-nav__burger {
      display: flex;
    }
  }

  .site-main {
    /* flex:1 fills the remaining column height so the footer sits at the
       bottom on short pages (the root flex column is set on <body> in
       app.css). We intentionally do NOT set a min-height here: the old
       `min-height: calc(100dvh - nav-height)` made main nearly a full
       viewport tall on its own, so the footer + its margin were appended
       BELOW that and overshot the viewport — the blank band under the
       footer. flex:1 against a 100dvh flex-column body is the correct
       sticky-footer mechanism. */
    flex: 1 0 auto;
    max-width: calc(var(--layout-content-max) + var(--layout-page-gutter) * 2);
    width: 100%;
    margin-inline: auto;
    padding-inline: var(--layout-page-gutter);
    padding-block: var(--layout-section-gap);
  }

  /* Tighter gutters + nav gap on phones so content gets the full width. */
  @media (max-width: 600px) {
    .site-nav { gap: var(--space-3); padding-inline: var(--space-4); }
    .site-main {
      padding-inline: var(--space-4);
      padding-block: var(--space-6);
    }
    .site-footer__inner { padding-inline: var(--space-4); }
  }
</style>
