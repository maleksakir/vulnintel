<script lang="ts">
  import type { Severity, WatchlistMatchCounts, WatchlistMatchStatus } from '@threat-lens/contracts';
  import type { PageData } from './$types';

  interface Props {
    data: PageData;
  }
  let { data }: Props = $props();

  const wl = $derived(data.detail);

  const SEV_COLOR: Record<Severity, string> = {
    CRITICAL: '#ef4444',
    HIGH: '#f97316',
    MEDIUM: '#eab308',
    LOW: '#22c55e',
    NONE: '#6b7280',
  };

  const STATUS_ORDER: Array<keyof WatchlistMatchCounts> = [
    'NEW',
    'TRIAGING',
    'ACKNOWLEDGED',
    'RESOLVED',
    'IGNORED',
  ];

  function isoToDate(iso: string) {
    return new Date(iso).toLocaleDateString(undefined, { dateStyle: 'medium' });
  }

  function statusHref(status: WatchlistMatchStatus | null): string {
    const base = `/watchlists/${wl.watchlistId}`;
    return status ? `${base}?status=${status}` : base;
  }

  function nextHref(cursor: string | null): string | null {
    if (!cursor) return null;
    const params = new URLSearchParams();
    if (data.activeStatus) params.set('status', data.activeStatus);
    params.set('cursor', cursor);
    return `/watchlists/${wl.watchlistId}?${params.toString()}`;
  }

  function subLabel(vendor: string, product: string | null): string {
    return product ? `${vendor} / ${product}` : `${vendor} (all products)`;
  }

  const totalMatches = $derived(STATUS_ORDER.reduce((sum, s) => sum + wl.matchCounts[s], 0));
</script>

<svelte:head>
  <title>{wl.name} — Watchlists — Threat-Lens CVE Hub</title>
</svelte:head>

<div class="page-wl-detail">
  <nav class="breadcrumb" aria-label="Breadcrumb">
    <a href="/watchlists">Watchlists</a>
    <span aria-hidden="true">/</span>
    <span>{wl.name}</span>
  </nav>

  <header class="wl-head">
    <h1 class="page-title">{wl.name}</h1>
    {#if wl.description}
      <p class="wl-desc">{wl.description}</p>
    {/if}
    <p class="wl-meta">Created {isoToDate(wl.createdAt)} · updated {isoToDate(wl.updatedAt)}</p>
  </header>

  <section class="wl-subs" aria-label="Subscriptions">
    <h2 class="section-title">Subscriptions</h2>
    {#if wl.subscriptions.length === 0}
      <p class="empty-state">
        No subscriptions. This watchlist matches nothing until a vendor or product is added.
      </p>
    {:else}
      <ul class="sub-list" role="list">
        {#each wl.subscriptions as sub (sub.subscriptionId)}
          <li class="sub-chip">{subLabel(sub.vendor, sub.product)}</li>
        {/each}
      </ul>
    {/if}
  </section>

  <section class="wl-matches" aria-label="Matched CVEs">
    <h2 class="section-title">Matched CVEs ({totalMatches})</h2>

    <nav class="tab-nav" aria-label="Filter matches by status">
      <a
        class="tab-link"
        class:tab-link--active={data.activeStatus === null}
        href={statusHref(null)}
        aria-current={data.activeStatus === null ? 'page' : undefined}
      >All</a>
      {#each STATUS_ORDER as status}
        <a
          class="tab-link"
          class:tab-link--active={data.activeStatus === status}
          href={statusHref(status)}
          aria-current={data.activeStatus === status ? 'page' : undefined}
        >{status} ({wl.matchCounts[status]})</a>
      {/each}
    </nav>

    {#if wl.matches.length === 0}
      <p class="empty-state">No CVEs in this view.</p>
    {:else}
      <div class="table-wrap">
        <table class="data-table">
          <thead>
            <tr>
              <th>CVE ID</th>
              <th>Severity</th>
              <th>CVSS</th>
              <th>KEV</th>
              <th>EPSS pct</th>
              <th>Status</th>
              <th>First matched</th>
            </tr>
          </thead>
          <tbody>
            {#each wl.matches as m (m.cveId)}
              <tr>
                <td><a class="cve-link" href="/cve/{m.cveId}">{m.cveId}</a></td>
                <td style={m.severity ? `color:${SEV_COLOR[m.severity]}` : ''}>
                  {m.severity ?? '—'}
                </td>
                <td>{m.cvssBase !== null ? m.cvssBase.toFixed(1) : '—'}</td>
                <td>{m.kevListed ? '⚠ KEV' : '—'}</td>
                <td>{m.epssPercentile !== null ? `${(m.epssPercentile * 100).toFixed(1)}th` : '—'}</td>
                <td><span class="status-pill status-pill--{m.status.toLowerCase()}">{m.status}</span></td>
                <td>{isoToDate(m.firstMatchedAt)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>

      {#if wl.nextCursor}
        {@const href = nextHref(wl.nextCursor)}
        {#if href}
          <div class="pagination">
            <a class="pagination-btn" {href}>Next page →</a>
          </div>
        {/if}
      {/if}
    {/if}
  </section>
</div>

<style>
  .breadcrumb {
    display: flex;
    gap: var(--space-2);
    font-size: var(--text-sm);
    color: var(--color-text-tertiary);
    margin-block-end: var(--space-4);
  }
  .breadcrumb a {
    color: var(--color-brand-400);
    text-decoration: none;
  }
  .breadcrumb a:hover {
    text-decoration: underline;
  }

  .page-title {
    font-size: var(--text-2xl);
    font-weight: var(--weight-semibold);
    margin: 0;
    color: var(--color-text-primary);
  }
  .wl-desc {
    font-size: var(--text-sm);
    color: var(--color-text-secondary);
    margin: var(--space-2) 0 0;
  }
  .wl-meta {
    font-size: var(--text-xs);
    color: var(--color-text-tertiary);
    margin: var(--space-2) 0 0;
  }

  .section-title {
    font-size: var(--text-base);
    font-weight: var(--weight-semibold);
    color: var(--color-text-primary);
    margin: var(--space-8) 0 var(--space-3);
  }

  .sub-list {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-2);
    list-style: none;
    margin: 0;
    padding: 0;
  }
  .sub-chip {
    font-size: var(--text-xs);
    font-family: var(--font-mono);
    padding: var(--space-1) var(--space-3);
    background: var(--color-surface-raised);
    border: 1px solid var(--color-border-subtle);
    border-radius: var(--radius-full);
    color: var(--color-text-secondary);
  }

  .empty-state {
    color: var(--color-text-secondary);
    font-size: var(--text-sm);
  }

  .tab-nav {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-1);
    margin-block-end: var(--space-4);
    border-bottom: 1px solid var(--color-border-subtle);
  }
  .tab-link {
    padding: var(--space-2) var(--space-3);
    font-size: var(--text-xs);
    font-weight: var(--weight-medium);
    color: var(--color-text-secondary);
    text-decoration: none;
    border-bottom: 2px solid transparent;
    margin-bottom: -1px;
    white-space: nowrap;
    transition: var(--transition-colors);
  }
  .tab-link:hover {
    color: var(--color-text-primary);
  }
  .tab-link--active {
    color: var(--color-brand-400);
    border-bottom-color: var(--color-brand-400);
  }

  .table-wrap {
    overflow-x: auto;
  }
  .data-table {
    width: 100%;
    border-collapse: collapse;
    font-size: var(--text-sm);
  }
  .data-table th {
    text-align: left;
    padding: var(--space-2) var(--space-3);
    font-size: var(--text-xs);
    font-weight: var(--weight-medium);
    color: var(--color-text-tertiary);
    text-transform: uppercase;
    letter-spacing: var(--tracking-wide);
    border-bottom: 1px solid var(--color-border-subtle);
    white-space: nowrap;
  }
  .data-table td {
    padding: var(--space-2) var(--space-3);
    color: var(--color-text-secondary);
    border-bottom: 1px solid var(--color-border-subtle);
  }
  .cve-link {
    font-family: var(--font-mono);
    font-size: var(--text-xs);
    color: var(--color-brand-400);
    text-decoration: none;
  }
  .cve-link:hover {
    text-decoration: underline;
  }

  .status-pill {
    font-size: var(--text-2xs);
    font-weight: var(--weight-medium);
    padding: 2px var(--space-2);
    border-radius: var(--radius-full);
    white-space: nowrap;
  }
  .status-pill--new {
    background: color-mix(in srgb, #ef4444 20%, transparent);
    color: #fca5a5;
  }
  .status-pill--triaging {
    background: color-mix(in srgb, #f97316 20%, transparent);
    color: #fdba74;
  }
  .status-pill--acknowledged {
    background: color-mix(in srgb, #eab308 18%, transparent);
    color: #fde047;
  }
  .status-pill--resolved {
    background: color-mix(in srgb, #22c55e 16%, transparent);
    color: #86efac;
  }
  .status-pill--ignored {
    background: var(--color-surface-overlay);
    color: var(--color-text-tertiary);
  }

  .pagination {
    margin-block-start: var(--space-6);
  }
  .pagination-btn {
    padding: var(--space-2) var(--space-4);
    background: var(--color-surface-raised);
    border: 1px solid var(--color-border-default);
    border-radius: var(--radius-md);
    font-size: var(--text-sm);
    color: var(--color-text-primary);
    text-decoration: none;
  }
  .pagination-btn:hover {
    background: var(--color-surface-elevated);
  }
</style>
