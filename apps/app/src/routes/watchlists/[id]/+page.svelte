<script lang="ts">
  import type { Severity, WatchlistMatchCounts, WatchlistMatchStatus } from '@threat-lens/contracts';
  import { invalidateAll } from '$app/navigation';
  import { adminFetch, getAdminToken, setAdminToken } from '$lib/client/adminToken';
  import type { PageData } from './$types';

  interface Props {
    data: PageData;
  }
  let { data }: Props = $props();

  const wl = $derived(data.detail);

  // --- Admin editing (gated by the admin token in sessionStorage) ---
  let adminToken = $state('');
  let busy = $state(false);
  let errorMsg = $state('');
  let newVendor = $state('');
  let newProduct = $state('');
  let newWebhookUrl = $state('');
  let newWebhookKind = $state<'generic' | 'slack'>('generic');

  $effect(() => {
    adminToken = getAdminToken();
  });

  function saveToken() {
    setAdminToken(adminToken.trim());
  }

  const ALL_STATUSES: WatchlistMatchStatus[] = [
    'NEW',
    'TRIAGING',
    'ACKNOWLEDGED',
    'RESOLVED',
    'IGNORED',
  ];

  async function run(fn: () => Promise<unknown>) {
    errorMsg = '';
    busy = true;
    try {
      await fn();
      await invalidateAll();
    } catch (err) {
      errorMsg = err instanceof Error ? err.message : 'Action failed';
    } finally {
      busy = false;
    }
  }

  function addSub(e: Event) {
    e.preventDefault();
    if (!newVendor.trim()) return;
    run(async () => {
      await adminFetch(`/api/watchlists/${wl.watchlistId}/subscriptions`, 'POST', {
        vendor: newVendor.trim(),
        ...(newProduct.trim() && { product: newProduct.trim() }),
      });
      newVendor = '';
      newProduct = '';
    });
  }

  function removeSub(subscriptionId: number) {
    run(() =>
      adminFetch(
        `/api/watchlists/${wl.watchlistId}/subscriptions/${subscriptionId}`,
        'DELETE',
      ),
    );
  }

  function changeStatus(cveId: string, status: string) {
    run(() =>
      adminFetch(`/api/watchlists/${wl.watchlistId}/matches/${cveId}`, 'PATCH', { status }),
    );
  }

  function addWebhook(e: Event) {
    e.preventDefault();
    if (!newWebhookUrl.trim()) return;
    run(async () => {
      await adminFetch(`/api/watchlists/${wl.watchlistId}/webhooks`, 'POST', {
        url: newWebhookUrl.trim(),
        kind: newWebhookKind,
      });
      newWebhookUrl = '';
    });
  }

  function removeWebhook(webhookId: number) {
    run(() => adminFetch(`/api/watchlists/${wl.watchlistId}/webhooks/${webhookId}`, 'DELETE'));
  }

  function deleteWatchlist() {
    if (!confirm(`Delete watchlist "${wl.name}" and all its matches? This cannot be undone.`)) {
      return;
    }
    run(async () => {
      await adminFetch(`/api/watchlists/${wl.watchlistId}`, 'DELETE');
      window.location.href = '/watchlists';
    });
  }

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

  <details class="admin-panel">
    <summary>Admin actions</summary>
    <div class="admin-body">
      <label class="field">
        <span class="field__label">Admin token</span>
        <input
          class="field__input"
          type="password"
          bind:value={adminToken}
          onblur={saveToken}
          placeholder="ADMIN_BEARER — stored in this tab only"
          autocomplete="off"
        />
      </label>

      <form class="inline-form" onsubmit={addSub}>
        <label class="field">
          <span class="field__label">Add subscription — vendor</span>
          <input class="field__input" bind:value={newVendor} placeholder="e.g. apache" />
        </label>
        <label class="field">
          <span class="field__label">Product (optional — blank = all)</span>
          <input class="field__input" bind:value={newProduct} placeholder="e.g. http_server" />
        </label>
        <button class="btn-primary" type="submit" disabled={busy || !newVendor.trim()}>Add</button>
      </form>

      <form class="inline-form" onsubmit={addWebhook}>
        <label class="field">
          <span class="field__label">Notification webhook URL (https)</span>
          <input class="field__input" bind:value={newWebhookUrl} placeholder="https://hooks.slack.com/…" />
        </label>
        <label class="field field--narrow">
          <span class="field__label">Kind</span>
          <select class="field__input" bind:value={newWebhookKind}>
            <option value="generic">Generic</option>
            <option value="slack">Slack</option>
          </select>
        </label>
        <button class="btn-primary" type="submit" disabled={busy || !newWebhookUrl.trim()}>Add webhook</button>
      </form>

      {#if wl.webhooks.length > 0}
        <ul class="webhook-list" role="list">
          {#each wl.webhooks as wh (wh.webhookId)}
            <li class="webhook-row">
              <span class="webhook-kind">{wh.kind}</span>
              <span class="webhook-url">{wh.url}</span>
              <button class="btn-danger-sm" type="button" disabled={busy} onclick={() => removeWebhook(wh.webhookId)}>Remove</button>
            </li>
          {/each}
        </ul>
      {/if}

      <button class="btn-danger" type="button" disabled={busy} onclick={deleteWatchlist}>
        Delete this watchlist
      </button>

      {#if errorMsg}
        <p class="admin-error" role="alert">{errorMsg}</p>
      {/if}
    </div>
  </details>

  <section class="wl-subs" aria-label="Subscriptions">
    <h2 class="section-title">Subscriptions</h2>
    {#if wl.subscriptions.length === 0}
      <p class="empty-state">
        No subscriptions. This watchlist matches nothing until a vendor or product is added.
      </p>
    {:else}
      <ul class="sub-list" role="list">
        {#each wl.subscriptions as sub (sub.subscriptionId)}
          <li class="sub-chip">
            {subLabel(sub.vendor, sub.product)}
            <button
              class="sub-remove"
              type="button"
              disabled={busy}
              aria-label="Remove subscription {subLabel(sub.vendor, sub.product)}"
              onclick={() => removeSub(sub.subscriptionId)}
            >×</button>
          </li>
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
              <th>Priority</th>
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
              <tr class:row-accepted={m.riskAccepted}>
                <td>
                  {#if m.riskAccepted}
                    <span class="prio-badge prio-badge--accepted" title="Risk accepted (active)">ACCEPTED</span>
                  {:else if m.priorityBand}
                    <span
                      class="prio-badge prio-badge--{m.priorityBand.toLowerCase()}"
                      title={m.priorityRationale ?? ''}
                    >{m.priorityScore} · {m.priorityBand}</span>
                  {:else}
                    <span class="prio-badge prio-badge--none">—</span>
                  {/if}
                </td>
                <td><a class="cve-link" href="/cve/{m.cveId}">{m.cveId}</a></td>
                <td style={m.severity ? `color:${SEV_COLOR[m.severity]}` : ''}>
                  {m.severity ?? '—'}
                </td>
                <td>{m.cvssBase !== null ? m.cvssBase.toFixed(1) : '—'}</td>
                <td>{m.kevListed ? '⚠ KEV' : '—'}</td>
                <td>{m.epssPercentile !== null ? `${(m.epssPercentile * 100).toFixed(1)}th` : '—'}</td>
                <td>
                  <select
                    class="status-select status-select--{m.status.toLowerCase()}"
                    value={m.status}
                    disabled={busy}
                    aria-label="Triage status for {m.cveId}"
                    onchange={(e) => changeStatus(m.cveId, (e.currentTarget as HTMLSelectElement).value)}
                  >
                    {#each ALL_STATUSES as s}
                      <option value={s}>{s}</option>
                    {/each}
                  </select>
                </td>
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

  /* --- Admin panel --- */
  .admin-panel {
    margin-block: var(--space-4) var(--space-2);
    border: 1px solid var(--color-border-subtle);
    border-radius: var(--radius-md);
    background: var(--color-surface-raised);
  }
  .admin-panel summary {
    padding: var(--space-3) var(--space-4);
    font-size: var(--text-sm);
    font-weight: var(--weight-medium);
    color: var(--color-text-secondary);
    cursor: pointer;
  }
  .admin-body {
    padding: 0 var(--space-4) var(--space-4);
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
  }
  .inline-form {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-end;
    gap: var(--space-3);
  }
  .field {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
    flex: 1;
    min-width: 12rem;
  }
  .field--narrow {
    flex: 0 0 8rem;
    min-width: 8rem;
  }
  .field__label {
    font-size: var(--text-xs);
    color: var(--color-text-tertiary);
  }
  .field__input {
    padding: var(--space-2) var(--space-3);
    background: var(--color-surface-base);
    border: 1px solid var(--color-border-default);
    border-radius: var(--radius-sm);
    color: var(--color-text-primary);
    font-size: var(--text-sm);
  }
  .btn-primary {
    padding: var(--space-2) var(--space-4);
    background: var(--color-brand-500);
    color: #fff;
    border-radius: var(--radius-sm);
    font-size: var(--text-sm);
    font-weight: var(--weight-medium);
    white-space: nowrap;
  }
  .btn-primary:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  .btn-danger {
    align-self: flex-start;
    padding: var(--space-2) var(--space-4);
    background: transparent;
    color: #fca5a5;
    border: 1px solid color-mix(in srgb, #ef4444 40%, transparent);
    border-radius: var(--radius-sm);
    font-size: var(--text-sm);
  }
  .btn-danger:disabled {
    opacity: 0.5;
  }
  .btn-danger-sm {
    padding: 2px var(--space-2);
    color: #fca5a5;
    font-size: var(--text-xs);
  }
  .admin-error {
    font-size: var(--text-sm);
    color: #fca5a5;
    margin: 0;
  }

  .webhook-list {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
  }
  .webhook-row {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    font-size: var(--text-xs);
  }
  .webhook-kind {
    font-family: var(--font-mono);
    color: var(--color-text-tertiary);
    text-transform: uppercase;
  }
  .webhook-url {
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: var(--color-text-secondary);
  }

  .sub-remove {
    margin-inline-start: var(--space-1);
    color: var(--color-text-tertiary);
    font-size: var(--text-sm);
    line-height: 1;
  }
  .sub-remove:hover {
    color: #fca5a5;
  }

  .status-select {
    padding: 2px var(--space-2);
    font-size: var(--text-2xs);
    font-weight: var(--weight-medium);
    border-radius: var(--radius-full);
    border: 1px solid var(--color-border-default);
    background: var(--color-surface-base);
    color: var(--color-text-secondary);
    cursor: pointer;
  }
  .status-select--new {
    color: #fca5a5;
  }
  .status-select--triaging {
    color: #fdba74;
  }
  .status-select--acknowledged {
    color: #fde047;
  }
  .status-select--resolved {
    color: #86efac;
  }
  .status-select--ignored {
    color: var(--color-text-tertiary);
  }

  .prio-badge {
    display: inline-block;
    font-size: var(--text-2xs);
    font-weight: var(--weight-semibold);
    font-family: var(--font-mono);
    padding: 2px var(--space-2);
    border-radius: var(--radius-sm);
    white-space: nowrap;
    cursor: help;
  }
  .prio-badge--critical {
    background: color-mix(in srgb, #ef4444 22%, transparent);
    color: #fca5a5;
  }
  .prio-badge--high {
    background: color-mix(in srgb, #f97316 20%, transparent);
    color: #fdba74;
  }
  .prio-badge--moderate {
    background: color-mix(in srgb, #eab308 18%, transparent);
    color: #fde047;
  }
  .prio-badge--low {
    background: var(--color-surface-overlay);
    color: var(--color-text-secondary);
  }
  .prio-badge--none {
    color: var(--color-text-tertiary);
    cursor: default;
  }
  .prio-badge--accepted {
    background: var(--color-surface-overlay);
    color: var(--color-text-tertiary);
    cursor: help;
  }
  .row-accepted {
    opacity: 0.55;
  }
</style>
