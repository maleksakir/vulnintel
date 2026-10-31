<script lang="ts">
  import { invalidateAll } from '$app/navigation';
  import { adminFetch, getAdminToken, setAdminToken } from '$lib/client/adminToken';
  import type { PageData } from './$types';

  interface Props {
    data: PageData;
  }
  let { data }: Props = $props();

  function isoToDate(iso: string) {
    return new Date(iso).toLocaleDateString(undefined, { dateStyle: 'medium' });
  }

  let adminToken = $state('');
  let busy = $state(false);
  let errorMsg = $state('');

  $effect(() => {
    adminToken = getAdminToken();
  });
  function saveToken() {
    setAdminToken(adminToken.trim());
  }

  async function revoke(cveId: string) {
    if (!confirm(`Revoke the risk acceptance for ${cveId}? It becomes actionable again now.`)) {
      return;
    }
    errorMsg = '';
    busy = true;
    try {
      await adminFetch(`/api/remediation/${cveId}`, 'DELETE');
      await invalidateAll();
    } catch (err) {
      errorMsg = err instanceof Error ? err.message : 'Revoke failed';
    } finally {
      busy = false;
    }
  }

  const active = $derived(data.acceptances.filter((a) => a.active));
  const expired = $derived(data.acceptances.filter((a) => !a.active));
</script>

<svelte:head>
  <title>Remediation — Threat-Lens CVE Hub</title>
</svelte:head>

<div class="page-remediation">
  <h1 class="page-title">Remediation — Risk Acceptances</h1>
  <p class="page-intro">
    CVEs formally risk-accepted for a bounded time with a written justification. An acceptance
    auto-reactivates (the CVE becomes actionable again) the moment it expires. Accept or extend an
    acceptance from a CVE's detail page.
  </p>

  <details class="admin-panel">
    <summary>Admin token</summary>
    <div class="admin-body">
      <label class="field">
        <span class="field__label">Admin token (needed to revoke)</span>
        <input
          class="field__input"
          type="password"
          bind:value={adminToken}
          onblur={saveToken}
          placeholder="ADMIN_BEARER — stored in this tab only"
          autocomplete="off"
        />
      </label>
      {#if errorMsg}<p class="admin-error" role="alert">{errorMsg}</p>{/if}
    </div>
  </details>

  {#if data.acceptances.length === 0}
    <p class="empty-state">No risk acceptances. Accept one from any CVE's detail page.</p>
  {:else}
    {#if active.length > 0}
      <h2 class="section-title">Active ({active.length})</h2>
      <div class="table-wrap">
        <table class="data-table">
          <thead>
            <tr><th>CVE</th><th>Justification</th><th>Accepted by</th><th>Expires</th><th></th></tr>
          </thead>
          <tbody>
            {#each active as a (a.cveId)}
              <tr>
                <td><a class="cve-link" href="/cve/{a.cveId}">{a.cveId}</a></td>
                <td class="just">{a.justification}</td>
                <td>{a.acceptedBy ?? '—'}</td>
                <td>{isoToDate(a.expiresAt)}</td>
                <td>
                  <button class="btn-revoke" type="button" disabled={busy} onclick={() => revoke(a.cveId)}>Revoke</button>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}

    {#if expired.length > 0}
      <h2 class="section-title">Recently expired ({expired.length})</h2>
      <div class="table-wrap">
        <table class="data-table expired">
          <thead>
            <tr><th>CVE</th><th>Justification</th><th>Expired</th></tr>
          </thead>
          <tbody>
            {#each expired as a (a.cveId)}
              <tr>
                <td><a class="cve-link" href="/cve/{a.cveId}">{a.cveId}</a></td>
                <td class="just">{a.justification}</td>
                <td>{isoToDate(a.expiresAt)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  {/if}
</div>

<style>
  .page-title {
    font-size: var(--text-2xl);
    font-weight: var(--weight-semibold);
    margin: 0 0 var(--space-2);
    color: var(--color-text-primary);
  }
  .page-intro {
    font-size: var(--text-sm);
    color: var(--color-text-tertiary);
    margin: 0 0 var(--space-6);
    max-width: 48rem;
  }
  .section-title {
    font-size: var(--text-base);
    font-weight: var(--weight-semibold);
    color: var(--color-text-primary);
    margin: var(--space-6) 0 var(--space-3);
  }
  .admin-panel {
    margin-block-end: var(--space-6);
    border: 1px solid var(--color-border-subtle);
    border-radius: var(--radius-md);
    background: var(--color-surface-raised);
  }
  .admin-panel summary {
    padding: var(--space-3) var(--space-4);
    font-size: var(--text-sm);
    color: var(--color-text-secondary);
    cursor: pointer;
  }
  .admin-body {
    padding: 0 var(--space-4) var(--space-4);
  }
  .field {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
    max-width: 32rem;
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
  .admin-error {
    font-size: var(--text-sm);
    color: #fca5a5;
    margin: var(--space-2) 0 0;
  }
  .empty-state {
    color: var(--color-text-secondary);
    font-size: var(--text-sm);
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
    vertical-align: top;
  }
  .data-table.expired {
    opacity: 0.6;
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
  .just {
    max-width: 32rem;
    font-size: var(--text-xs);
    line-height: 1.5;
  }
  .btn-revoke {
    padding: 2px var(--space-2);
    font-size: var(--text-xs);
    color: #fca5a5;
    border: 1px solid color-mix(in srgb, #ef4444 35%, transparent);
    border-radius: var(--radius-sm);
  }
  .btn-revoke:disabled {
    opacity: 0.5;
  }
</style>
