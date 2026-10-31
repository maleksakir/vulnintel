<script lang="ts">
  import { invalidateAll } from '$app/navigation';
  import { adminFetch, getAdminToken, setAdminToken } from '$lib/client/adminToken';
  import AdminSignIn from '$lib/ui/AdminSignIn.svelte';
  import type { PageData } from './$types';

  interface Props {
    data: PageData;
  }
  let { data }: Props = $props();

  function isoToDate(iso: string | null) {
    return iso ? new Date(iso).toLocaleDateString(undefined, { dateStyle: 'medium' }) : 'never';
  }

  let adminToken = $state('');
  let newName = $state('');
  let newDesc = $state('');
  let busy = $state(false);
  let errorMsg = $state('');

  $effect(() => {
    adminToken = getAdminToken();
  });
  function saveToken() {
    setAdminToken(adminToken.trim());
  }

  async function createAsset(e: Event) {
    e.preventDefault();
    errorMsg = '';
    if (!newName.trim()) return;
    busy = true;
    try {
      await adminFetch('/api/assets', 'POST', {
        name: newName.trim(),
        ...(newDesc.trim() && { description: newDesc.trim() }),
      });
      newName = '';
      newDesc = '';
      await invalidateAll();
    } catch (err) {
      errorMsg = err instanceof Error ? err.message : 'Failed to create asset';
    } finally {
      busy = false;
    }
  }
</script>

<svelte:head>
  <title>Assets — Threat-Lens CVE Hub</title>
</svelte:head>

{#if !data.authed}
<AdminSignIn what="The asset inventory" />
{:else}
<div class="page-assets">
  <h1 class="page-title">Asset Inventory</h1>
  <p class="page-intro">
    Import a CycloneDX SBOM per application; its components are matched to known CVEs
    (package-URL first, falling back to vendor/product) so you can see what's affected.
  </p>

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
      <form class="create-form" onsubmit={createAsset}>
        <label class="field">
          <span class="field__label">New asset name</span>
          <input class="field__input" bind:value={newName} maxlength="120" placeholder="e.g. billing-api" />
        </label>
        <label class="field">
          <span class="field__label">Description (optional)</span>
          <input class="field__input" bind:value={newDesc} maxlength="500" />
        </label>
        <button class="btn-primary" type="submit" disabled={busy || !newName.trim()}>
          {busy ? 'Creating…' : 'Create asset'}
        </button>
      </form>
      {#if errorMsg}<p class="admin-error" role="alert">{errorMsg}</p>{/if}
    </div>
  </details>

  {#if data.assets.length === 0}
    <div class="empty-state">
      <p>No assets yet.</p>
      <p class="empty-hint">Create an asset, then import its SBOM from the asset's page.</p>
    </div>
  {:else}
    <div class="table-wrap">
      <table class="data-table">
        <thead>
          <tr>
            <th>Asset</th>
            <th>Components</th>
            <th>Vulnerable components</th>
            <th>CVEs</th>
            <th>Last import</th>
          </tr>
        </thead>
        <tbody>
          {#each data.assets as a (a.assetId)}
            <tr>
              <td>
                <a class="asset-link" href="/assets/{a.assetId}">{a.name}</a>
                {#if a.description}<span class="asset-desc">{a.description}</span>{/if}
              </td>
              <td>{a.componentCount}</td>
              <td>
                <span class:vuln={a.vulnerableComponentCount > 0}>{a.vulnerableComponentCount}</span>
              </td>
              <td><span class:vuln={a.vulnerableCveCount > 0}>{a.vulnerableCveCount}</span></td>
              <td>{isoToDate(a.lastImportAt)}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>
{/if}

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
  .admin-panel {
    margin-block-end: var(--space-6);
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
  .create-form {
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
    min-width: 14rem;
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
  .admin-error {
    font-size: var(--text-sm);
    color: #fca5a5;
    margin: 0;
  }
  .empty-state {
    padding: var(--space-8);
    border: 1px dashed var(--color-border-default);
    border-radius: var(--radius-lg);
    color: var(--color-text-secondary);
    text-align: center;
  }
  .empty-hint {
    font-size: var(--text-sm);
    color: var(--color-text-tertiary);
    margin-block-start: var(--space-2);
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
    padding: var(--space-3);
    color: var(--color-text-secondary);
    border-bottom: 1px solid var(--color-border-subtle);
    vertical-align: top;
  }
  .asset-link {
    color: var(--color-brand-400);
    text-decoration: none;
    font-weight: var(--weight-medium);
  }
  .asset-link:hover {
    text-decoration: underline;
  }
  .asset-desc {
    display: block;
    font-size: var(--text-xs);
    color: var(--color-text-tertiary);
    margin-block-start: 2px;
  }
  .vuln {
    color: #fca5a5;
    font-weight: var(--weight-semibold);
  }
</style>
