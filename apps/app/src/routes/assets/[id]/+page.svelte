<script lang="ts">
  import type { Severity } from '@threat-lens/contracts';
  import { invalidateAll } from '$app/navigation';
  import { adminFetch, getAdminToken, setAdminToken } from '$lib/client/adminToken';
  import type { PageData } from './$types';

  interface Props {
    data: PageData;
  }
  let { data }: Props = $props();
  const asset = $derived(data.detail);

  const SEV_COLOR: Record<Severity, string> = {
    CRITICAL: '#ef4444',
    HIGH: '#f97316',
    MEDIUM: '#eab308',
    LOW: '#22c55e',
    NONE: '#6b7280',
  };

  function isoToDate(iso: string | null) {
    return iso ? new Date(iso).toLocaleDateString(undefined, { dateStyle: 'medium' }) : 'never';
  }

  let adminToken = $state('');
  let busy = $state(false);
  let errorMsg = $state('');
  let importMsg = $state('');

  $effect(() => {
    adminToken = getAdminToken();
  });
  function saveToken() {
    setAdminToken(adminToken.trim());
  }

  async function onFileChange(e: Event) {
    const input = e.currentTarget as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) return;
    errorMsg = '';
    importMsg = '';
    busy = true;
    try {
      const text = await file.text();
      let json: unknown;
      try {
        json = JSON.parse(text);
      } catch {
        throw new Error('File is not valid JSON');
      }
      const result = (await adminFetch(`/api/assets/${asset.assetId}/import`, 'POST', json)) as {
        componentsImported: number;
        componentsSkipped: number;
        matchesFound: number;
      };
      importMsg = `Imported ${result.componentsImported} components (${result.componentsSkipped} skipped), ${result.matchesFound} CVE matches.`;
      await invalidateAll();
    } catch (err) {
      errorMsg = err instanceof Error ? err.message : 'Import failed';
    } finally {
      busy = false;
      input.value = '';
    }
  }

  async function deleteAsset() {
    if (!confirm(`Delete asset "${asset.name}" and its SBOM? This cannot be undone.`)) return;
    busy = true;
    try {
      await adminFetch(`/api/assets/${asset.assetId}`, 'DELETE');
      window.location.href = '/assets';
    } catch (err) {
      errorMsg = err instanceof Error ? err.message : 'Delete failed';
      busy = false;
    }
  }
</script>

<svelte:head>
  <title>{asset.name} — Assets — Threat-Lens CVE Hub</title>
</svelte:head>

<div class="page-asset-detail">
  <nav class="breadcrumb" aria-label="Breadcrumb">
    <a href="/assets">Assets</a>
    <span aria-hidden="true">/</span>
    <span>{asset.name}</span>
  </nav>

  <header class="asset-head">
    <h1 class="page-title">{asset.name}</h1>
    {#if asset.description}<p class="asset-desc">{asset.description}</p>{/if}
    <p class="asset-meta">
      {asset.componentCount} components · last import {isoToDate(asset.lastImportAt)}
    </p>
  </header>

  <details class="admin-panel">
    <summary>Admin actions — import SBOM</summary>
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
      <label class="field">
        <span class="field__label">Import CycloneDX SBOM (JSON)</span>
        <input class="field__input" type="file" accept=".json,application/json" onchange={onFileChange} disabled={busy} />
      </label>
      {#if importMsg}<p class="import-ok" role="status">{importMsg}</p>{/if}
      {#if errorMsg}<p class="admin-error" role="alert">{errorMsg}</p>{/if}
      <button class="btn-danger" type="button" disabled={busy} onclick={deleteAsset}>Delete this asset</button>
    </div>
  </details>

  {#if asset.componentCount === 0}
    <p class="empty-state">No components yet — import a CycloneDX SBOM above.</p>
  {:else}
    <section aria-label="Most vulnerable components">
      <h2 class="section-title">Components ({asset.componentCount})</h2>
      <div class="table-wrap">
        <table class="data-table">
          <thead>
            <tr><th>Component</th><th>Version</th><th>Ecosystem</th><th>CVEs</th><th>Max severity</th><th>KEV</th></tr>
          </thead>
          <tbody>
            {#each asset.components as c (c.componentId)}
              <tr>
                <td class="mono">{c.name}</td>
                <td class="mono">{c.version ?? '—'}</td>
                <td>{c.ecosystem ?? '—'}</td>
                <td><span class:vuln={c.cveCount > 0}>{c.cveCount}</span></td>
                <td style={c.maxSeverity ? `color:${SEV_COLOR[c.maxSeverity]}` : ''}>
                  {c.maxSeverity ?? '—'}
                </td>
                <td>{c.hasKev ? '⚠ KEV' : '—'}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </section>

    <section aria-label="Matched CVEs">
      <h2 class="section-title">Affected CVEs</h2>
      {#if asset.cves.length === 0}
        <p class="empty-state">No known CVEs match this asset's components. 🎉</p>
      {:else}
        <div class="table-wrap">
          <table class="data-table">
            <thead>
              <tr><th>CVE ID</th><th>Severity</th><th>CVSS</th><th>KEV</th><th>EPSS pct</th><th>Component</th><th>Via</th></tr>
            </thead>
            <tbody>
              {#each asset.cves as v (v.cveId)}
                <tr class:row-accepted={v.riskAccepted}>
                  <td>
                    <a class="cve-link" href="/cve/{v.cveId}">{v.cveId}</a>
                    {#if v.riskAccepted}<span class="accepted-tag" title="Risk accepted (active)">accepted</span>{/if}
                  </td>
                  <td style={v.severity ? `color:${SEV_COLOR[v.severity]}` : ''}>{v.severity ?? '—'}</td>
                  <td>{v.cvssBase !== null ? v.cvssBase.toFixed(1) : '—'}</td>
                  <td>{v.kevListed ? '⚠ KEV' : '—'}</td>
                  <td>{v.epssPercentile !== null ? `${(v.epssPercentile * 100).toFixed(1)}th` : '—'}</td>
                  <td class="mono">{v.componentName}{v.componentVersion ? `@${v.componentVersion}` : ''}</td>
                  <td><span class="via via--{v.matchVia.toLowerCase()}">{v.matchVia}</span></td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
        {#if asset.cveCursor}
          <div class="pagination">
            <a class="pagination-btn" href="/assets/{asset.assetId}?cursor={encodeURIComponent(asset.cveCursor)}">Next page →</a>
          </div>
        {/if}
      {/if}
    </section>
  {/if}
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
  .page-title {
    font-size: var(--text-2xl);
    font-weight: var(--weight-semibold);
    margin: 0;
    color: var(--color-text-primary);
  }
  .asset-desc {
    font-size: var(--text-sm);
    color: var(--color-text-secondary);
    margin: var(--space-2) 0 0;
  }
  .asset-meta {
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
  .field {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
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
  .btn-danger {
    align-self: flex-start;
    padding: var(--space-2) var(--space-4);
    background: transparent;
    color: #fca5a5;
    border: 1px solid color-mix(in srgb, #ef4444 40%, transparent);
    border-radius: var(--radius-sm);
    font-size: var(--text-sm);
  }
  .import-ok {
    font-size: var(--text-sm);
    color: #86efac;
    margin: 0;
  }
  .admin-error {
    font-size: var(--text-sm);
    color: #fca5a5;
    margin: 0;
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
  }
  .mono {
    font-family: var(--font-mono);
    font-size: var(--text-xs);
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
  .vuln {
    color: #fca5a5;
    font-weight: var(--weight-semibold);
  }
  .via {
    font-size: var(--text-2xs);
    font-family: var(--font-mono);
    padding: 1px var(--space-2);
    border-radius: var(--radius-sm);
  }
  .via--purl {
    background: color-mix(in srgb, #22c55e 16%, transparent);
    color: #86efac;
  }
  .via--cpe {
    background: var(--color-surface-overlay);
    color: var(--color-text-tertiary);
  }
  .row-accepted {
    opacity: 0.55;
  }
  .accepted-tag {
    margin-inline-start: var(--space-2);
    font-size: var(--text-2xs);
    padding: 1px var(--space-2);
    border-radius: var(--radius-sm);
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
</style>
