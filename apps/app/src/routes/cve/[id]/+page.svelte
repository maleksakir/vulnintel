<script lang="ts">
  import { invalidateAll } from '$app/navigation';
  import { adminFetch, getAdminToken, setAdminToken } from '$lib/client/adminToken';
  import SeverityBadge from '$lib/ui/SeverityBadge.svelte';
  import type { PageData } from './$types';

  interface Props { data: PageData }
  let { data }: Props = $props();

  function isoToDate(iso: string | null) {
    return iso ? new Date(iso).toLocaleDateString(undefined, { dateStyle: 'medium' }) : '—';
  }

  // --- Risk acceptance (remediation) ---
  const acceptance = $derived(data.riskAcceptance);
  let adminToken = $state('');
  let justification = $state('');
  let expiresAt = $state(''); // yyyy-mm-dd from a date input
  let busy = $state(false);
  let errorMsg = $state('');

  $effect(() => {
    adminToken = getAdminToken();
  });
  function saveToken() {
    setAdminToken(adminToken.trim());
  }

  async function accept(e: Event) {
    e.preventDefault();
    errorMsg = '';
    if (!justification.trim() || !expiresAt) return;
    busy = true;
    try {
      // The date input gives a local date; send end-of-day UTC ISO.
      const iso = new Date(`${expiresAt}T23:59:59Z`).toISOString();
      await adminFetch(`/api/remediation/${data.detail.cveId}`, 'PUT', {
        justification: justification.trim(),
        expiresAt: iso,
      });
      justification = '';
      expiresAt = '';
      await invalidateAll();
    } catch (err) {
      errorMsg = err instanceof Error ? err.message : 'Failed to accept risk';
    } finally {
      busy = false;
    }
  }

  async function revoke() {
    errorMsg = '';
    busy = true;
    try {
      await adminFetch(`/api/remediation/${data.detail.cveId}`, 'DELETE');
      await invalidateAll();
    } catch (err) {
      errorMsg = err instanceof Error ? err.message : 'Failed to revoke';
    } finally {
      busy = false;
    }
  }
</script>

<svelte:head>
  <title>{data.detail.cveId} — Threat-Lens CVE Hub</title>
  <meta name="description" content="{data.detail.description.slice(0, 200)}" />
</svelte:head>

<div class="page-cve">
  <!-- Header -->
  <header class="cve-header">
    <div class="cve-header-top">
      <h1 class="cve-id">{data.detail.cveId}</h1>
      <SeverityBadge severity={data.detail.severity} />
      {#if data.detail.cvss}
        <span class="cve-cvss" title="CVSS {data.detail.cvss.version} base score">CVSS {data.detail.cvss.base.toFixed(1)}</span>
      {/if}
      {#if data.detail.state.kevListed}
        <span class="badge-kev">KEV</span>
      {/if}
    </div>
    <p class="cve-dates">
      Published {isoToDate(data.detail.publishedAt)} · Modified {isoToDate(data.detail.lastModifiedAt)}
    </p>
  </header>

  <!--
    Risk acceptance (remediation) — operator-only. The CVE itself is public
    data; our decision to leave it unpatched until a given date is not, so the
    banner and the accept/revoke panel only render for a signed-in operator
    (`?token=<ADMIN_BEARER>`). See src/lib/server/adminSession.ts.
  -->
  {#if data.adminView}
  {#if acceptance && acceptance.active}
    <div class="risk-banner" role="status">
      <div>
        <strong>Risk accepted</strong> until {isoToDate(acceptance.expiresAt)}{acceptance.acceptedBy ? ` · by ${acceptance.acceptedBy}` : ''}
        <p class="risk-just">{acceptance.justification}</p>
      </div>
      <button class="btn-revoke" type="button" disabled={busy} onclick={revoke}>Revoke</button>
    </div>
  {/if}

  <details class="admin-panel risk-panel">
    <summary>{acceptance?.active ? 'Extend / change risk acceptance' : 'Accept risk for this CVE'}</summary>
    <div class="admin-body">
      <label class="field">
        <span class="field__label">Admin token</span>
        <input class="field__input" type="password" bind:value={adminToken} onblur={saveToken} placeholder="ADMIN_BEARER — this tab only" autocomplete="off" />
      </label>
      <form class="risk-form" onsubmit={accept}>
        <label class="field field--grow">
          <span class="field__label">Justification (required)</span>
          <input class="field__input" bind:value={justification} maxlength="2000" placeholder="e.g. not reachable in our deployment; compensating control X" />
        </label>
        <label class="field">
          <span class="field__label">Expires (required)</span>
          <input class="field__input" type="date" bind:value={expiresAt} />
        </label>
        <button class="btn-primary" type="submit" disabled={busy || !justification.trim() || !expiresAt}>
          {acceptance?.active ? 'Update' : 'Accept'}
        </button>
      </form>
      {#if errorMsg}<p class="risk-error" role="alert">{errorMsg}</p>{/if}
    </div>
  </details>
  {/if}

  <!-- Description -->
  <section class="cve-section" aria-labelledby="desc-heading">
    <h2 id="desc-heading" class="section-title">Description</h2>
    <p class="cve-description">{data.detail.description}</p>
  </section>

  <div class="two-col">
    <!-- CVSS Metrics -->
    {#if data.detail.cvss}
      <section class="cve-section" aria-labelledby="cvss-heading">
        <h2 id="cvss-heading" class="section-title">CVSS {data.detail.cvss.version}</h2>
        <dl class="metric-grid">
          <dt>Vector</dt>
          <dd><code class="mono">{data.detail.cvss.vector}</code></dd>
          <dt>Base Score</dt>
          <dd class="score-value score-value--{data.detail.severity.toLowerCase()}">{data.detail.cvss.base.toFixed(1)}</dd>
          {#if data.detail.cvss.exploitability !== null}
            <dt>Exploitability</dt>
            <dd>{data.detail.cvss.exploitability.toFixed(2)}</dd>
          {/if}
          {#if data.detail.cvss.impact !== null}
            <dt>Impact</dt>
            <dd>{data.detail.cvss.impact.toFixed(2)}</dd>
          {/if}
        </dl>
      </section>
    {/if}

    <!-- Threat Intel -->
    <section class="cve-section" aria-labelledby="threat-heading">
      <h2 id="threat-heading" class="section-title">Threat Intelligence</h2>
      <dl class="metric-grid">
        <dt>KEV Listed</dt>
        <dd>{data.detail.state.kevListed ? '✓ Yes' : 'No'}</dd>
        {#if data.detail.state.kevDateAdded}
          <dt>Date Added</dt>
          <dd>{isoToDate(data.detail.state.kevDateAdded)}</dd>
        {/if}
        {#if data.detail.state.kevDueDate}
          <dt>Due Date</dt>
          <dd>{isoToDate(data.detail.state.kevDueDate)}</dd>
        {/if}
        {#if data.detail.state.epssScore !== null}
          <dt>EPSS Score</dt>
          <dd>{(data.detail.state.epssScore * 100).toFixed(2)}%</dd>
        {/if}
        {#if data.detail.state.epssPercentile !== null}
          <dt>EPSS Percentile</dt>
          <dd>{(data.detail.state.epssPercentile * 100).toFixed(1)}th</dd>
        {/if}
      </dl>
      {#if data.detail.state.kevRequiredAction}
        <p class="kev-action"><strong>Required Action:</strong> {data.detail.state.kevRequiredAction}</p>
      {/if}
    </section>
  </div>

  <!-- CWEs -->
  {#if data.detail.cwes.length > 0}
    <section class="cve-section" aria-labelledby="cwe-heading">
      <h2 id="cwe-heading" class="section-title">Weaknesses (CWE)</h2>
      <ul class="cwe-list" role="list">
        {#each data.detail.cwes as cwe}
          <li class="cwe-item">
            <code class="cwe-id">{cwe.id}</code>
            <span class="cwe-name">{cwe.name}</span>
            {#if cwe.category}
              <span class="cwe-category">{cwe.category}</span>
            {/if}
          </li>
        {/each}
      </ul>
    </section>
  {/if}

  <!-- CPEs -->
  {#if data.detail.cpes.length > 0}
    <section class="cve-section" aria-labelledby="cpe-heading">
      <h2 id="cpe-heading" class="section-title">Affected Products ({data.detail.cpes.length})</h2>
      <div class="table-wrap">
        <table class="data-table">
          <thead>
            <tr>
              <th>Vendor</th>
              <th>Product</th>
              <th>Version</th>
              <th>Vulnerable</th>
            </tr>
          </thead>
          <tbody>
            {#each data.detail.cpes.slice(0, 100) as cpe}
              <tr>
                <td>
                  <a href="/affected-products?vendor={encodeURIComponent(cpe.vendor)}">{cpe.vendor}</a>
                </td>
                <td>{cpe.product}</td>
                <td class="mono">{cpe.version ?? formatRange(cpe)}</td>
                <td>{cpe.vulnerable ? '✓' : '—'}</td>
              </tr>
            {/each}
          </tbody>
        </table>
        {#if data.detail.cpes.length > 100}
          <p class="table-overflow">Showing 100 of {data.detail.cpes.length} affected products.</p>
        {/if}
      </div>
    </section>
  {/if}

  <!-- References -->
  {#if data.detail.references.length > 0}
    <section class="cve-section" aria-labelledby="ref-heading">
      <h2 id="ref-heading" class="section-title">References ({data.detail.references.length})</h2>
      <ul class="ref-list" role="list">
        {#each data.detail.references as ref}
          <li class="ref-item">
            <a class="ref-url" href={ref.url} target="_blank" rel="noopener noreferrer">{ref.url}</a>
            {#each ref.tags as tag}
              <span class="ref-tag">{tag}</span>
            {/each}
          </li>
        {/each}
      </ul>
    </section>
  {/if}
</div>

<script module>
  function formatRange(cpe: { versionStartIncluding?: string | null; versionStartExcluding?: string | null; versionEndIncluding?: string | null; versionEndExcluding?: string | null }): string {
    const parts: string[] = [];
    if (cpe.versionStartIncluding) parts.push('>=' + cpe.versionStartIncluding);
    if (cpe.versionStartExcluding) parts.push('>' + cpe.versionStartExcluding);
    if (cpe.versionEndIncluding) parts.push('<=' + cpe.versionEndIncluding);
    if (cpe.versionEndExcluding) parts.push('<' + cpe.versionEndExcluding);
    return parts.join(', ') || '*';
  }
</script>

<style>
  .page-cve { max-width: 56rem; }
  .cve-header { margin-block-end: var(--space-8); }
  .cve-header-top { display: flex; align-items: center; gap: var(--space-3); flex-wrap: wrap; margin-block-end: var(--space-2); }
  .cve-id { font-size: var(--text-3xl); font-weight: var(--weight-bold); color: var(--color-text-primary); margin: 0; font-family: var(--font-mono); letter-spacing: var(--tracking-tight); }
  .cve-cvss { font-size: var(--text-sm); color: var(--color-text-secondary); font-family: var(--font-mono); padding: 0.125rem 0.5rem; background: var(--color-surface-elevated); border: 1px solid var(--color-border-default); border-radius: var(--radius-sm); }
  .badge-kev { font-family: var(--font-mono); font-size: var(--text-2xs); letter-spacing: var(--tracking-wide); text-transform: uppercase; background: var(--color-kev-subtle); color: var(--color-kev-text); border: 1px solid var(--color-kev); padding: 0.1rem 0.5rem; border-radius: var(--radius-sm); font-weight: var(--weight-semibold); box-shadow: var(--glow-critical); }
  .cve-dates { font-size: var(--text-sm); color: var(--color-text-tertiary); margin: 0; }

  .cve-section { margin-block-end: var(--space-8); }
  .section-title { font-size: var(--text-xs); font-weight: var(--weight-semibold); text-transform: uppercase; letter-spacing: var(--tracking-wide); color: var(--color-text-tertiary); margin: 0 0 var(--space-4); }
  .cve-description { font-size: var(--text-base); line-height: 1.7; color: var(--color-text-secondary); margin: 0; }

  .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: var(--layout-card-gap); margin-block-end: var(--space-8); }
  .metric-grid { display: grid; grid-template-columns: 8rem 1fr; gap: var(--space-1) var(--space-4); font-size: var(--text-sm); margin: 0; }
  .metric-grid dt { color: var(--color-text-tertiary); }
  .metric-grid dd { color: var(--color-text-secondary); margin: 0; }
  .score-value { font-size: var(--text-2xl); font-weight: var(--weight-bold); font-variant-numeric: tabular-nums; }
  .score-value--critical { color: var(--color-critical-text); }
  .score-value--high { color: var(--color-high-text); }
  .score-value--medium { color: var(--color-medium-text); }
  .score-value--low { color: var(--color-low-text); }
  .score-value--none { color: var(--color-none-text); }
  .mono { font-family: var(--font-mono); font-size: var(--text-xs); word-break: break-all; }
  .kev-action { font-size: var(--text-sm); color: var(--color-text-secondary); margin: var(--space-3) 0 0; line-height: 1.5; }

  .cwe-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: var(--space-2); }
  .cwe-item { display: flex; align-items: center; gap: var(--space-3); font-size: var(--text-sm); }
  .cwe-id { font-family: var(--font-mono); color: var(--color-brand-text); background: var(--color-surface-elevated); padding: 0.125rem 0.375rem; border-radius: var(--radius-sm); }
  .cwe-name { color: var(--color-text-primary); }
  .cwe-category { font-size: var(--text-xs); color: var(--color-text-tertiary); background: var(--color-surface-elevated); padding: 0.125rem 0.375rem; border-radius: var(--radius-full); }

  /* Inherits the global .data-grid/.data-table look (app.css §15). */
  .table-overflow { font-size: var(--text-xs); color: var(--color-text-tertiary); margin: var(--space-2) 0 0; }

  .ref-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: var(--space-2); }
  .ref-item { display: flex; align-items: flex-start; gap: var(--space-2); font-size: var(--text-sm); flex-wrap: wrap; }
  .ref-url { color: var(--color-brand-text); word-break: break-all; flex: 1; min-width: 0; }
  .ref-url:hover { color: var(--color-brand-hover); }
  .ref-tag { font-family: var(--font-mono); font-size: var(--text-2xs); color: var(--color-text-tertiary); background: var(--color-surface-elevated); padding: 0.125rem 0.375rem; border-radius: var(--radius-sm); flex-shrink: 0; text-transform: uppercase; letter-spacing: var(--tracking-wide); }

  .risk-banner { display: flex; align-items: flex-start; justify-content: space-between; gap: var(--space-4); padding: var(--space-3) var(--space-4); margin-block-end: var(--space-6); background: var(--color-kev-subtle); border: 1px solid var(--color-kev-border, var(--color-critical-border)); border-radius: var(--radius-md); font-size: var(--text-sm); color: var(--color-text-secondary); }
  .risk-banner strong { color: var(--color-kev-text); }
  .risk-just { margin: var(--space-1) 0 0; font-size: var(--text-xs); color: var(--color-text-tertiary); }
  .risk-panel { margin-block-end: var(--space-6); border: 1px solid var(--color-border-default); border-radius: var(--radius-md); background: var(--color-surface-raised); }
  .risk-panel summary { padding: var(--space-2_5) var(--space-4); font-family: var(--font-mono); font-size: var(--text-xs); letter-spacing: var(--tracking-wide); text-transform: uppercase; color: var(--color-text-secondary); cursor: pointer; }
  .risk-panel summary:hover { color: var(--color-brand-text); }
  .admin-body { padding: 0 var(--space-4) var(--space-4); display: flex; flex-direction: column; gap: var(--space-3); }
  .risk-form { display: flex; flex-wrap: wrap; align-items: flex-end; gap: var(--space-3); }
  .field { display: flex; flex-direction: column; gap: var(--space-1); min-width: 10rem; }
  .field--grow { flex: 1; min-width: 16rem; }
  .field__label { font-size: var(--text-xs); color: var(--color-text-tertiary); }
  .field__input { padding: var(--space-2) var(--space-3); background: var(--color-surface-sunken); border: 1px solid var(--color-border-default); border-radius: var(--radius-sm); color: var(--color-text-primary); font-size: var(--text-sm); outline: none; }
  .field__input:focus { border-color: var(--color-brand-border); }
  .btn-primary { padding: var(--space-2) var(--space-4); background: var(--color-brand-subtle); color: var(--color-brand-text); border: 1px solid var(--color-brand-border); border-radius: var(--radius-md); font-family: var(--font-mono); font-size: var(--text-sm); font-weight: var(--weight-medium); white-space: nowrap; transition: var(--transition-colors), box-shadow var(--duration-fast) var(--ease-out); }
  .btn-primary:hover:not(:disabled) { border-color: var(--color-brand-default); box-shadow: var(--glow-accent); }
  .btn-primary:disabled { opacity: 0.45; cursor: not-allowed; }
  .btn-revoke { padding: 2px var(--space-2); font-family: var(--font-mono); font-size: var(--text-2xs); text-transform: uppercase; letter-spacing: var(--tracking-wide); color: var(--color-critical-text); background: transparent; border: 1px solid var(--color-critical-border); border-radius: var(--radius-sm); flex-shrink: 0; }
  .btn-revoke:hover:not(:disabled) { background: var(--color-critical-subtle); }
  .risk-error { font-size: var(--text-sm); color: var(--color-critical-text); margin: 0; }

  @media (max-width: 700px) {
    .two-col { grid-template-columns: 1fr; }
  }
</style>
