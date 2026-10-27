<script lang="ts">
  import type { PageData } from './$types';
  import type { Severity } from '@threat-lens/contracts';

  interface Props { data: PageData }
  let { data }: Props = $props();

  const SEV_COLOR: Record<Severity, string> = {
    CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#22c55e', NONE: '#6b7280',
  };

  function isoToDate(iso: string | null) {
    return iso ? new Date(iso).toLocaleDateString(undefined, { dateStyle: 'medium' }) : '—';
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
      <span class="cve-severity" style="color:{SEV_COLOR[data.detail.severity]}">{data.detail.severity}</span>
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
          <dd class="score-value" style="color:{SEV_COLOR[data.detail.severity]}">{data.detail.cvss.base.toFixed(1)}</dd>
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
  .cve-id { font-size: var(--text-3xl); font-weight: var(--weight-bold); color: var(--color-text-primary); margin: 0; font-family: var(--font-mono); }
  .cve-severity { font-size: var(--text-sm); font-weight: var(--weight-semibold); text-transform: uppercase; letter-spacing: var(--tracking-wide); }
  .cve-cvss { font-size: var(--text-sm); color: var(--color-text-secondary); font-family: var(--font-mono); padding: 0.125rem 0.5rem; background: var(--color-surface-elevated); border-radius: var(--radius-sm); }
  .badge-kev { font-size: var(--text-xs); background: #7c2d12; color: #fed7aa; padding: 0.125rem 0.5rem; border-radius: var(--radius-full); font-weight: var(--weight-semibold); }
  .cve-dates { font-size: var(--text-sm); color: var(--color-text-tertiary); margin: 0; }

  .cve-section { margin-block-end: var(--space-8); }
  .section-title { font-size: var(--text-xs); font-weight: var(--weight-semibold); text-transform: uppercase; letter-spacing: var(--tracking-wide); color: var(--color-text-tertiary); margin: 0 0 var(--space-4); }
  .cve-description { font-size: var(--text-base); line-height: 1.7; color: var(--color-text-secondary); margin: 0; }

  .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: var(--layout-card-gap); margin-block-end: var(--space-8); }
  .metric-grid { display: grid; grid-template-columns: 8rem 1fr; gap: var(--space-1) var(--space-4); font-size: var(--text-sm); margin: 0; }
  .metric-grid dt { color: var(--color-text-tertiary); }
  .metric-grid dd { color: var(--color-text-secondary); margin: 0; }
  .score-value { font-size: var(--text-2xl); font-weight: var(--weight-bold); }
  .mono { font-family: var(--font-mono); font-size: var(--text-xs); word-break: break-all; }
  .kev-action { font-size: var(--text-sm); color: var(--color-text-secondary); margin: var(--space-3) 0 0; line-height: 1.5; }

  .cwe-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: var(--space-2); }
  .cwe-item { display: flex; align-items: center; gap: var(--space-3); font-size: var(--text-sm); }
  .cwe-id { font-family: var(--font-mono); color: var(--color-brand-400); background: var(--color-surface-elevated); padding: 0.125rem 0.375rem; border-radius: var(--radius-sm); }
  .cwe-name { color: var(--color-text-primary); }
  .cwe-category { font-size: var(--text-xs); color: var(--color-text-tertiary); background: var(--color-surface-elevated); padding: 0.125rem 0.375rem; border-radius: var(--radius-full); }

  .table-wrap { overflow-x: auto; }
  .data-table { width: 100%; border-collapse: collapse; font-size: var(--text-sm); }
  .data-table th { text-align: left; padding: var(--space-2) var(--space-3); font-size: var(--text-xs); font-weight: var(--weight-medium); color: var(--color-text-tertiary); text-transform: uppercase; letter-spacing: var(--tracking-wide); border-bottom: 1px solid var(--color-border-subtle); }
  .data-table td { padding: var(--space-2) var(--space-3); color: var(--color-text-secondary); border-bottom: 1px solid var(--color-border-subtle); vertical-align: top; }
  .data-table a { color: var(--color-brand-400); text-decoration: none; }
  .data-table a:hover { text-decoration: underline; }
  .table-overflow { font-size: var(--text-xs); color: var(--color-text-tertiary); margin: var(--space-2) 0 0; }

  .ref-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: var(--space-2); }
  .ref-item { display: flex; align-items: flex-start; gap: var(--space-2); font-size: var(--text-sm); flex-wrap: wrap; }
  .ref-url { color: var(--color-brand-400); word-break: break-all; flex: 1; min-width: 0; }
  .ref-url:hover { text-decoration: underline; }
  .ref-tag { font-size: var(--text-xs); color: var(--color-text-tertiary); background: var(--color-surface-elevated); padding: 0.125rem 0.375rem; border-radius: var(--radius-sm); flex-shrink: 0; }

  @media (max-width: 700px) {
    .two-col { grid-template-columns: 1fr; }
  }
</style>
