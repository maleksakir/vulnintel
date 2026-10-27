<script lang="ts">
  import type { PageData } from './$types';
  import type { Severity } from '@threat-lens/contracts';

  interface Props { data: PageData }
  let { data }: Props = $props();

  const SEV_COLOR: Record<Severity, string> = {
    CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#22c55e', NONE: '#6b7280',
  };
</script>

<svelte:head>
  <title>Affected Products — Threat-Lens CVE Hub</title>
</svelte:head>

<div class="page-affected">
  <h1 class="page-title">Affected Products</h1>

  <form class="filter-bar" method="GET">
    <input
      class="filter-input"
      type="text"
      name="vendor"
      value={data.vendor}
      placeholder="Filter by vendor…"
      aria-label="Vendor filter"
    />
    <input
      class="filter-input"
      type="text"
      name="product"
      value={data.product}
      placeholder="Filter by product…"
      aria-label="Product filter"
    />
    <button class="filter-btn" type="submit">Apply</button>
    {#if data.vendor || data.product}
      <a class="filter-clear" href="/affected-products">Clear</a>
    {/if}
  </form>

  {#if data.rows.length === 0}
    <p class="empty-state">No affected products found.</p>
  {:else}
    <div class="table-wrap">
      <table class="data-table">
        <thead>
          <tr>
            <th>Vendor</th>
            <th>Product</th>
            <th>CVE Count</th>
            <th>Max Severity</th>
            <th>Latest CVE</th>
            <th>Last Published</th>
          </tr>
        </thead>
        <tbody>
          {#each data.rows as row}
            <tr>
              <td>
                <a href="/affected-products?vendor={encodeURIComponent(row.vendor)}">{row.vendor}</a>
              </td>
              <td>
                <a href="/affected-products?vendor={encodeURIComponent(row.vendor)}&product={encodeURIComponent(row.product)}">{row.product}</a>
              </td>
              <td>{row.cveCount.toLocaleString()}</td>
              <td style="color:{SEV_COLOR[row.maxSeverity]}">{row.maxSeverity}</td>
              <td>
                <a class="cve-link" href="/cve/{row.latestCveId}">{row.latestCveId}</a>
              </td>
              <td>{new Date(row.latestPublishedAt).toLocaleDateString()}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>

    {#if data.nextCursor}
      <div class="pagination">
        <a class="pagination-btn" href="?{new URLSearchParams({ ...(data.vendor ? { vendor: data.vendor } : {}), ...(data.product ? { product: data.product } : {}), cursor: data.nextCursor })}">
          Next page →
        </a>
      </div>
    {/if}
  {/if}
</div>

<style>
  .page-title { font-size: var(--text-2xl); font-weight: var(--weight-semibold); margin: 0 0 var(--space-6); color: var(--color-text-primary); }
  .filter-bar { display: flex; gap: var(--space-2); margin-block-end: var(--space-6); flex-wrap: wrap; }
  .filter-input { padding: var(--space-2) var(--space-3); background: var(--color-surface-raised); border: 1px solid var(--color-border-default); border-radius: var(--radius-md); font-size: var(--text-sm); color: var(--color-text-primary); width: 12rem; }
  .filter-btn { padding: var(--space-2) var(--space-4); background: var(--color-brand-500); color: #fff; border: none; border-radius: var(--radius-md); font-size: var(--text-sm); cursor: pointer; }
  .filter-clear { padding: var(--space-2) var(--space-4); font-size: var(--text-sm); color: var(--color-text-secondary); text-decoration: none; }
  .filter-clear:hover { color: var(--color-text-primary); }
  .empty-state { color: var(--color-text-secondary); }
  .table-wrap { overflow-x: auto; }
  .data-table { width: 100%; border-collapse: collapse; font-size: var(--text-sm); }
  .data-table th { text-align: left; padding: var(--space-2) var(--space-3); font-size: var(--text-xs); font-weight: var(--weight-medium); color: var(--color-text-tertiary); text-transform: uppercase; letter-spacing: var(--tracking-wide); border-bottom: 1px solid var(--color-border-subtle); white-space: nowrap; }
  .data-table td { padding: var(--space-2) var(--space-3); color: var(--color-text-secondary); border-bottom: 1px solid var(--color-border-subtle); }
  .data-table a { color: var(--color-brand-400); text-decoration: none; }
  .data-table a:hover { text-decoration: underline; }
  .cve-link { font-family: var(--font-mono); font-size: var(--text-xs); }
  .pagination { margin-block-start: var(--space-6); }
  .pagination-btn { padding: var(--space-2) var(--space-4); background: var(--color-surface-raised); border: 1px solid var(--color-border-default); border-radius: var(--radius-md); font-size: var(--text-sm); color: var(--color-text-primary); text-decoration: none; }
  .pagination-btn:hover { background: var(--color-surface-elevated); }
</style>
