<script lang="ts">
  import DataOfflineNotice from '$lib/ui/DataOfflineNotice.svelte';
  import PageHeader from '$lib/ui/PageHeader.svelte';
  import SeverityBadge from '$lib/ui/SeverityBadge.svelte';
  import type { PageData } from './$types';

  interface Props {
    data: PageData;
  }
  let { data }: Props = $props();

  const filtered = $derived(Boolean(data.vendor || data.product));

  function isoToDate(iso: string) {
    return new Date(iso).toLocaleDateString(undefined, { dateStyle: 'medium' });
  }
</script>

<svelte:head>
  <title>Affected Products — Threat-Lens CVE Hub</title>
</svelte:head>

<div class="page-affected">
  <PageHeader
    eyebrow="EXPOSURE SURFACE"
    title="Affected Products"
    subtitle="Vendors and products ranked by the CVEs that name them. Severity is ranked correctly, the latest CVE is the most recently published, and KEV counts flag actively-exploited exposure."
  />

  <form class="filter-bar" method="GET">
    <div class="filter-field">
      <span class="filter-prefix">vendor:</span>
      <input
        class="filter-input"
        type="text"
        name="vendor"
        value={data.vendor}
        placeholder="e.g. microsoft"
        aria-label="Vendor filter"
      />
    </div>
    <div class="filter-field">
      <span class="filter-prefix">product:</span>
      <input
        class="filter-input"
        type="text"
        name="product"
        value={data.product}
        placeholder="e.g. windows"
        aria-label="Product filter"
      />
    </div>
    <button class="btn-cmd" type="submit">Apply</button>
    {#if filtered}
      <a class="filter-clear" href="/affected-products">Reset</a>
    {/if}
  </form>

  {#if data.versions && data.versions.versions.length > 0}
    <!-- Version drill-down: vendor → product → version. Shown when a specific
         vendor + product are selected. -->
    <section class="versions" aria-label="Affected versions">
      <h2 class="versions__title">
        Affected versions of <span class="vp">{data.versions.vendor} / {data.versions.product}</span>
      </h2>
      <div class="data-grid__wrap">
        <table class="data-grid">
          <thead>
            <tr>
              <th>Version / range</th>
              <th>Type</th>
              <th>CVEs</th>
              <th>KEV</th>
              <th>Max CVSS</th>
              <th>Severity</th>
              <th>Sample CVEs</th>
            </tr>
          </thead>
          <tbody>
            {#each data.versions.versions as v (v.version ?? v.rangeSummary ?? 'any')}
              <tr>
                <td class="mono">
                  {#if v.version}{v.version}{:else if v.rangeSummary}{v.rangeSummary}{:else}<span class="dim">all versions</span>{/if}
                </td>
                <td>
                  <span class="part-chip">{v.part === 'a' ? 'app' : v.part === 'o' ? 'os' : v.part === 'h' ? 'hw' : '—'}</span>
                </td>
                <td class="mono">{v.cveCount.toLocaleString()}</td>
                <td>{#if v.kevCount > 0}<span class="kev-chip">{v.kevCount}</span>{:else}<span class="dim">—</span>{/if}</td>
                <td class="mono">{v.maxCvssBase !== null ? v.maxCvssBase.toFixed(1) : '—'}</td>
                <td><SeverityBadge severity={v.maxSeverity} variant="text" /></td>
                <td class="samples">
                  {#each v.sampleCveIds as id (id)}
                    <a class="cve-link" href="/cve/{id}">{id}</a>
                  {/each}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </section>
  {/if}

  {#if data.dataError}
    <DataOfflineNotice what="Product exposure data" />
  {:else if data.rows.length === 0}
    <div class="empty-state">
      <span class="empty-state__title">No signal</span>
      <span>No affected products match the current filter.</span>
    </div>
  {:else}
    <div class="data-grid__wrap boot-in">
      <table class="data-grid">
        <thead>
          <tr>
            <th>Vendor</th>
            <th>Product</th>
            <th>CVEs</th>
            <th>Versions</th>
            <th>KEV</th>
            <th>Max CVSS</th>
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
                <a
                  href="/affected-products?vendor={encodeURIComponent(
                    row.vendor,
                  )}&product={encodeURIComponent(row.product)}">{row.product}</a>
              </td>
              <td class="mono">{row.cveCount.toLocaleString()}</td>
              <td class="mono">{row.affectedVersionCount > 0 ? row.affectedVersionCount.toLocaleString() : '—'}</td>
              <td>{#if row.kevCount > 0}<span class="kev-chip">{row.kevCount}</span>{:else}<span class="dim">—</span>{/if}</td>
              <td class="mono">{row.maxCvssBase !== null ? row.maxCvssBase.toFixed(1) : '—'}</td>
              <td><SeverityBadge severity={row.maxSeverity} variant="text" /></td>
              <td><a class="cve-link" href="/cve/{row.latestCveId}">{row.latestCveId}</a></td>
              <td class="mono">{isoToDate(row.latestPublishedAt)}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>

    {#if data.nextCursor}
      <div class="pagination">
        <a
          class="btn-cmd"
          href="?{new URLSearchParams({
            ...(data.vendor ? { vendor: data.vendor } : {}),
            ...(data.product ? { product: data.product } : {}),
            cursor: data.nextCursor,
          })}"
        >
          Next page →
        </a>
      </div>
    {/if}
  {/if}
</div>

<style>
  .filter-bar {
    display: flex;
    gap: var(--space-2);
    align-items: center;
    margin-block-end: var(--space-6);
    flex-wrap: wrap;
  }
  .filter-field {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    padding-inline-start: var(--space-3);
    background: var(--color-surface-raised);
    border: 1px solid var(--color-border-default);
    border-radius: var(--radius-md);
    transition: var(--transition-colors);
  }
  .filter-field:focus-within {
    border-color: var(--color-brand-border);
  }
  .filter-prefix {
    font-family: var(--font-mono);
    font-size: var(--text-xs);
    color: var(--color-brand-text);
    user-select: none;
  }
  .filter-input {
    padding: var(--space-2) var(--space-3) var(--space-2) 0;
    background: transparent;
    border: none;
    outline: none;
    font-size: var(--text-sm);
    color: var(--color-text-primary);
    width: 11rem;
  }
  .filter-input::placeholder {
    color: var(--color-text-tertiary);
  }
  .filter-clear {
    font-family: var(--font-mono);
    font-size: var(--text-sm);
    color: var(--color-text-secondary);
    text-decoration: none;
  }
  .filter-clear:hover {
    color: var(--color-brand-text);
  }
  .pagination {
    margin-block-start: var(--space-6);
  }
  .kev-chip {
    font-family: var(--font-mono);
    font-size: var(--text-2xs);
    font-weight: var(--weight-semibold);
    color: var(--color-kev-text);
    background: var(--color-kev-subtle);
    border: 1px solid var(--color-kev);
    padding: 0.1rem 0.4rem;
    border-radius: var(--radius-sm);
  }
  .dim { color: var(--color-text-tertiary); }

  /* Version drill-down */
  .versions {
    margin-block-end: var(--space-8);
    padding: var(--space-5);
    border: 1px solid var(--color-brand-border);
    border-radius: var(--radius-lg);
    background:
      radial-gradient(120% 140% at 0% 0%, var(--color-brand-subtle) 0%, transparent 55%),
      var(--color-surface-raised);
  }
  .versions__title {
    font-size: var(--text-sm);
    font-weight: var(--weight-semibold);
    color: var(--color-text-primary);
    margin: 0 0 var(--space-4);
  }
  .versions__title .vp { font-family: var(--font-mono); color: var(--color-brand-text); }
  .part-chip {
    font-family: var(--font-mono); font-size: var(--text-2xs); text-transform: uppercase;
    letter-spacing: var(--tracking-wide); color: var(--color-text-tertiary);
    background: var(--color-surface-elevated); padding: 0.1rem 0.4rem; border-radius: var(--radius-sm);
  }
  .samples { display: flex; flex-wrap: wrap; gap: var(--space-2); }
  .samples .cve-link { font-family: var(--font-mono); font-size: var(--text-xs); color: var(--color-brand-text); }
</style>
