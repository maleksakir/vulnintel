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
  // Drill-down is active when a specific vendor+product was requested.
  const drillDown = $derived(Boolean(data.vendor && data.product));

  // Drill-down summary stats (distinct CVEs / KEV across all version groups).
  const vstats = $derived.by(() => {
    const vs = data.versions?.versions ?? [];
    return {
      groups: vs.length,
      cves: vs.reduce((n, v) => n + v.cveCount, 0),
      kev: vs.reduce((n, v) => n + v.kevCount, 0),
    };
  });

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

  {#if drillDown}
    <!-- Version drill-down: vendor → product → version. Shown when a specific
         vendor + product are selected. -->
    <section class="versions" aria-label="Affected versions">
      <header class="versions__head">
        <div>
          <p class="versions__eyebrow">VERSION BREAKDOWN</p>
          <h2 class="versions__title">
            <span class="vp">{data.vendor} / {data.product}</span>
          </h2>
        </div>
        <a class="versions__back" href="/affected-products">← All products</a>
      </header>

      {#if data.versions && data.versions.versions.length > 0}
      <dl class="versions__stats" aria-label="Breakdown summary">
        <div class="vstat"><dt>Version groups</dt><dd class="mono">{vstats.groups.toLocaleString()}</dd></div>
        <div class="vstat"><dt>Affected CVEs</dt><dd class="mono">{vstats.cves.toLocaleString()}</dd></div>
        <div class="vstat vstat--kev"><dt>KEV</dt><dd class="mono">{vstats.kev.toLocaleString()}</dd></div>
      </dl>

      <!-- Each version is an expandable group listing ALL its CVEs. When there
           is only one version group it's expanded by default, so a
           single-version product reads straight as a CVE list. -->
      <ul class="vgroups" role="list">
        {#each data.versions.versions as v (v.version ?? v.rangeSummary ?? 'any')}
          <li>
            <details class="vgroup" open={data.versions.versions.length === 1}>
              <summary class="vgroup__summary">
                <span class="vgroup__ver mono">
                  {#if v.version}{v.version}{:else if v.rangeSummary}{v.rangeSummary}{:else}<span class="dim">all versions</span>{/if}
                </span>
                <span class="part-chip">{v.part === 'a' ? 'app' : v.part === 'o' ? 'os' : v.part === 'h' ? 'hw' : '—'}</span>
                <span class="vgroup__spacer"></span>
                {#if v.kevCount > 0}<span class="kev-chip">KEV {v.kevCount}</span>{/if}
                {#if v.maxCvssBase !== null}<span class="vgroup__cvss mono">CVSS {v.maxCvssBase.toFixed(1)}</span>{/if}
                <SeverityBadge severity={v.maxSeverity} variant="text" />
                <span class="vgroup__count mono">{v.cveCount.toLocaleString()} CVE{v.cveCount === 1 ? '' : 's'}</span>
              </summary>
              <div class="data-grid__wrap">
                <table class="data-grid vgroup__table">
                  <thead>
                    <tr>
                      <th>CVE</th>
                      <th>Severity</th>
                      <th>CVSS</th>
                      <th>KEV</th>
                      <th>Published</th>
                    </tr>
                  </thead>
                  <tbody>
                    {#each v.cves as cve (cve.cveId)}
                      <tr>
                        <td><a class="cve-link" href="/cve/{cve.cveId}">{cve.cveId}</a></td>
                        <td><SeverityBadge severity={cve.severity} variant="text" /></td>
                        <td class="mono">{cve.cvssBase !== null ? cve.cvssBase.toFixed(1) : '—'}</td>
                        <td>{#if cve.kevListed}<span class="kev-chip">KEV</span>{:else}<span class="dim">—</span>{/if}</td>
                        <td class="mono">{isoToDate(cve.publishedAt)}</td>
                      </tr>
                    {/each}
                  </tbody>
                </table>
                {#if v.cveCount > v.cves.length}
                  <p class="vgroup__more">Showing {v.cves.length} of {v.cveCount} — refine by searching this product.</p>
                {/if}
              </div>
            </details>
          </li>
        {/each}
      </ul>
      {:else}
        <p class="versions__empty">
          No CPE-level version data recorded for this product. It may be named in CVEs only by
          vendor/product without discrete version configurations.
        </p>
      {/if}
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
  .versions__head {
    display: flex; align-items: flex-start; justify-content: space-between;
    gap: var(--space-4); flex-wrap: wrap; margin-block-end: var(--space-4);
  }
  .versions__eyebrow {
    font-family: var(--font-mono); font-size: var(--text-2xs); letter-spacing: var(--tracking-caps);
    text-transform: uppercase; color: var(--color-brand-text); margin: 0 0 var(--space-1);
  }
  .versions__title {
    font-size: var(--text-lg);
    font-weight: var(--weight-bold);
    color: var(--color-text-primary);
    margin: 0;
  }
  .versions__title .vp { font-family: var(--font-mono); color: var(--color-brand-text); }
  .versions__back {
    font-family: var(--font-mono); font-size: var(--text-xs); color: var(--color-text-secondary);
    flex-shrink: 0; align-self: center;
  }
  .versions__back:hover { color: var(--color-brand-text); text-decoration: none; }
  .versions__stats {
    display: flex; gap: var(--space-6); margin: 0 0 var(--space-4); flex-wrap: wrap;
    padding: var(--space-3) var(--space-4);
    border: 1px solid var(--color-border-default); border-radius: var(--radius-md);
    background: var(--color-surface-sunken);
  }
  .vstat { display: flex; flex-direction: column; gap: 2px; }
  .vstat dt { font-size: var(--text-2xs); text-transform: uppercase; letter-spacing: var(--tracking-wide); color: var(--color-text-tertiary); margin: 0; }
  .vstat dd { font-size: var(--text-xl); font-weight: var(--weight-bold); color: var(--color-text-primary); margin: 0; }
  .vstat--kev dd { color: var(--color-kev-text); }
  .versions__empty { font-size: var(--text-sm); color: var(--color-text-tertiary); margin: 0; line-height: var(--leading-snug); }

  /* Expandable version groups */
  .vgroups { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: var(--space-2); }
  .vgroup {
    border: 1px solid var(--color-border-default); border-radius: var(--radius-md);
    background: var(--color-surface-base); overflow: hidden;
  }
  .vgroup__summary {
    display: flex; align-items: center; gap: var(--space-3); flex-wrap: wrap;
    padding: var(--space-3) var(--space-4); cursor: pointer; list-style: none;
    font-size: var(--text-sm);
  }
  .vgroup__summary::-webkit-details-marker { display: none; }
  .vgroup__summary::before {
    content: '▸'; color: var(--color-text-tertiary); font-size: var(--text-xs);
    transition: transform var(--duration-fast) var(--ease-out); flex-shrink: 0;
  }
  .vgroup[open] .vgroup__summary::before { transform: rotate(90deg); }
  .vgroup__summary:hover { background: var(--color-surface-overlay); }
  .vgroup__ver { font-weight: var(--weight-semibold); color: var(--color-text-primary); }
  .vgroup__spacer { flex: 1; }
  .vgroup__cvss { font-size: var(--text-xs); color: var(--color-text-secondary); }
  .vgroup__count { font-size: var(--text-xs); color: var(--color-text-tertiary); flex-shrink: 0; }
  .vgroup__table { margin: 0; }
  .vgroup__table thead th { background: var(--color-surface-sunken); }
  .vgroup__more { font-size: var(--text-xs); color: var(--color-text-tertiary); margin: var(--space-2) var(--space-4); }
  .part-chip {
    font-family: var(--font-mono); font-size: var(--text-2xs); text-transform: uppercase;
    letter-spacing: var(--tracking-wide); color: var(--color-text-tertiary);
    background: var(--color-surface-elevated); padding: 0.1rem 0.4rem; border-radius: var(--radius-sm);
  }
  .cve-link { font-family: var(--font-mono); color: var(--color-brand-text); }
  .cve-link:hover { color: var(--color-brand-hover); }
</style>
