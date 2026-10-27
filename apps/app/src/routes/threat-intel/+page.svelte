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

  function nextPageHref(tab: string, cursor: string | null) {
    if (!cursor) return null;
    return `/threat-intel?tab=${tab}&cursor=${encodeURIComponent(cursor)}`;
  }
</script>

<svelte:head>
  <title>Threat Intelligence — Threat-Lens CVE Hub</title>
</svelte:head>

<div class="page-threat">
  <h1 class="page-title">Threat Intelligence</h1>

  <nav class="tab-nav" aria-label="Threat intel sections">
    <a
      class="tab-link"
      class:tab-link--active={data.tab === 'kev'}
      href="/threat-intel?tab=kev"
      aria-current={data.tab === 'kev' ? 'page' : undefined}
    >CISA KEV</a>
    <a
      class="tab-link"
      class:tab-link--active={data.tab === 'epss'}
      href="/threat-intel?tab=epss"
      aria-current={data.tab === 'epss' ? 'page' : undefined}
    >EPSS Top CVEs</a>
  </nav>

  {#if data.tab === 'kev'}
    <section aria-label="CISA Known Exploited Vulnerabilities">
      {#if data.kev.rows.length === 0}
        <p class="empty-state">No KEV entries found.</p>
      {:else}
        <div class="table-wrap">
          <table class="data-table">
            <thead>
              <tr>
                <th>CVE ID</th>
                <th>Severity</th>
                <th>Vendor</th>
                <th>Date Added</th>
                <th>Due Date</th>
                <th>Required Action</th>
              </tr>
            </thead>
            <tbody>
              {#each data.kev.rows as row}
                <tr>
                  <td>
                    <a class="cve-link" href="/cve/{row.cveId}">{row.cveId}</a>
                  </td>
                  <td style="color:{SEV_COLOR[row.severity]}">{row.severity}</td>
                  <td>
                    <a href="/affected-products?vendor={encodeURIComponent(row.vendor)}">{row.vendor}</a>
                  </td>
                  <td>{isoToDate(row.kevDateAdded)}</td>
                  <td>{isoToDate(row.kevDueDate)}</td>
                  <td class="action-cell">{row.kevRequiredAction}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>

        {#if data.kev.nextCursor}
          {@const href = nextPageHref('kev', data.kev.nextCursor)}
          {#if href}
            <div class="pagination">
              <a class="pagination-btn" {href}>Next page →</a>
            </div>
          {/if}
        {/if}
      {/if}
    </section>

  {:else}
    <section aria-label="EPSS Top CVEs by Exploitation Probability">
      <p class="epss-note">
        EPSS (Exploit Prediction Scoring System) estimates the probability of exploitation in the wild.
        Higher score = higher risk.
      </p>
      {#if data.epss.rows.length === 0}
        <p class="empty-state">No EPSS data found.</p>
      {:else}
        <div class="table-wrap">
          <table class="data-table">
            <thead>
              <tr>
                <th>CVE ID</th>
                <th>Severity</th>
                <th>Vendor</th>
                <th>EPSS Score</th>
                <th>Percentile</th>
                <th>CVSS</th>
              </tr>
            </thead>
            <tbody>
              {#each data.epss.rows as row, i}
                <tr>
                  <td>
                    <a class="cve-link" href="/cve/{row.cveId}">{row.cveId}</a>
                  </td>
                  <td style="color:{SEV_COLOR[row.severity]}">{row.severity}</td>
                  <td>
                    <a href="/affected-products?vendor={encodeURIComponent(row.vendor)}">{row.vendor}</a>
                  </td>
                  <td>
                    <div class="score-bar-wrap">
                      <div class="score-bar" style="width:{(row.epssScore * 100).toFixed(1)}%"></div>
                      <span class="score-text">{(row.epssScore * 100).toFixed(2)}%</span>
                    </div>
                  </td>
                  <td>{(row.epssPercentile * 100).toFixed(1)}th</td>
                  <td>{row.cvssBase !== null ? row.cvssBase.toFixed(1) : '—'}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>

        {#if data.epss.nextCursor}
          {@const href = nextPageHref('epss', data.epss.nextCursor)}
          {#if href}
            <div class="pagination">
              <a class="pagination-btn" {href}>Next page →</a>
            </div>
          {/if}
        {/if}
      {/if}
    </section>
  {/if}
</div>

<style>
  .page-title { font-size: var(--text-2xl); font-weight: var(--weight-semibold); margin: 0 0 var(--space-6); color: var(--color-text-primary); }

  .tab-nav { display: flex; gap: var(--space-1); margin-block-end: var(--space-6); border-bottom: 1px solid var(--color-border-subtle); }
  .tab-link { padding: var(--space-2) var(--space-4); font-size: var(--text-sm); font-weight: var(--weight-medium); color: var(--color-text-secondary); text-decoration: none; border-bottom: 2px solid transparent; margin-bottom: -1px; transition: var(--transition-colors); }
  .tab-link:hover { color: var(--color-text-primary); }
  .tab-link--active { color: var(--color-brand-400); border-bottom-color: var(--color-brand-400); }

  .epss-note { font-size: var(--text-sm); color: var(--color-text-tertiary); margin-block-end: var(--space-4); }
  .empty-state { color: var(--color-text-secondary); }

  .table-wrap { overflow-x: auto; }
  .data-table { width: 100%; border-collapse: collapse; font-size: var(--text-sm); }
  .data-table th { text-align: left; padding: var(--space-2) var(--space-3); font-size: var(--text-xs); font-weight: var(--weight-medium); color: var(--color-text-tertiary); text-transform: uppercase; letter-spacing: var(--tracking-wide); border-bottom: 1px solid var(--color-border-subtle); white-space: nowrap; }
  .data-table td { padding: var(--space-2) var(--space-3); color: var(--color-text-secondary); border-bottom: 1px solid var(--color-border-subtle); vertical-align: top; }
  .data-table a { color: var(--color-brand-400); text-decoration: none; }
  .data-table a:hover { text-decoration: underline; }
  .cve-link { font-family: var(--font-mono); font-size: var(--text-xs); }
  .action-cell { max-width: 28rem; font-size: var(--text-xs); line-height: 1.5; }

  .score-bar-wrap { display: flex; align-items: center; gap: var(--space-2); }
  .score-bar { height: 0.5rem; background: var(--color-brand-500); border-radius: var(--radius-full); min-width: 2px; max-width: 8rem; }
  .score-text { font-family: var(--font-mono); font-size: var(--text-xs); white-space: nowrap; }

  .pagination { margin-block-start: var(--space-6); }
  .pagination-btn { padding: var(--space-2) var(--space-4); background: var(--color-surface-raised); border: 1px solid var(--color-border-default); border-radius: var(--radius-md); font-size: var(--text-sm); color: var(--color-text-primary); text-decoration: none; }
  .pagination-btn:hover { background: var(--color-surface-elevated); }
</style>
