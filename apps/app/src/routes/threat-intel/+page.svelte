<script lang="ts">
  import PageHeader from '$lib/ui/PageHeader.svelte';
  import SeverityBadge from '$lib/ui/SeverityBadge.svelte';
  import type { PageData } from './$types';

  interface Props {
    data: PageData;
  }
  let { data }: Props = $props();

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
  <PageHeader
    eyebrow="THREAT INTELLIGENCE"
    title="Active Exploitation Feed"
    subtitle="CISA KEV and EPSS — the two signals that say an exploit exists, not just a flaw."
    live
  />

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
        <div class="empty-state">
          <span class="empty-state__title">No KEV entries</span>
          <span>Nothing in the CISA Known Exploited catalog for this view yet.</span>
        </div>
      {:else}
        <div class="data-grid__wrap boot-in">
          <table class="data-grid">
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
                  <td><a class="cve-link" href="/cve/{row.cveId}">{row.cveId}</a></td>
                  <td><SeverityBadge severity={row.severity} variant="text" /></td>
                  <td>
                    <a href="/affected-products?vendor={encodeURIComponent(row.vendor)}">{row.vendor}</a>
                  </td>
                  <td class="mono">{isoToDate(row.kevDateAdded)}</td>
                  <td class="mono">{isoToDate(row.kevDueDate)}</td>
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
              <a class="btn-cmd" {href}>Next page →</a>
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
        <div class="empty-state">
          <span class="empty-state__title">No EPSS data</span>
          <span>No exploit-probability scores are available for this view yet.</span>
        </div>
      {:else}
        <div class="data-grid__wrap boot-in">
          <table class="data-grid">
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
              {#each data.epss.rows as row}
                <tr>
                  <td><a class="cve-link" href="/cve/{row.cveId}">{row.cveId}</a></td>
                  <td><SeverityBadge severity={row.severity} variant="text" /></td>
                  <td>
                    <a href="/affected-products?vendor={encodeURIComponent(row.vendor)}">{row.vendor}</a>
                  </td>
                  <td>
                    <div class="score-bar-wrap">
                      <div class="score-bar" style="width:{(row.epssScore * 100).toFixed(1)}%"></div>
                      <span class="score-text mono">{(row.epssScore * 100).toFixed(2)}%</span>
                    </div>
                  </td>
                  <td class="mono">{(row.epssPercentile * 100).toFixed(1)}th</td>
                  <td class="mono">{row.cvssBase !== null ? row.cvssBase.toFixed(1) : '—'}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>

        {#if data.epss.nextCursor}
          {@const href = nextPageHref('epss', data.epss.nextCursor)}
          {#if href}
            <div class="pagination">
              <a class="btn-cmd" {href}>Next page →</a>
            </div>
          {/if}
        {/if}
      {/if}
    </section>
  {/if}
</div>

<style>
  /* Command-console tab strip. */
  .tab-nav {
    display: flex;
    gap: var(--space-1);
    margin-block-end: var(--space-6);
    border-bottom: 1px solid var(--color-border-default);
  }
  .tab-link {
    position: relative;
    padding: var(--space-2_5) var(--space-4);
    font-family: var(--font-mono);
    font-size: var(--text-xs);
    font-weight: var(--weight-medium);
    letter-spacing: var(--tracking-wide);
    text-transform: uppercase;
    color: var(--color-text-secondary);
    text-decoration: none;
    border-bottom: 2px solid transparent;
    margin-bottom: -1px;
    transition: var(--transition-colors);
  }
  .tab-link:hover {
    color: var(--color-text-primary);
    text-decoration: none;
  }
  .tab-link--active {
    color: var(--color-brand-text);
    border-bottom-color: var(--color-brand-default);
  }
  .tab-link--active::after {
    content: '';
    position: absolute;
    left: 0;
    right: 0;
    bottom: -1px;
    height: 2px;
    background: var(--color-brand-default);
    box-shadow: 0 0 8px hsl(188 92% 52% / 0.7);
  }

  .epss-note {
    font-size: var(--text-sm);
    color: var(--color-text-tertiary);
    margin-block-end: var(--space-4);
    padding-inline-start: var(--space-3);
    border-inline-start: 2px solid var(--color-epss);
  }

  .action-cell {
    max-width: 28rem;
    font-size: var(--text-xs);
    line-height: var(--leading-snug);
    color: var(--color-text-tertiary);
  }

  .score-bar-wrap {
    display: flex;
    align-items: center;
    gap: var(--space-2);
  }
  .score-bar {
    height: 0.4rem;
    background: linear-gradient(90deg, var(--color-epss), var(--color-brand-default));
    border-radius: var(--radius-full);
    min-width: 2px;
    max-width: 8rem;
    box-shadow: 0 0 8px -2px var(--color-epss);
  }
  .score-text {
    font-size: var(--text-xs);
    white-space: nowrap;
    color: var(--color-text-secondary);
  }

  .pagination {
    margin-block-start: var(--space-6);
  }
</style>
