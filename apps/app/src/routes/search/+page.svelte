<script lang="ts">
  import type { Severity } from '@threat-lens/contracts';
  import PageHeader from '$lib/ui/PageHeader.svelte';
  import SeverityBadge from '$lib/ui/SeverityBadge.svelte';
  import SearchResultsTable from './SearchResultsTable.svelte';
  import type { PageData } from './$types';

  interface Props {
    data: PageData;
  }
  let { data }: Props = $props();

  const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'];
</script>

<svelte:head>
  <title>{data.query ? `"${data.query}" — Search` : 'Search'} — Threat-Lens CVE Hub</title>
</svelte:head>

<div class="page-search">
  <PageHeader
    eyebrow="QUERY CONSOLE"
    title="CVE Search"
    subtitle="Keyword, CVE ID, vendor or technology — fused full-text and semantic ranking."
  />

  <form class="search-form" method="GET">
    <div class="search-input-row">
      <!-- svelte-ignore a11y_autofocus -->
      <input
        class="search-input"
        type="search"
        name="q"
        value={data.query}
        placeholder="Search CVEs by keyword, CVE ID, vendor, or technology…"
        aria-label="Search CVEs"
        autofocus
      />
      <button class="btn-cmd btn-cmd--lg" type="submit">Search</button>
    </div>

    <details class="filter-row" open={!!(data.filters?.severity?.length || data.filters?.kev || data.filters?.minCvss !== undefined)}>
      <summary class="filter-summary">Filters</summary>
      <div class="filter-grid">
        <fieldset class="filter-group">
          <legend class="filter-group-label">Severity</legend>
          <div class="checkbox-list">
            {#each SEVERITIES as sev}
              <label class="checkbox-label">
                <input
                  type="checkbox"
                  name="severity"
                  value={sev}
                  checked={data.filters?.severity?.includes(sev) ?? false}
                />
                <SeverityBadge severity={sev} variant="text" />
              </label>
            {/each}
          </div>
        </fieldset>

        <fieldset class="filter-group">
          <legend class="filter-group-label">Threat Intel</legend>
          <label class="checkbox-label">
            <input
              type="checkbox"
              name="kev"
              value="true"
              checked={data.filters?.kev === true}
            />
            <span>KEV listed only</span>
          </label>
        </fieldset>

        <div class="filter-group">
          <label class="filter-group-label" for="minCvss">Min CVSS</label>
          <input
            id="minCvss"
            class="filter-input"
            type="number"
            name="minCvss"
            min="0"
            max="10"
            step="0.1"
            placeholder="0–10"
            value={data.filters?.minCvss ?? ''}
          />
        </div>
      </div>
    </details>
  </form>

  {#if data.quotaError}
    <div class="alert alert--warn" role="alert">
      {data.quotaError === 'RATE_LIMITED'
        ? 'Per-IP hourly search limit reached. Try again in an hour.'
        : 'Daily search quota exceeded. Try again tomorrow.'}
    </div>
  {:else if data.query && data.results.length === 0}
    <div class="empty-state">
      <span class="empty-state__title">No matches</span>
      <span>Nothing found for <strong>"{data.query}"</strong>. Try broader terms or fewer filters.</span>
    </div>
  {:else if data.results.length > 0}
    <div class="results-header">
      <p class="results-count">
        {data.results.length}{data.truncated ? '+' : ''} results
        {#if data.query}for <strong>"{data.query}"</strong>{/if}
      </p>
    </div>

    <SearchResultsTable results={data.results} />
  {/if}
</div>

<style>
  .search-form { margin-block-end: var(--space-6); }
  .search-input-row { display: flex; gap: var(--space-2); }
  .search-input {
    flex: 1;
    padding: var(--space-3) var(--space-4);
    background: var(--color-surface-raised);
    border: 1px solid var(--color-border-default);
    border-radius: var(--radius-md);
    font-size: var(--text-base);
    color: var(--color-text-primary);
    outline: none;
    transition: var(--transition-colors), box-shadow var(--duration-fast) var(--ease-out);
  }
  .search-input::placeholder { color: var(--color-text-tertiary); }
  .search-input:focus {
    border-color: var(--color-brand-default);
    box-shadow: var(--glow-accent);
  }
  /* Larger variant of the shared console button, for the primary search action. */
  .btn-cmd--lg {
    padding: var(--space-3) var(--space-6);
    font-size: var(--text-base);
  }

  .filter-row { margin-block-start: var(--space-3); }
  .filter-summary {
    font-family: var(--font-mono);
    font-size: var(--text-xs);
    letter-spacing: var(--tracking-wide);
    text-transform: uppercase;
    color: var(--color-text-secondary);
    cursor: pointer;
  }
  .filter-summary:hover { color: var(--color-brand-text); }
  .filter-grid {
    display: flex;
    gap: var(--space-8);
    padding: var(--space-4);
    margin-block-start: var(--space-3);
    flex-wrap: wrap;
    border: 1px solid var(--color-border-default);
    border-radius: var(--radius-md);
    background: var(--color-surface-sunken);
  }
  .filter-group { border: none; padding: 0; margin: 0; }
  .filter-group-label {
    display: block;
    font-family: var(--font-mono);
    font-size: var(--text-2xs);
    color: var(--color-text-tertiary);
    text-transform: uppercase;
    letter-spacing: var(--tracking-wide);
    margin-block-end: var(--space-2);
  }
  .checkbox-list { display: flex; flex-direction: column; gap: var(--space-1_5); }
  .checkbox-label {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    font-size: var(--text-sm);
    cursor: pointer;
    color: var(--color-text-secondary);
  }
  .checkbox-label input { accent-color: var(--color-brand-default); }
  .filter-input {
    padding: var(--space-1_5) var(--space-2);
    background: var(--color-surface-raised);
    border: 1px solid var(--color-border-default);
    border-radius: var(--radius-sm);
    font-size: var(--text-sm);
    color: var(--color-text-primary);
    width: 6rem;
    outline: none;
  }
  .filter-input:focus { border-color: var(--color-brand-border); }

  .alert {
    padding: var(--space-4);
    border-radius: var(--radius-md);
    margin-block-end: var(--space-4);
    font-size: var(--text-sm);
  }
  .alert--warn {
    background: var(--color-medium-subtle);
    border: 1px solid var(--color-medium-border);
    color: var(--color-medium-text);
  }

  .results-header { margin-block-end: var(--space-3); }
  .results-count {
    font-family: var(--font-mono);
    font-size: var(--text-xs);
    letter-spacing: var(--tracking-wide);
    color: var(--color-text-tertiary);
  }
</style>
