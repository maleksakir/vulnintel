<script lang="ts">
  import type { PageData } from './$types';
  import type { Severity } from '@threat-lens/contracts';
  import SearchResultsTable from './SearchResultsTable.svelte';

  interface Props { data: PageData }
  let { data }: Props = $props();

  const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'];

  const SEV_COLOR: Record<Severity, string> = {
    CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#22c55e', NONE: '#6b7280',
  };
</script>

<svelte:head>
  <title>{data.query ? `"${data.query}" — Search` : 'Search'} — Threat-Lens CVE Hub</title>
</svelte:head>

<div class="page-search">
  <h1 class="page-title">CVE Search</h1>

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
      <button class="search-btn" type="submit">Search</button>
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
                <span style="color:{SEV_COLOR[sev]}">{sev}</span>
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
    <p class="empty-state">No results found for <strong>"{data.query}"</strong>.</p>
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
  .page-title { font-size: var(--text-2xl); font-weight: var(--weight-semibold); margin: 0 0 var(--space-6); color: var(--color-text-primary); }

  .search-form { margin-block-end: var(--space-6); }
  .search-input-row { display: flex; gap: var(--space-2); }
  .search-input {
    flex: 1; padding: var(--space-3) var(--space-4);
    background: var(--color-surface-raised); border: 1px solid var(--color-border-default);
    border-radius: var(--radius-md); font-size: var(--text-base); color: var(--color-text-primary);
    outline: none;
  }
  .search-input:focus { border-color: var(--color-brand-500); box-shadow: 0 0 0 3px color-mix(in srgb, var(--color-brand-500) 20%, transparent); }
  .search-btn {
    padding: var(--space-3) var(--space-6); background: var(--color-brand-500); color: #fff;
    border-radius: var(--radius-md); font-size: var(--text-sm); font-weight: var(--weight-medium);
    border: none; cursor: pointer;
  }
  .search-btn:hover { background: var(--color-brand-600, #2563eb); }

  .filter-row { margin-block-start: var(--space-3); }
  .filter-summary { font-size: var(--text-sm); color: var(--color-text-secondary); cursor: pointer; }
  .filter-grid { display: flex; gap: var(--space-6); padding: var(--space-4) 0; flex-wrap: wrap; }
  .filter-group { border: none; padding: 0; margin: 0; }
  .filter-group-label { display: block; font-size: var(--text-xs); color: var(--color-text-tertiary); text-transform: uppercase; letter-spacing: var(--tracking-wide); margin-block-end: var(--space-2); font-weight: var(--weight-medium); }
  .checkbox-list { display: flex; flex-direction: column; gap: var(--space-1); }
  .checkbox-label { display: flex; align-items: center; gap: var(--space-2); font-size: var(--text-sm); cursor: pointer; color: var(--color-text-secondary); }
  .filter-input { padding: var(--space-1) var(--space-2); background: var(--color-surface-raised); border: 1px solid var(--color-border-default); border-radius: var(--radius-sm); font-size: var(--text-sm); color: var(--color-text-primary); width: 5rem; }

  .alert { padding: var(--space-4); border-radius: var(--radius-md); margin-block-end: var(--space-4); }
  .alert--warn { background: #7c2d1220; border: 1px solid #7c2d12; color: #fed7aa; }
  .empty-state { color: var(--color-text-secondary); font-size: var(--text-base); }

  .results-header { margin-block-end: var(--space-2); }
  .results-count { font-size: var(--text-sm); color: var(--color-text-secondary); }
</style>
