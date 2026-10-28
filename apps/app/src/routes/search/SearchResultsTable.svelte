<script lang="ts" module>
  import {
    createSortedRowModel,
    metaHelper,
    rowSortingFeature,
    sortFn_alphanumeric,
    sortFn_basic,
    tableFeatures,
  } from '@tanstack/svelte-table';
  import type { Severity } from '@threat-lens/contracts';

  interface ColumnMeta {
    /** Fixed column width (the table uses `table-layout: fixed`). Omit for the flexible column. */
    width?: string;
  }

  // Module scope: TanStack Table needs the feature set to stay stable for the table's lifetime.
  const features = tableFeatures({
    rowSortingFeature,
    sortedRowModel: createSortedRowModel(),
    sortFns: { alphanumeric: sortFn_alphanumeric, basic: sortFn_basic },
    columnMeta: metaHelper<ColumnMeta>(),
  });

  const SEVERITY_RANK: Record<Severity, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, NONE: 0 };
</script>

<script lang="ts">
  import { createColumnHelper, createTable, FlexRender, renderSnippet } from '@tanstack/svelte-table';
  import type { SearchResultItem } from '@threat-lens/contracts';
  import { createWindowRows } from '$lib/ui/windowRows.svelte';

  interface Props {
    /** Results in relevance (RRF) order, as returned by the search loader. */
    results: SearchResultItem[];
  }

  let { results }: Props = $props();

  // Sorting is client-side over the rows already loaded — the search API has
  // no server-side sort, so this only reorders the current result page.
  // Nullable numbers map to `undefined` because `sortUndefined` only treats
  // `undefined` (not `null`) as missing; 'last' keeps unscored CVEs at the
  // bottom in both directions.
  const helper = createColumnHelper<typeof features, SearchResultItem>();
  const columns = helper.columns([
    helper.accessor('cveId', {
      header: 'CVE ID',
      sortFn: 'alphanumeric', // natural order: CVE-2024-9999 before CVE-2024-10000
      cell: (ctx) => renderSnippet(cveIdCell, ctx.row.original),
      meta: { width: '10rem' },
    }),
    helper.accessor((r) => SEVERITY_RANK[r.severity], {
      id: 'severity',
      header: 'Severity',
      sortFn: 'basic',
      sortDescFirst: true,
      cell: (ctx) => renderSnippet(severityCell, ctx.row.original.severity),
      meta: { width: '7rem' },
    }),
    helper.accessor((r) => r.cvssBase ?? undefined, {
      id: 'cvss',
      header: 'CVSS',
      sortFn: 'basic',
      sortDescFirst: true,
      sortUndefined: 'last',
      cell: (ctx) => renderSnippet(cvssCell, ctx.row.original.cvssBase),
      meta: { width: '5rem' },
    }),
    helper.accessor((r) => r.epssPercentile ?? undefined, {
      id: 'epss',
      header: 'EPSS',
      sortFn: 'basic',
      sortDescFirst: true,
      sortUndefined: 'last',
      cell: (ctx) => renderSnippet(epssCell, ctx.row.original.epssPercentile),
      meta: { width: '5rem' },
    }),
    helper.accessor((r) => (r.kevListed ? 1 : 0), {
      id: 'kev',
      header: 'KEV',
      sortFn: 'basic',
      sortDescFirst: true,
      cell: (ctx) => renderSnippet(kevCell, ctx.row.original.kevListed),
      meta: { width: '4.5rem' },
    }),
    helper.accessor((r) => Date.parse(r.publishedAt), {
      id: 'published',
      header: 'Published',
      sortFn: 'basic',
      sortDescFirst: true,
      cell: (ctx) => renderSnippet(publishedCell, ctx.row.original.publishedAt),
      meta: { width: '7.5rem' },
    }),
    helper.display({
      id: 'summary',
      header: 'Summary',
      cell: (ctx) => renderSnippet(summaryCell, ctx.row.original),
    }),
  ]);

  const table = createTable({
    features,
    columns,
    get data() {
      return results;
    },
    getRowId: (r) => r.cveId,
    enableMultiSort: false,
  });

  const rows = $derived(table.getRowModel().rows);
  const rowKeys = $derived(rows.map((r) => r.id));
  const activeSort = $derived(table.atoms.sorting.get()[0]);
  const activeSortLabel = $derived.by(() => {
    if (!activeSort) return null;
    const header = table.getColumn(activeSort.id)?.columnDef.header;
    return typeof header === 'string' ? header : activeSort.id;
  });

  // ~3-line summary + vendor tags. Only a starting estimate: rows are measured once rendered.
  const windowRows = createWindowRows({ keys: () => rowKeys, estimateSize: 96, threshold: 100 });

  function ariaSort(sorted: false | 'asc' | 'desc') {
    return sorted === 'asc' ? 'ascending' : sorted === 'desc' ? 'descending' : undefined;
  }
</script>

{#snippet cveIdCell(r: SearchResultItem)}
  <a class="cve-link" href="/cve/{r.cveId}">{r.cveId}</a>
  <a class="similar-link" href="/search?q={r.cveId}" title="Find similar CVEs">Similar</a>
{/snippet}

{#snippet severityCell(severity: Severity)}
  <span class="severity severity--{severity.toLowerCase()}">{severity}</span>
{/snippet}

{#snippet cvssCell(score: number | null)}
  {#if score !== null}<span class="mono">{score.toFixed(1)}</span>{:else}<span class="muted">—</span>{/if}
{/snippet}

{#snippet epssCell(percentile: number | null)}
  {#if percentile !== null}
    <span class="mono" title="EPSS percentile {(percentile * 100).toFixed(1)}">p{(percentile * 100).toFixed(0)}</span>
  {:else}<span class="muted">—</span>{/if}
{/snippet}

{#snippet kevCell(listed: boolean)}
  {#if listed}<span class="kev-badge" title="Listed in CISA Known Exploited Vulnerabilities">KEV</span>{:else}<span class="muted">—</span>{/if}
{/snippet}

{#snippet publishedCell(iso: string)}
  <!-- ISO date (UTC): identical on server and client, unlike toLocaleDateString(). -->
  <time class="mono" datetime={iso}>{iso.slice(0, 10)}</time>
{/snippet}

{#snippet summaryCell(r: SearchResultItem)}
  <p class="snippet">{r.snippet}</p>
  {#if r.vendors.length > 0}
    <div class="vendors">
      {#each r.vendors as v}
        <a href="/affected-products?vendor={encodeURIComponent(v)}" class="vendor-tag">{v}</a>
      {/each}
    </div>
  {/if}
{/snippet}

<p class="sort-status" aria-live="polite">
  {#if activeSort && activeSortLabel}
    Sorted by {activeSortLabel}, {activeSort.desc ? 'descending' : 'ascending'} ·
    <button type="button" class="link-btn" onclick={() => table.resetSorting()}>Back to relevance order</button>
  {:else}
    Ordered by relevance · select a column heading to sort
  {/if}
</p>

<div class="table-wrap">
  <table
    class="data-table"
    aria-label="Search results"
    aria-rowcount={windowRows.active ? rows.length + 1 : undefined}
  >
    <colgroup>
      {#each table.getAllLeafColumns() as column (column.id)}
        <col style:width={column.columnDef.meta?.width} />
      {/each}
    </colgroup>
    <thead>
      {#each table.getHeaderGroups() as group (group.id)}
        <tr aria-rowindex={windowRows.active ? 1 : undefined}>
          {#each group.headers as header (header.id)}
            {@const sorted = header.column.getIsSorted()}
            <th scope="col" aria-sort={ariaSort(sorted)}>
              {#if header.isPlaceholder}
                <!-- grouped-header placeholder -->
              {:else if header.column.getCanSort()}
                <button
                  type="button"
                  class="sort-btn"
                  class:sort-btn--active={sorted !== false}
                  onclick={header.column.getToggleSortingHandler()}
                >
                  <FlexRender {header} />
                  <svg class="sort-icon" width="8" height="12" viewBox="0 0 8 12" aria-hidden="true">
                    <path d="M4 1 7.5 5h-7z" class:on={sorted === 'asc'} />
                    <path d="M4 11 .5 7h7z" class:on={sorted === 'desc'} />
                  </svg>
                </button>
              {:else}
                <FlexRender {header} />
              {/if}
            </th>
          {/each}
        </tr>
      {/each}
    </thead>
    <tbody {@attach windowRows.anchor}>
      {#if windowRows.paddingTop > 0}
        <tr class="spacer" aria-hidden="true"><td colspan={columns.length} style:height="{windowRows.paddingTop}px"></td></tr>
      {/if}
      {#each windowRows.indexes as index (rowKeys[index])}
        {@const row = rows[index]}
        {#if row}
          <tr data-index={index} aria-rowindex={windowRows.active ? index + 2 : undefined} {@attach windowRows.measure}>
            {#each row.getAllCells() as cell (cell.id)}
              <td><FlexRender {cell} /></td>
            {/each}
          </tr>
        {/if}
      {/each}
      {#if windowRows.paddingBottom > 0}
        <tr class="spacer" aria-hidden="true"><td colspan={columns.length} style:height="{windowRows.paddingBottom}px"></td></tr>
      {/if}
    </tbody>
  </table>
</div>

<style>
  .sort-status { font-size: var(--text-xs); color: var(--color-text-tertiary); margin: 0 0 var(--space-2); }
  .link-btn { color: var(--color-brand-400); font-size: inherit; padding: 0; }
  .link-btn:hover { text-decoration: underline; }

  /* Same table look as /threat-intel and /affected-products; fixed layout so
     column widths don't shift as virtualized rows scroll in and out. */
  .table-wrap { overflow-x: auto; }
  .data-table { width: 100%; min-width: 54rem; table-layout: fixed; border-collapse: collapse; font-size: var(--text-sm); }
  .data-table th { text-align: left; padding: var(--space-2) var(--space-3); font-size: var(--text-xs); font-weight: var(--weight-medium); color: var(--color-text-tertiary); text-transform: uppercase; letter-spacing: var(--tracking-wide); border-bottom: 1px solid var(--color-border-subtle); white-space: nowrap; }
  .data-table td { padding: var(--space-2) var(--space-3); color: var(--color-text-secondary); border-bottom: 1px solid var(--color-border-subtle); vertical-align: top; overflow-wrap: anywhere; }
  .data-table a { color: var(--color-brand-400); text-decoration: none; }
  .data-table a:hover { text-decoration: underline; }
  .data-table .spacer td { padding: 0; border: 0; }

  .sort-btn { display: inline-flex; align-items: center; gap: var(--space-1); padding: 0; font: inherit; color: inherit; text-transform: inherit; letter-spacing: inherit; }
  .sort-btn:hover, .sort-btn--active { color: var(--color-text-primary); }
  .sort-icon { flex-shrink: 0; }
  .sort-icon path { fill: currentColor; opacity: 0.3; }
  .sort-icon path.on { opacity: 1; }

  .cve-link { display: block; font-family: var(--font-mono); font-size: var(--text-sm); font-weight: var(--weight-semibold); }
  .data-table .similar-link { font-size: var(--text-xs); color: var(--color-text-tertiary); }
  .data-table .similar-link:hover { color: var(--color-brand-400); }

  .severity { font-size: var(--text-xs); font-weight: var(--weight-medium); letter-spacing: var(--tracking-wide); }
  .severity--critical { color: var(--color-critical); }
  .severity--high { color: var(--color-high); }
  .severity--medium { color: var(--color-medium); }
  .severity--low { color: var(--color-low); }
  .severity--none { color: var(--color-none); }

  .mono { font-family: var(--font-mono); font-size: var(--text-xs); }
  .muted { color: var(--color-text-tertiary); }
  .kev-badge { font-size: var(--text-xs); background: var(--color-kev-subtle); color: var(--color-kev-text); padding: 0.125rem 0.375rem; border-radius: var(--radius-full); font-weight: var(--weight-medium); white-space: nowrap; }

  .snippet { margin: 0; line-height: var(--leading-normal); display: -webkit-box; -webkit-line-clamp: 3; line-clamp: 3; -webkit-box-orient: vertical; overflow: hidden; }
  .vendors { display: flex; gap: var(--space-1); flex-wrap: wrap; margin-block-start: var(--space-1_5); }
  .data-table .vendor-tag { font-size: var(--text-xs); color: var(--color-text-secondary); background: var(--color-surface-elevated); padding: 0.125rem 0.375rem; border-radius: var(--radius-sm); }
  .data-table .vendor-tag:hover { background: var(--color-surface-overlay); color: var(--color-text-primary); text-decoration: none; }

  /* Narrow screens: the table scrolls horizontally inside .table-wrap (same as
     the other tables); a shorter summary keeps rows from towering over the
     columns that are actually on screen. */
  @media (max-width: 700px) {
    .data-table th, .data-table td { padding-inline: var(--space-2); }
    .snippet { -webkit-line-clamp: 2; line-clamp: 2; }
  }
</style>
