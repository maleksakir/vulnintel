<script lang="ts" generics="P extends Record<string, unknown>">
  import { onMount, type Component } from 'svelte';

  /*
   * Client-only island for a LayerChart chart.
   *
   * Why not server-render the SVG: measured 2026-10-28 against the built
   * SSR bundle, rendering these LayerChart charts on the server cost roughly
   * 30–400 ms of CPU per request (scaling with mark count: ~30 ms for the
   * 5-bar severity chart alone, ~200+ ms for 91 daily bars). Workers Free
   * kills a request at 10 ms CPU, so any server-rendered LayerChart chart
   * would fail every dashboard load in production.
   *
   * So the chart component is only ever `import()`ed inside onMount, which
   * never runs during SSR: no LayerChart code is evaluated or rendered on the
   * server at all (which also rules out browser-global crashes in the
   * library's internals), and the library ships as a lazy chunk instead of
   * blocking hydration. The server renders a fixed-height skeleton (so the
   * card doesn't change size when the chart arrives) and the same numbers as
   * a visually hidden table for screen readers.
   */
  interface Props {
    /** Dynamic import of the chart component, e.g. `() => import('./SeverityChart.svelte')`. */
    load: () => Promise<{ default: Component<P> }>;
    /** Props forwarded to the chart once loaded. */
    props: P;
    height: number;
    /** Accessible name for the data table (the visible title lives in the card). */
    caption: string;
    columns: readonly [string, string];
    rows: readonly (readonly [string, string])[];
  }

  let { load, props, height, caption, columns, rows }: Props = $props();

  let Chart = $state<Component<P> | null>(null);
  let failed = $state(false);

  onMount(() => {
    let cancelled = false;
    load()
      .then((mod) => {
        if (!cancelled) Chart = mod.default;
      })
      .catch(() => {
        // e.g. a stale chunk hash after a deploy; the data is still in the table.
        if (!cancelled) failed = true;
      });
    return () => {
      cancelled = true;
    };
  });
</script>

<div class="chart-island">
  <div class="chart-island__plot" style:height="{height}px" aria-hidden="true">
    {#if Chart}
      <Chart {...props} />
    {:else if failed}
      <p class="chart-island__failed">Chart unavailable — reload the page to try again.</p>
    {:else}
      <div class="skeleton chart-island__skeleton"></div>
    {/if}
  </div>
  <table class="chart-island__sr-table">
    <caption>{caption}</caption>
    <thead>
      <tr><th scope="col">{columns[0]}</th><th scope="col">{columns[1]}</th></tr>
    </thead>
    <tbody>
      {#each rows as [label, value]}
        <tr><th scope="row">{label}</th><td>{value}</td></tr>
      {/each}
    </tbody>
  </table>
</div>

<style>
  .chart-island {
    position: relative;
  }

  .chart-island__plot {
    position: relative;
    width: 100%;
  }

  .chart-island__skeleton {
    width: 100%;
    height: 100%;
  }

  .chart-island__failed {
    font-size: var(--text-sm);
    color: var(--color-text-tertiary);
  }

  /* LayerChart reads these custom properties for axis text, gridlines, the
     text halo behind tick labels, and the tooltip surface. Pointing them at
     app.css tokens (never literal colours) keeps both themes correct, and
     because they're resolved live, a theme toggle needs no re-render. The
     tooltip is portalled to <body>, outside this component, so it needs the
     mapping on its own root too. */
  .chart-island__plot :global(.lc-root-container) {
    --color-surface-content: var(--color-text-secondary);
    --color-surface-100: var(--color-surface-raised);
    --color-surface-200: var(--color-surface-overlay);
    --color-surface-300: var(--color-surface-overlay);
    --color-primary: var(--color-brand-default);
    font-family: var(--font-sans);
  }

  .chart-island__plot :global(.lc-axis-tick-label) {
    font-size: var(--text-2xs);
    font-weight: var(--weight-regular);
  }

  :global(.lc-tooltip-root) {
    --color-surface-content: var(--color-text-primary);
    --color-surface-100: var(--color-surface-overlay);
    --color-surface-300: var(--color-surface-overlay);
    --color-primary: var(--color-brand-default);
    z-index: var(--z-tooltip);
  }

  :global(.lc-tooltip-root .lc-tooltip-container) {
    border: 1px solid var(--color-border-default);
    font-size: var(--text-xs);
  }

  .chart-island__sr-table {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border: 0;
  }
</style>
