<script lang="ts">
  import type { PageData } from './$types';
  import ChartIsland from '$lib/ui/charts/ChartIsland.svelte';
  import {
    dailyTableRows,
    fillDailySeries,
    severityDistribution,
    severityTableRows,
  } from '$lib/ui/charts/chartData';

  interface Props { data: PageData }
  let { data }: Props = $props();

  function pct(n: number) { return (n * 100).toFixed(1) + '%'; }
  function fmt(n: number) { return n.toLocaleString(); }

  // getMetrics('90d') queries `published_at > now - 90d`, i.e. 91 UTC days.
  const WINDOW_DAYS = 90;

  // Charts are client-only islands (dynamic import in onMount — see
  // ChartIsland.svelte): server-rendering LayerChart SVG blows the Workers
  // Free 10 ms CPU budget. Never import the chart components statically here.
  // `import.meta.env.SSR` is a literal `true` in the server build, so the
  // import() is dead code there and LayerChart (~1.2 MB) never ships in the
  // worker bundle at all — no cold-start parse cost, and no way to run it.
  const SERVER_ONLY = () => Promise.reject(new Error('chart islands are client-only'));
  const loadSeverityChart = () =>
    import.meta.env.SSR ? SERVER_ONLY() : import('$lib/ui/charts/SeverityChart.svelte');
  const loadDailyTrendChart = () =>
    import.meta.env.SSR ? SERVER_ONLY() : import('$lib/ui/charts/DailyTrendChart.svelte');

  const severity = $derived(severityDistribution(data.series.severityDistribution));
  const severityTotal = $derived(severity.reduce((sum, d) => sum + d.count, 0));
  const velocity = $derived(fillDailySeries(data.series.publicationVelocity, data.generatedAt, WINDOW_DAYS));
  const velocityTotal = $derived(velocity.reduce((sum, d) => sum + d.count, 0));
  const kevInflow = $derived(fillDailySeries(data.series.kevInflow, data.generatedAt, WINDOW_DAYS));
  const kevInflowTotal = $derived(kevInflow.reduce((sum, d) => sum + d.count, 0));
</script>

<svelte:head>
  <title>Dashboard — Threat-Lens CVE Hub</title>
</svelte:head>

<div class="page-dashboard">
  <header class="page-header">
    <h1 class="page-title">Live Intelligence Dashboard</h1>
    <p class="page-subtitle">90-day rolling window · updated {new Date(data.generatedAt).toLocaleString()}</p>
  </header>

  <!-- KPI cards -->
  <div class="kpi-grid" aria-label="Key performance indicators">
    <div class="kpi-card">
      <span class="kpi-label">Total CVEs</span>
      <span class="kpi-value">{fmt(data.kpis.totalCves)}</span>
    </div>
    <div class="kpi-card kpi-card--critical">
      <span class="kpi-label">Critical</span>
      <span class="kpi-value">{fmt(data.kpis.criticalCount)}</span>
    </div>
    <div class="kpi-card kpi-card--kev">
      <span class="kpi-label">KEV Listed</span>
      <span class="kpi-value">{fmt(data.kpis.kevCount)}</span>
    </div>
    <div class="kpi-card">
      <span class="kpi-label">Mean EPSS (7d)</span>
      <span class="kpi-value">{pct(data.kpis.meanEpssPercentile7d)}</span>
    </div>
  </div>

  <div class="charts-grid">
    <!-- Severity distribution -->
    <section class="chart-card" aria-labelledby="chart-severity-heading">
      <h2 id="chart-severity-heading" class="chart-title">Severity Distribution</h2>
      {#if severityTotal > 0}
        <ChartIsland
          load={loadSeverityChart}
          props={{ data: severity, height: 168 }}
          height={168}
          caption="CVEs by severity, last 90 days"
          columns={['Severity', 'CVEs']}
          rows={severityTableRows(severity)}
        />
      {:else}
        <p class="chart-empty">No data for this window.</p>
      {/if}
    </section>

    <!-- Publication velocity -->
    <section class="chart-card" aria-labelledby="chart-velocity-heading">
      <h2 id="chart-velocity-heading" class="chart-title">Publication Velocity (90d)</h2>
      {#if velocityTotal > 0}
        <ChartIsland
          load={loadDailyTrendChart}
          props={{ data: velocity, variant: 'area' as const, color: 'var(--color-brand-default)', label: 'CVEs published', height: 180 }}
          height={180}
          caption="CVEs published per day (UTC), last 90 days"
          columns={['Date (UTC)', 'CVEs published']}
          rows={dailyTableRows(velocity)}
        />
      {:else}
        <p class="chart-empty">No data for this window.</p>
      {/if}
    </section>
  </div>

  <div class="charts-grid">
    <!-- Top vendors -->
    <section class="chart-card" aria-labelledby="chart-vendors-heading">
      <h2 id="chart-vendors-heading" class="chart-title">Top Vendors by CVE Count</h2>
      <ol class="vendor-list">
        {#each data.series.topVendors.slice(0, 10) as row, i}
          <li class="vendor-row">
            <span class="vendor-rank">{i + 1}</span>
            <a href="/affected-products?vendor={encodeURIComponent(row.vendor)}" class="vendor-name">{row.vendor}</a>
            <span class="vendor-count">{fmt(row.cveCount)}</span>
            {#if row.kevCount > 0}
              <span class="vendor-kev-badge">KEV: {row.kevCount}</span>
            {/if}
          </li>
        {/each}
      </ol>
    </section>

    <!-- KEV inflow -->
    <section class="chart-card" aria-labelledby="chart-kev-heading">
      <h2 id="chart-kev-heading" class="chart-title">KEV Additions (90d)</h2>
      {#if kevInflowTotal > 0}
        <ChartIsland
          load={loadDailyTrendChart}
          props={{ data: kevInflow, variant: 'bar' as const, color: 'var(--color-kev)', label: 'KEV additions', height: 180 }}
          height={180}
          caption="CVEs added to the CISA KEV catalog per day (UTC), last 90 days"
          columns={['Date (UTC)', 'KEV additions']}
          rows={dailyTableRows(kevInflow)}
        />
      {:else}
        <p class="chart-empty">No KEV additions in this window.</p>
      {/if}
    </section>
  </div>
</div>

<style>
  .page-header { margin-block-end: var(--space-8); }
  .page-title {
    font-size: var(--text-2xl); font-weight: var(--weight-semibold);
    color: var(--color-text-primary); margin: 0;
  }
  .page-subtitle { font-size: var(--text-sm); color: var(--color-text-tertiary); margin: var(--space-1) 0 0; }

  .kpi-grid {
    display: grid; grid-template-columns: repeat(4, 1fr);
    gap: var(--layout-card-gap); margin-block-end: var(--layout-section-gap);
  }
  .kpi-card {
    background: var(--color-surface-raised); border: 1px solid var(--color-border-subtle);
    border-radius: var(--radius-md); padding: var(--space-5);
    display: flex; flex-direction: column; gap: var(--space-2);
  }
  .kpi-card--critical { border-color: var(--color-critical-border); }
  /* app.css has no --color-kev-border; KEV is the critical hue family by design. */
  .kpi-card--kev { border-color: var(--color-critical-border); }
  .kpi-label { font-size: var(--text-sm); color: var(--color-text-secondary); }
  .kpi-value { font-size: var(--text-3xl); font-weight: var(--weight-semibold); color: var(--color-text-primary); line-height: 1; }

  .charts-grid {
    display: grid; grid-template-columns: 1fr 1fr;
    gap: var(--layout-card-gap); margin-block-end: var(--layout-section-gap);
  }
  .chart-card {
    background: var(--color-surface-raised); border: 1px solid var(--color-border-subtle);
    border-radius: var(--radius-md); padding: var(--space-5);
  }
  .chart-title { font-size: var(--text-sm); font-weight: var(--weight-semibold); color: var(--color-text-secondary); margin: 0 0 var(--space-4); text-transform: uppercase; letter-spacing: var(--tracking-wide); }
  .chart-empty { font-size: var(--text-sm); color: var(--color-text-tertiary); }

  .vendor-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: var(--space-2); }
  .vendor-row { display: flex; align-items: center; gap: var(--space-2); font-size: var(--text-sm); }
  .vendor-rank { width: 1.25rem; color: var(--color-text-tertiary); font-size: var(--text-xs); flex-shrink: 0; }
  .vendor-name { flex: 1; color: var(--color-text-primary); text-decoration: none; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .vendor-name:hover { text-decoration: underline; }
  .vendor-count { color: var(--color-text-secondary); font-size: var(--text-xs); flex-shrink: 0; }
  .vendor-kev-badge { font-size: var(--text-xs); color: var(--color-kev-text); background: var(--color-kev-subtle); padding: 0.125rem 0.375rem; border-radius: var(--radius-full); flex-shrink: 0; }

  @media (max-width: 900px) {
    .kpi-grid { grid-template-columns: repeat(2, 1fr); }
    .charts-grid { grid-template-columns: 1fr; }
  }
</style>
