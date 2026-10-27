<script lang="ts">
  import type { PageData } from './$types';

  interface Props { data: PageData }
  let { data }: Props = $props();

  function pct(n: number) { return (n * 100).toFixed(1) + '%'; }
  function fmt(n: number) { return n.toLocaleString(); }
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
      <div class="bar-chart" role="list">
        {#each data.series.severityDistribution as row}
          {@const total = data.series.severityDistribution.reduce((s, r) => s + r.count, 0)}
          {@const pctVal = total > 0 ? (row.count / total) * 100 : 0}
          <div class="bar-row" role="listitem">
            <span class="bar-label badge--{row.severity.toLowerCase()}">{row.severity}</span>
            <div class="bar-track" title="{row.count.toLocaleString()} CVEs">
              <div class="bar-fill bar-fill--{row.severity.toLowerCase()}" style="width:{pctVal.toFixed(1)}%"></div>
            </div>
            <span class="bar-count">{fmt(row.count)}</span>
          </div>
        {/each}
      </div>
    </section>

    <!-- Publication velocity -->
    <section class="chart-card" aria-labelledby="chart-velocity-heading">
      <h2 id="chart-velocity-heading" class="chart-title">Publication Velocity (90d)</h2>
      <div class="sparkline-wrap">
        {#if data.series.publicationVelocity.length > 0}
          {@const max = Math.max(...data.series.publicationVelocity.map(r => r.count), 1)}
          <div class="sparkline" role="img" aria-label="Publication velocity sparkline">
            {#each data.series.publicationVelocity.slice().reverse() as row}
              <div
                class="spark-bar"
                style="height:{((row.count / max) * 100).toFixed(1)}%"
                title="{row.date}: {row.count}"
              ></div>
            {/each}
          </div>
        {:else}
          <p class="chart-empty">No data for this window.</p>
        {/if}
      </div>
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
      <div class="sparkline-wrap">
        {#if data.series.kevInflow.length > 0}
          {@const max = Math.max(...data.series.kevInflow.map(r => r.count), 1)}
          <div class="sparkline sparkline--kev" role="img" aria-label="KEV inflow sparkline">
            {#each data.series.kevInflow.slice().reverse() as row}
              <div
                class="spark-bar spark-bar--kev"
                style="height:{((row.count / max) * 100).toFixed(1)}%"
                title="{row.date}: {row.count}"
              ></div>
            {/each}
          </div>
        {:else}
          <p class="chart-empty">No KEV additions in this window.</p>
        {/if}
      </div>
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
  .kpi-card--critical { border-color: #7f1d1d; }
  .kpi-card--kev { border-color: #7c2d12; }
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

  .bar-chart { display: flex; flex-direction: column; gap: var(--space-2); }
  .bar-row { display: grid; grid-template-columns: 6rem 1fr 4rem; align-items: center; gap: var(--space-2); }
  .bar-label { font-size: var(--text-xs); font-weight: var(--weight-medium); text-transform: uppercase; letter-spacing: var(--tracking-wide); }
  .badge--critical { color: #fca5a5; }
  .badge--high { color: #fed7aa; }
  .badge--medium { color: #fde68a; }
  .badge--low { color: #86efac; }
  .badge--none { color: var(--color-text-tertiary); }
  .bar-track { height: 0.5rem; background: var(--color-surface-elevated); border-radius: var(--radius-full); overflow: hidden; }
  .bar-fill { height: 100%; border-radius: var(--radius-full); transition: width 0.3s ease; }
  .bar-fill--critical { background: #ef4444; }
  .bar-fill--high { background: #f97316; }
  .bar-fill--medium { background: #eab308; }
  .bar-fill--low { background: #22c55e; }
  .bar-fill--none { background: var(--color-text-tertiary); }
  .bar-count { font-size: var(--text-xs); color: var(--color-text-tertiary); text-align: right; }

  .sparkline-wrap { height: 8rem; position: relative; }
  .sparkline { display: flex; align-items: flex-end; gap: 2px; height: 100%; }
  .spark-bar { flex: 1; min-width: 2px; background: var(--color-brand-500); border-radius: 1px 1px 0 0; opacity: 0.7; }
  .spark-bar--kev { background: #f97316; }

  .vendor-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: var(--space-2); }
  .vendor-row { display: flex; align-items: center; gap: var(--space-2); font-size: var(--text-sm); }
  .vendor-rank { width: 1.25rem; color: var(--color-text-tertiary); font-size: var(--text-xs); flex-shrink: 0; }
  .vendor-name { flex: 1; color: var(--color-text-primary); text-decoration: none; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .vendor-name:hover { text-decoration: underline; }
  .vendor-count { color: var(--color-text-secondary); font-size: var(--text-xs); flex-shrink: 0; }
  .vendor-kev-badge { font-size: var(--text-xs); color: #fed7aa; background: #7c2d12; padding: 0.125rem 0.375rem; border-radius: var(--radius-full); flex-shrink: 0; }

  @media (max-width: 900px) {
    .kpi-grid { grid-template-columns: repeat(2, 1fr); }
    .charts-grid { grid-template-columns: 1fr; }
  }
</style>
