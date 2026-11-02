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
  <header class="page-header hud-grid scanline boot-in">
    <div class="page-header__row">
      <div>
        <p class="page-eyebrow"><span class="live-dot" aria-hidden="true"></span> LIVE INTELLIGENCE FEED</p>
        <h1 class="page-title glow-text">Threat Command</h1>
        <p class="page-subtitle">
          Global CVE telemetry · 90-day rolling window
        </p>
      </div>
      <dl class="page-header__readouts" aria-label="Feed status">
        <div class="readout"><dt class="readout__key">WINDOW</dt><dd class="readout__val">90D</dd></div>
        <div class="readout"><dt class="readout__key">SYNC</dt><dd class="readout__val"><time datetime={data.generatedAt}>{new Date(data.generatedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}Z</time></dd></div>
        <div class="readout"><dt class="readout__key">STATUS</dt><dd class="readout__val readout__val--ok">NOMINAL</dd></div>
      </dl>
    </div>
  </header>

  <!-- KPI cards -->
  <div class="cmd-heading"><span class="cmd-heading__text">Threat Posture</span></div>
  <div class="kpi-grid" aria-label="Key performance indicators">
    <div class="kpi-card boot-in" style="--boot-delay:40ms">
      <span class="kpi-label">Total CVEs</span>
      <span class="kpi-value mono">{fmt(data.kpis.totalCves)}</span>
      <span class="kpi-meta">tracked in window</span>
    </div>
    <div class="kpi-card kpi-card--critical boot-in" style="--boot-delay:80ms">
      <span class="kpi-label">Critical</span>
      <span class="kpi-value mono">{fmt(data.kpis.criticalCount)}</span>
      <span class="kpi-meta">severity ≥ 9.0</span>
    </div>
    <div class="kpi-card kpi-card--kev boot-in" style="--boot-delay:120ms">
      <span class="kpi-label">KEV Listed</span>
      <span class="kpi-value mono">{fmt(data.kpis.kevCount)}</span>
      <span class="kpi-meta">actively exploited</span>
    </div>
    <div class="kpi-card kpi-card--epss boot-in" style="--boot-delay:160ms">
      <span class="kpi-label">Mean EPSS (7d)</span>
      <span class="kpi-value mono">{pct(data.kpis.meanEpssPercentile7d)}</span>
      <span class="kpi-meta">exploit probability</span>
    </div>
  </div>

  <div class="cmd-heading"><span class="cmd-heading__text">Telemetry Channels</span></div>

  <div class="charts-grid">
    <!-- Severity distribution -->
    <section class="cmd-panel boot-in" aria-labelledby="chart-severity-heading">
      <header class="cmd-panel__bar">
        <span class="cmd-panel__index">01 /</span>
        <h2 id="chart-severity-heading" class="cmd-panel__label">Severity Matrix</h2>
        <span class="cmd-panel__status">Live</span>
      </header>
      <div class="cmd-panel__body">
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
      </div>
    </section>

    <!-- Publication velocity -->
    <section class="cmd-panel boot-in" style="--boot-delay:60ms" aria-labelledby="chart-velocity-heading">
      <header class="cmd-panel__bar">
        <span class="cmd-panel__index">02 /</span>
        <h2 id="chart-velocity-heading" class="cmd-panel__label">Publication Velocity</h2>
        <span class="cmd-panel__status">Live</span>
      </header>
      <div class="cmd-panel__body">
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
      </div>
    </section>
  </div>

  <div class="charts-grid">
    <!-- Top vendors -->
    <section class="cmd-panel boot-in" aria-labelledby="chart-vendors-heading">
      <header class="cmd-panel__bar">
        <span class="cmd-panel__index">03 /</span>
        <h2 id="chart-vendors-heading" class="cmd-panel__label">Top Vendors — Exposure</h2>
      </header>
      <div class="cmd-panel__body">
      <ol class="vendor-list">
        {#each data.series.topVendors.slice(0, 10) as row, i}
          <li class="vendor-row">
            <span class="vendor-rank mono">{String(i + 1).padStart(2, '0')}</span>
            <a href="/affected-products?vendor={encodeURIComponent(row.vendor)}" class="vendor-name">{row.vendor}</a>
            <span class="vendor-count mono">{fmt(row.cveCount)}</span>
            {#if row.kevCount > 0}
              <span class="vendor-kev-badge">KEV {row.kevCount}</span>
            {/if}
          </li>
        {/each}
      </ol>
      </div>
    </section>
    <!-- KEV inflow -->
    <section class="cmd-panel cmd-panel--live boot-in" style="--boot-delay:60ms" aria-labelledby="chart-kev-heading">
      <header class="cmd-panel__bar">
        <span class="cmd-panel__index">04 /</span>
        <h2 id="chart-kev-heading" class="cmd-panel__label">KEV Additions</h2>
        <span class="cmd-panel__status">Live</span>
      </header>
      <div class="cmd-panel__body">
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
      </div>
    </section>
  </div>
</div>

<style>
  .page-header {
    margin-block-end: var(--space-8);
    padding: var(--space-6) var(--space-6) var(--space-7);
    border: 1px solid var(--color-border-default);
    border-radius: var(--radius-lg);
    background:
      radial-gradient(120% 140% at 0% 0%, var(--color-brand-subtle) 0%, transparent 45%),
      var(--color-surface-raised);
    overflow: hidden;
  }
  .page-eyebrow {
    display: flex; align-items: center; gap: var(--space-2);
    margin: 0 0 var(--space-2);
    font-family: var(--font-mono);
    font-size: var(--text-xs);
    letter-spacing: var(--tracking-caps);
    text-transform: uppercase;
    color: var(--color-brand-text);
  }
  .page-title {
    font-size: var(--text-3xl); font-weight: var(--weight-bold);
    color: var(--color-text-primary); margin: 0;
    letter-spacing: var(--tracking-tight);
  }
  .page-subtitle { font-size: var(--text-sm); color: var(--color-text-tertiary); margin: var(--space-2) 0 0; }

  .kpi-grid {
    display: grid; grid-template-columns: repeat(4, 1fr);
    gap: var(--layout-card-gap); margin-block-end: var(--layout-section-gap);
  }
  .kpi-card {
    position: relative;
    background: var(--color-surface-raised); border: 1px solid var(--color-border-default);
    border-radius: var(--radius-lg); padding: var(--space-5);
    display: flex; flex-direction: column; gap: var(--space-1_5);
    overflow: hidden;
    transition: var(--transition-colors), var(--transition-transform);
  }
  /* Accent rail down the left edge of every KPI — brand by default,
     recoloured per severity below. */
  .kpi-card::before {
    content: '';
    position: absolute; inset: 0 auto 0 0; width: 3px;
    background: var(--color-brand-default);
    box-shadow: var(--glow-accent);
  }
  .kpi-card:hover { transform: translateY(-2px); border-color: var(--color-border-strong); }
  .kpi-card--critical::before { background: var(--color-critical); box-shadow: var(--glow-critical); }
  .kpi-card--kev::before { background: var(--color-kev); box-shadow: var(--glow-critical); }
  .kpi-card--epss::before { background: var(--color-epss); box-shadow: 0 0 16px -4px var(--color-epss); }
  .kpi-card--critical { border-color: var(--color-critical-border); }
  .kpi-card--kev { border-color: var(--color-kev-subtle); }
  .kpi-label {
    font-size: var(--text-xs); color: var(--color-text-secondary);
    text-transform: uppercase; letter-spacing: var(--tracking-wide);
    font-weight: var(--weight-medium);
  }
  .kpi-value {
    font-size: var(--text-4xl); font-weight: var(--weight-bold);
    color: var(--color-text-primary); line-height: 1;
  }
  .kpi-card--critical .kpi-value { color: var(--color-critical-text); }
  .kpi-card--kev .kpi-value { color: var(--color-kev-text); }
  .kpi-card--epss .kpi-value { color: var(--color-epss-text); }
  .kpi-meta {
    font-size: var(--text-2xs); color: var(--color-text-tertiary);
    text-transform: uppercase; letter-spacing: var(--tracking-wide);
  }

  /* Header row + telemetry readouts */
  .page-header__row {
    display: flex; align-items: flex-start; justify-content: space-between;
    gap: var(--space-4); flex-wrap: wrap;
  }
  .page-header__readouts {
    display: flex; gap: var(--space-5); margin: 0;
    padding: var(--space-3) var(--space-4);
    border: 1px solid var(--color-border-default);
    border-radius: var(--radius-md);
    background: var(--color-surface-sunken);
  }
  .page-header__readouts .readout { flex-direction: column; gap: 2px; }
  .page-header__readouts dt { margin: 0; }
  .page-header__readouts dd { margin: 0; font-size: var(--text-sm); }
  .readout__val--ok { color: var(--color-low-text) !important; }

  .charts-grid {
    display: grid; grid-template-columns: 1fr 1fr;
    gap: var(--layout-card-gap); margin-block-end: var(--layout-section-gap);
  }
  .chart-empty { font-size: var(--text-sm); color: var(--color-text-tertiary); }

  .vendor-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; }
  .vendor-row {
    display: flex; align-items: center; gap: var(--space-3); font-size: var(--text-sm);
    padding: var(--space-2) 0; border-bottom: 1px solid var(--color-border-subtle);
  }
  .vendor-row:last-child { border-bottom: none; }
  .vendor-rank { width: 1.75rem; color: var(--color-brand-text); font-size: var(--text-xs); flex-shrink: 0; opacity: 0.75; }
  .vendor-name { flex: 1; color: var(--color-text-primary); text-decoration: none; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .vendor-name:hover { color: var(--color-brand-text); }
  .vendor-count { color: var(--color-text-secondary); font-size: var(--text-sm); flex-shrink: 0; font-weight: var(--weight-semibold); }
  .vendor-kev-badge {
    font-family: var(--font-mono); font-size: var(--text-2xs); letter-spacing: var(--tracking-wide);
    color: var(--color-kev-text); background: var(--color-kev-subtle);
    border: 1px solid var(--color-kev); padding: 0.125rem 0.375rem; border-radius: var(--radius-sm); flex-shrink: 0;
  }

  @media (max-width: 900px) {
    .kpi-grid { grid-template-columns: repeat(2, 1fr); }
    .charts-grid { grid-template-columns: 1fr; }
    .page-header__readouts { width: 100%; }
  }
</style>
