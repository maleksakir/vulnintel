<script lang="ts">
  // Client-only: loaded via ChartIsland's onMount import(), never rendered
  // during SSR (see ChartIsland.svelte for the Workers CPU-budget reason).
  import { BarChart, Text, Tooltip } from 'layerchart/svg';
  import {
    SEVERITY_COLOR,
    SEVERITY_ORDER,
    formatCount,
    formatShare,
    type SeverityDatum,
  } from './chartData';

  interface Props {
    /** Output of `severityDistribution()` — every severity, canonical order. */
    data: SeverityDatum[];
    height: number;
  }

  let { data, height }: Props = $props();

  const total = $derived(data.reduce((sum, d) => sum + d.count, 0));
  const colorDomain = [...SEVERITY_ORDER];
  const colorRange = SEVERITY_ORDER.map((s) => SEVERITY_COLOR[s]);
</script>

<!--
  Per-bar colour comes from the `c` channel mapped onto app.css token
  references. Value labels are drawn in `aboveMarks` with Text rather than
  the `labels` prop, which LayerChart lazy-loads in a second round-trip.
  LayerChart's Bars default to a 1px black stroke, hence stroke: 'none'.
-->
<BarChart
  {data}
  orientation="horizontal"
  y="label"
  x="count"
  c="severity"
  cDomain={colorDomain}
  cRange={colorRange}
  bandPadding={0.3}
  axis="y"
  grid={false}
  padding={{ top: 4, right: 52, bottom: 4, left: 56 }}
  props={{ bars: { radius: 3, stroke: 'none', strokeWidth: 0 }, yAxis: { tickMarks: false } }}
  {height}
>
  {#snippet aboveMarks({ context })}
    {#each data as d (d.severity)}
      <Text
        x={context.xScale(d.count) + 6}
        y={(context.yScale(d.label) ?? 0) + (context.yScale.bandwidth?.() ?? 0) / 2}
        value={formatCount(d.count)}
        textAnchor="start"
        verticalAnchor="middle"
        class="severity-chart__value"
      />
    {/each}
  {/snippet}

  {#snippet tooltip()}
    <Tooltip.Root>
      {#snippet children({ data: d })}
        <Tooltip.Header value={d.label} color={SEVERITY_COLOR[d.severity as SeverityDatum['severity']]} />
        <Tooltip.List>
          <Tooltip.Item label="CVEs" value={formatCount(d.count)} />
          <Tooltip.Item label="Share" value={formatShare(d.count, total)} />
        </Tooltip.List>
      {/snippet}
    </Tooltip.Root>
  {/snippet}
</BarChart>

<style>
  :global(.severity-chart__value) {
    --fill-color: var(--color-text-secondary);
    font-size: var(--text-xs);
    font-variant-numeric: tabular-nums;
  }
</style>
