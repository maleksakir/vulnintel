<script lang="ts">
  // Client-only: loaded via ChartIsland's onMount import(), never rendered
  // during SSR (see ChartIsland.svelte for the Workers CPU-budget reason).
  import { scaleUtc } from 'd3-scale';
  import { AreaChart, BarChart, Tooltip } from 'layerchart/svg';
  import {
    dailyTicks,
    formatCount,
    formatLongDay,
    formatShortDay,
    integerTicks,
    type DailyDatum,
  } from './chartData';

  interface Props {
    /** Output of `fillDailySeries()` — continuous, ascending, zero-filled. */
    data: DailyDatum[];
    /** `area` for a continuous trend, `bar` for sparse discrete events. */
    variant: 'area' | 'bar';
    /** A CSS colour reference to an app.css token, e.g. `var(--color-kev)`. */
    color: string;
    /** Series name shown in the tooltip, e.g. "CVEs published". */
    label: string;
    height: number;
  }

  let { data, variant, color, label, height }: Props = $props();

  const ticks = $derived(dailyTicks(data));
  const series = $derived([{ key: 'count', label, value: 'count', color }]);

  // `right` leaves room for the centred "today" tick label on the last point.
  const padding = { top: 8, right: 20, bottom: 22, left: 36 };
  const yAxis = { ticks: (scale: any) => integerTicks(scale), format: formatCount };
</script>

{#snippet dayTooltip()}
  <Tooltip.Root>
    {#snippet children({ data: d })}
      <Tooltip.Header value={formatLongDay(d.day)} />
      <Tooltip.List>
        <Tooltip.Item {label} value={formatCount(d.count)} {color} />
      </Tooltip.List>
    {/snippet}
  </Tooltip.Root>
{/snippet}

{#if variant === 'area'}
  <!-- scaleUtc, not LayerChart's default (local-time) scaleTime: the buckets
       are UTC days, and a local scale would shift ticks and tooltip dates by
       the analyst's timezone offset. -->
  <AreaChart
    {data}
    x="date"
    y="count"
    xScale={scaleUtc()}
    {series}
    {padding}
    props={{
      xAxis: { ticks: ticks.map((t) => t.date), format: formatShortDay },
      yAxis,
    }}
    tooltip={dayTooltip}
    {height}
  />
{:else}
  <!-- Band scale keyed on the `YYYY-MM-DD` string: one bar per UTC day, no
       Date/timezone handling at all. Bars default to a 1px black stroke. -->
  <BarChart
    {data}
    x="day"
    y="count"
    {series}
    bandPadding={0.25}
    {padding}
    props={{
      bars: { radius: 1, stroke: 'none', strokeWidth: 0 },
      xAxis: { ticks: ticks.map((t) => t.day), format: formatShortDay },
      yAxis,
    }}
    tooltip={dayTooltip}
    {height}
  />
{/if}
