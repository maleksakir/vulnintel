import type { MetricsSeries, Severity } from '@threat-lens/contracts';

/*
 * Pure data shaping for the dashboard charts. Kept free of Svelte, LayerChart
 * and any browser API: the page runs these during SSR to build the
 * accessible data tables, while the charts themselves render client-only
 * (see ChartIsland.svelte).
 *
 * Every date is a UTC calendar day — D1 buckets with
 * `DATE(ms / 1000, 'unixepoch')`, i.e. UTC — and every formatter pins both
 * locale and timezone. Otherwise an analyst west of UTC would see each bar
 * labelled with the previous day, and the server-rendered table and the
 * client-rendered chart could disagree.
 */

const DAY_MS = 86_400_000;

export const SEVERITY_ORDER: readonly Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'];

const SEVERITY_LABEL: Record<Severity, string> = {
  CRITICAL: 'Critical',
  HIGH: 'High',
  MEDIUM: 'Medium',
  LOW: 'Low',
  NONE: 'None',
};

/**
 * Severity colours as references to the app.css design tokens, never literal
 * values: SVG `fill` resolves `var()` against the live cascade, so the bars
 * follow `[data-theme]` without the chart re-rendering.
 */
export const SEVERITY_COLOR: Record<Severity, string> = {
  CRITICAL: 'var(--color-critical)',
  HIGH: 'var(--color-high)',
  MEDIUM: 'var(--color-medium)',
  LOW: 'var(--color-low)',
  NONE: 'var(--color-none)',
};

export interface SeverityDatum {
  severity: Severity;
  label: string;
  count: number;
}

/**
 * Every severity in canonical order (zero-filled so the chart layout is
 * stable). `cve.severity` is nullable in D1 (CHECK constraint, no NOT NULL);
 * current ingest maps "no CVSS" to 'NONE', so a NULL or unexpected value is
 * folded into NONE rather than dropped or allowed to throw.
 */
export function severityDistribution(
  rows: readonly MetricsSeries['severityDistribution'][number][],
): SeverityDatum[] {
  const counts = new Map<Severity, number>(SEVERITY_ORDER.map((s) => [s, 0]));
  for (const row of rows) {
    const key: Severity = SEVERITY_ORDER.includes(row.severity) ? row.severity : 'NONE';
    counts.set(key, (counts.get(key) ?? 0) + (Number(row.count) || 0));
  }
  return SEVERITY_ORDER.map((severity) => ({
    severity,
    label: SEVERITY_LABEL[severity],
    count: counts.get(severity) ?? 0,
  }));
}

export interface DailyDatum {
  /** UTC calendar day, `YYYY-MM-DD` — matches D1's `DATE(..., 'unixepoch')`. */
  day: string;
  /** UTC midnight of `day`. */
  date: Date;
  count: number;
}

/**
 * Expands sparse daily rows (D1 only returns days with at least one event)
 * into a continuous, ascending series of `days + 1` UTC days ending on the UTC
 * day of `endIso`, with missing days as zero. Without this a trend line would
 * silently interpolate across gaps and bar spacing would be uneven.
 */
export function fillDailySeries(
  rows: readonly { date: string; count: number }[],
  endIso: string,
  days: number,
): DailyDatum[] {
  const end = new Date(endIso);
  if (Number.isNaN(end.getTime())) return [];
  const endDay = Date.UTC(end.getUTCFullYear(), end.getUTCMonth(), end.getUTCDate());

  const byDay = new Map<string, number>();
  for (const row of rows)
    byDay.set(row.date, (byDay.get(row.date) ?? 0) + (Number(row.count) || 0));

  const out: DailyDatum[] = [];
  for (let i = days; i >= 0; i--) {
    const date = new Date(endDay - i * DAY_MS);
    const day = isoDay(date);
    out.push({ day, date, count: byDay.get(day) ?? 0 });
  }
  return out;
}

/*
 * Date strings are built by hand from UTC getters rather than with
 * Intl.DateTimeFormat / toISOString: this runs for 2 x 91 days on every SSR
 * request, and Workers Free allows 10 ms CPU per request. Measured: ~1.2 ms
 * per request with Intl + toISOString vs ~0.05 ms like this, same output.
 */
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

const pad2 = (n: number) => (n < 10 ? `0${n}` : `${n}`);

function isoDay(d: Date): string {
  return `${d.getUTCFullYear()}-${pad2(d.getUTCMonth() + 1)}-${pad2(d.getUTCDate())}`;
}

/** [year, monthIndex, day] of a Date (UTC) or a `YYYY-MM-DD` string. */
function utcParts(value: unknown): [number, number, number] | null {
  if (value instanceof Date) {
    return Number.isNaN(value.getTime())
      ? null
      : [value.getUTCFullYear(), value.getUTCMonth(), value.getUTCDate()];
  }
  if (typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value)) {
    const month = Number(value.slice(5, 7)) - 1;
    if (month < 0 || month > 11) return null;
    return [Number(value.slice(0, 4)), month, Number(value.slice(8, 10))];
  }
  return null;
}

/**
 * Up to `maxTicks` evenly spaced points, anchored on the most recent day so
 * "today" is always labelled, at the same days on every chart and at any
 * container width.
 */
export function dailyTicks(series: readonly DailyDatum[], maxTicks = 6): DailyDatum[] {
  if (series.length === 0) return [];
  const step = Math.max(1, Math.ceil((series.length - 1) / maxTicks));
  const ticks: DailyDatum[] = [];
  for (let i = series.length - 1; i >= 0; i -= step) ticks.unshift(series[i] as DailyDatum);
  return ticks;
}

/**
 * Integer-only value-axis ticks: counts are whole numbers, and on a small
 * domain (e.g. 0..2 KEV additions) d3 would otherwise offer 0.5 steps.
 */
export function integerTicks(scale: { ticks?: (count?: number) => number[] }, count = 4): number[] {
  return (scale.ticks?.(count) ?? []).filter((v) => Number.isInteger(v));
}

const intFormat = new Intl.NumberFormat('en-US', { maximumFractionDigits: 0 });
const pctFormat = new Intl.NumberFormat('en-US', { style: 'percent', maximumFractionDigits: 1 });

/** "1,234" — fixed en-US grouping, independent of server/browser locale. */
export function formatCount(value: unknown): string {
  const n = Math.round(Number(value) || 0);
  // Fast path: most daily counts need no grouping separator (see above).
  return n > -1000 && n < 1000 ? String(n) : intFormat.format(n);
}

export function formatShare(part: number, total: number): string {
  return total > 0 ? pctFormat.format(part / total) : pctFormat.format(0);
}

/** Axis label for a UTC day, e.g. "Oct 28". Accepts a Date or `YYYY-MM-DD`. */
export function formatShortDay(value: unknown): string {
  const p = utcParts(value);
  return p ? `${MONTHS[p[1]]} ${p[2]}` : String(value ?? '');
}

/** Tooltip/table label for a UTC day, e.g. "Oct 28, 2026". */
export function formatLongDay(value: unknown): string {
  const p = utcParts(value);
  return p ? `${MONTHS[p[1]]} ${p[2]}, ${p[0]}` : String(value ?? '');
}

export type TableRow = readonly [string, string];

/** Rows for the screen-reader table behind the severity chart. */
export function severityTableRows(data: readonly SeverityDatum[]): TableRow[] {
  const total = data.reduce((sum, d) => sum + d.count, 0);
  return data.map((d) => [d.label, `${formatCount(d.count)} (${formatShare(d.count, total)})`]);
}

/** Rows for the screen-reader table behind a daily trend chart. */
export function dailyTableRows(data: readonly DailyDatum[]): TableRow[] {
  return data.map((d) => [formatLongDay(d.day), formatCount(d.count)]);
}
