import { describe, expect, it } from 'vitest';
import {
  dailyTicks,
  fillDailySeries,
  formatCount,
  formatLongDay,
  formatShortDay,
  SEVERITY_ORDER,
  severityDistribution,
} from '../src/lib/ui/charts/chartData';

const DAY_MS = 86_400_000;

describe('fillDailySeries', () => {
  it('zero-fills a continuous, ascending window of days + 1 UTC days ending on the end day', () => {
    const series = fillDailySeries(
      [
        { date: '2026-10-28', count: 5 },
        { date: '2026-10-26', count: 2 },
        { date: '2026-07-30', count: 1 },
      ],
      '2026-10-28T23:59:00.000Z',
      90,
    );

    expect(series).toHaveLength(91);
    expect(series[0]?.day).toBe('2026-07-30');
    expect(series.at(-1)?.day).toBe('2026-10-28');
    expect(series.map((d) => d.count).filter((c) => c > 0)).toEqual([1, 2, 5]);
    expect(series.find((d) => d.day === '2026-10-27')?.count).toBe(0);
    const times = series.map((d) => d.date.getTime());
    expect(times.slice(1).map((t, i) => t - (times[i] ?? 0))).toEqual(Array(90).fill(DAY_MS));
  });

  it('uses the UTC day of the end timestamp, not the local one', () => {
    // 00:30 UTC on Oct 28 is still Oct 27 in the Americas.
    const series = fillDailySeries([], '2026-10-28T00:30:00.000Z', 1);
    expect(series.map((d) => d.day)).toEqual(['2026-10-27', '2026-10-28']);
  });

  it('returns an empty series for an unparseable end timestamp', () => {
    expect(fillDailySeries([{ date: '2026-10-28', count: 1 }], 'not-a-date', 90)).toEqual([]);
  });
});

describe('severityDistribution', () => {
  it('returns every severity in canonical order, folding NULL into NONE', () => {
    const rows = [
      { severity: 'MEDIUM', count: 10 },
      { severity: null, count: 3 },
      { severity: 'NONE', count: 2 },
      { severity: 'CRITICAL', count: 1 },
    ] as unknown as Parameters<typeof severityDistribution>[0];

    expect(severityDistribution(rows)).toEqual([
      { severity: 'CRITICAL', label: 'Critical', count: 1 },
      { severity: 'HIGH', label: 'High', count: 0 },
      { severity: 'MEDIUM', label: 'Medium', count: 10 },
      { severity: 'LOW', label: 'Low', count: 0 },
      { severity: 'NONE', label: 'None', count: 5 },
    ]);
    expect(SEVERITY_ORDER).toHaveLength(5);
  });
});

describe('formatting', () => {
  // The formatters avoid Intl for SSR CPU cost; they must still produce
  // exactly what Intl en-US/UTC would.
  const shortIntl = new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: 'numeric',
    timeZone: 'UTC',
  });
  const longIntl = new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    timeZone: 'UTC',
  });

  it('matches Intl en-US (UTC) day formatting for Dates and YYYY-MM-DD strings', () => {
    const start = Date.UTC(2026, 0, 1);
    for (let i = 0; i < 400; i++) {
      const date = new Date(start + i * DAY_MS);
      const iso = date.toISOString().slice(0, 10);
      expect(formatShortDay(date)).toBe(shortIntl.format(date));
      expect(formatShortDay(iso)).toBe(shortIntl.format(date));
      expect(formatLongDay(iso)).toBe(longIntl.format(date));
    }
  });

  it('matches Intl en-US integer grouping, including the small-number fast path', () => {
    const intl = new Intl.NumberFormat('en-US', { maximumFractionDigits: 0 });
    for (const n of [0, 7, 999, 1000, 1234, 123456, 1_000_000, -5, -999, -1000, -123456]) {
      expect(formatCount(n)).toBe(intl.format(n));
    }
    expect(formatCount(null)).toBe('0');
  });
});

describe('dailyTicks', () => {
  it('anchors on the most recent day and caps the tick count', () => {
    const series = fillDailySeries([], '2026-10-28T12:00:00.000Z', 90);
    const ticks = dailyTicks(series, 6);
    expect(ticks.at(-1)?.day).toBe('2026-10-28');
    expect(ticks.length).toBeLessThanOrEqual(7);
    expect(ticks[0]?.day).toBe('2026-07-30');
  });
});
