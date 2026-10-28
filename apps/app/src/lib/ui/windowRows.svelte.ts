/**
 * Window-scrolled row virtualization for native `<table>` markup.
 *
 * Wraps `@tanstack/svelte-virtual`'s `createWindowVirtualizer` so a table can
 * virtualize its `<tbody>` while the page keeps scrolling normally — no nested
 * scroll box, which matters on touch devices and leaves the sticky site header
 * working as it does on every other page.
 *
 * Rendered rows stay in normal table flow; the off-screen regions are stood in
 * for by one spacer row above and one below. Native table layout doesn't honour
 * absolutely-positioned / transformed rows, so this keeps `<table>` semantics
 * and column widths intact (pair it with `table-layout: fixed` so widths don't
 * shift as different rows scroll into view).
 *
 * Virtualization only engages above `threshold` rows. Below that every row is
 * rendered: a short list gains nothing from virtualizing, and fully-rendered
 * rows keep browser find-in-page and the SSR output complete. Above it, SSR and
 * the hydration pass render the first `threshold` rows (identical on both sides,
 * so hydration matches), then the virtualizer takes over once mounted.
 */
import { createWindowVirtualizer, type SvelteVirtualizer } from '@tanstack/svelte-virtual';
import { untrack } from 'svelte';
import type { Attachment } from 'svelte/attachments';

export interface WindowRowsOptions {
  /** Stable key per row, in render order. A getter, so re-sorts and new data are picked up. */
  keys: () => readonly string[];
  /** Estimated row height in px, used until a row has been measured. */
  estimateSize: number;
  /** Rows kept rendered beyond each edge of the viewport. */
  overscan?: number;
  /** Virtualize only when there are more rows than this. */
  threshold?: number;
}

export interface WindowRows {
  /** True while the virtualizer (rather than "render everything") decides which rows exist. */
  readonly active: boolean;
  /** Row indexes to render, in order. */
  readonly indexes: readonly number[];
  /** Height in px of the spacer row standing in for unrendered rows above. */
  readonly paddingTop: number;
  /** Height in px of the spacer row standing in for unrendered rows below. */
  readonly paddingBottom: number;
  /** Attach to the `<tbody>` — tracks where the list starts on the page. */
  readonly anchor: Attachment<HTMLElement>;
  /** Attach to each rendered row; the element must carry `data-index={index}`. */
  readonly measure: Attachment<HTMLElement>;
}

const EMPTY_VIEW = { indexes: [] as number[], paddingTop: 0, paddingBottom: 0 };

/** Must be called during component initialisation (it registers effects). */
export function createWindowRows(options: WindowRowsOptions): WindowRows {
  const threshold = options.threshold ?? 100;

  let mounted = $state(false);
  let scrollMargin = $state(0);
  // The store re-emits the same Virtualizer instance on every change, so
  // identity can't signal an update — bump a counter instead. Written from a
  // plain counter (never read-then-written) so writing it from inside an
  // effect can't make that effect depend on it.
  let version = $state(0);
  let notifications = 0;
  let instance: SvelteVirtualizer<Window, HTMLElement> | null = null;

  const keys = $derived(options.keys());
  const active = $derived(mounted && keys.length > threshold);

  const store = createWindowVirtualizer<HTMLElement>({
    count: 0,
    enabled: false,
    estimateSize: () => options.estimateSize,
    overscan: options.overscan ?? 8,
    // Apply row measurements on the next frame instead of inside the
    // ResizeObserver callback; otherwise the re-render they trigger lands in
    // the same observer cycle and Chrome logs "ResizeObserver loop completed
    // with undelivered notifications".
    useAnimationFrameWithResizeObserver: true,
  });

  // One subscription for the component's whole lifetime. The adapter
  // re-applies its *initial* options whenever its subscriber count goes
  // 0 → 1, which would silently undo the options pushed below if
  // subscriptions came and went (e.g. with `{#if}` blocks or `get(store)`).
  $effect.pre(() =>
    untrack(() =>
      store.subscribe((v) => {
        instance = v;
        version = ++notifications;
      }),
    ),
  );

  // `.pre` so the virtualizer has the new row count before the template asks
  // it which rows to render — otherwise a shrinking result set could briefly
  // render indexes that no longer exist.
  $effect.pre(() => {
    const rowKeys = keys;
    const enabled = active;
    const margin = scrollMargin;
    untrack(() =>
      instance?.setOptions({
        count: rowKeys.length,
        // A fresh function identity per key list: virtual-core memoizes row
        // offsets on `getItemKey`, so a re-sort has to invalidate them.
        getItemKey: (i) => rowKeys[i] ?? i,
        enabled,
        scrollMargin: margin,
      }),
    );
  });

  // Client-only: flips once hydration is done, letting virtualization engage.
  $effect(() => {
    mounted = true;
  });

  const view = $derived.by(() => {
    void version;
    const count = keys.length;

    if (!active || !instance) {
      const n = mounted ? count : Math.min(count, threshold);
      return { indexes: Array.from({ length: n }, (_, i) => i), paddingTop: 0, paddingBottom: 0 };
    }

    const items = instance.getVirtualItems().filter((item) => item.index < count);
    const first = items[0];
    const last = items[items.length - 1];
    if (!first || !last) return EMPTY_VIEW;

    // Item offsets are page-absolute (they include scrollMargin); spacer
    // heights are relative to the top of the <tbody>.
    const margin = instance.options.scrollMargin;
    return {
      indexes: items.map((item) => item.index),
      paddingTop: Math.max(0, first.start - margin),
      paddingBottom: Math.max(0, instance.getTotalSize() - (last.end - margin)),
    };
  });

  const anchor: Attachment<HTMLElement> = (el) => {
    // The list's document offset moves whenever content above it changes
    // height (filter panel toggled, an alert shown, fonts loading, reflow on
    // resize) — all of which also resize <body>, so watch that.
    const update = () => {
      const top = Math.round(el.getBoundingClientRect().top + window.scrollY);
      if (top !== untrack(() => scrollMargin)) scrollMargin = top;
    };
    update();
    // Deferred a frame (and coalesced) for the same reason as
    // useAnimationFrameWithResizeObserver above: a re-render from inside the
    // observer callback would retrigger it within the same cycle.
    let frame = 0;
    const observer = new ResizeObserver(() => {
      if (!frame) {
        frame = requestAnimationFrame(() => {
          frame = 0;
          update();
        });
      }
    });
    observer.observe(document.body);
    return () => {
      observer.disconnect();
      cancelAnimationFrame(frame);
    };
  };

  const measure: Attachment<HTMLElement> = (el) => {
    // Reading `active` re-runs this for already-mounted rows when
    // virtualization switches on. Detached rows are unobserved by
    // virtual-core's own ResizeObserver, so no teardown is needed.
    if (!active) return;
    untrack(() => instance?.measureElement(el));
  };

  return {
    get active() {
      return active;
    },
    get indexes() {
      return view.indexes;
    },
    get paddingTop() {
      return view.paddingTop;
    },
    get paddingBottom() {
      return view.paddingBottom;
    },
    anchor,
    measure,
  };
}
