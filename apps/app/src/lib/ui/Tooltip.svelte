<script lang="ts">
  interface Props {
    content: string | import('svelte').Snippet;
    /** Delay before the tooltip opens, ms. Default 400. */
    openDelay?: number;
    /** Delay before the tooltip closes, ms. Default 0. */
    closeDelay?: number;
    children: import('svelte').Snippet;
    disabled?: boolean;
    /** Preferred placement. Default 'top'. */
    placement?: 'top' | 'bottom' | 'left' | 'right';
  }

  let {
    content,
    openDelay = 400,
    closeDelay = 0,
    children,
    disabled = false,
    placement = 'top',
  }: Props = $props();

  let visible = $state(false);
  let openTimer: ReturnType<typeof setTimeout> | null = null;
  let closeTimer: ReturnType<typeof setTimeout> | null = null;

  function scheduleOpen() {
    if (disabled) return;
    if (closeTimer) { clearTimeout(closeTimer); closeTimer = null; }
    openTimer = setTimeout(() => { visible = true; }, openDelay);
  }

  function scheduleClose() {
    if (openTimer) { clearTimeout(openTimer); openTimer = null; }
    closeTimer = setTimeout(() => { visible = false; }, closeDelay);
  }
</script>

<span
  class="tooltip-host"
  role="presentation"
  onmouseenter={scheduleOpen}
  onmouseleave={scheduleClose}
  onfocusin={scheduleOpen}
  onfocusout={scheduleClose}
>
  {@render children()}
  {#if visible}
    <span
      class="tooltip-bubble"
      data-placement={placement}
      role="tooltip"
    >
      {#if typeof content === 'string'}
        {content}
      {:else}
        {@render content()}
      {/if}
    </span>
  {/if}
</span>

<style>
  .tooltip-host {
    position: relative;
    display: inline-flex;
    align-items: center;
  }

  .tooltip-bubble {
    position: absolute;
    z-index: var(--z-tooltip);
    padding: 0.3125rem 0.625rem;
    background: var(--color-surface-invert);
    color: var(--color-text-invert);
    font-size: var(--text-xs);
    font-weight: var(--weight-medium);
    line-height: var(--leading-snug);
    border-radius: var(--radius-sm);
    white-space: nowrap;
    max-width: 16rem;
    white-space: normal;
    pointer-events: none;
    box-shadow: var(--shadow-md);
    animation: tooltip-in 120ms var(--ease-out) both;
  }

  @keyframes tooltip-in {
    from { opacity: 0; transform: scale(0.94); }
    to   { opacity: 1; transform: scale(1); }
  }

  /* Placement variants */
  .tooltip-bubble[data-placement='top'] {
    bottom: calc(100% + 0.375rem);
    left: 50%;
    transform: translateX(-50%);
  }

  .tooltip-bubble[data-placement='bottom'] {
    top: calc(100% + 0.375rem);
    left: 50%;
    transform: translateX(-50%);
  }

  .tooltip-bubble[data-placement='left'] {
    right: calc(100% + 0.375rem);
    top: 50%;
    transform: translateY(-50%);
  }

  .tooltip-bubble[data-placement='right'] {
    left: calc(100% + 0.375rem);
    top: 50%;
    transform: translateY(-50%);
  }

  /* Arrow */
  .tooltip-bubble[data-placement='top']::after {
    content: '';
    position: absolute;
    top: 100%;
    left: 50%;
    transform: translateX(-50%);
    border: 4px solid transparent;
    border-top-color: var(--color-surface-invert);
  }

  .tooltip-bubble[data-placement='bottom']::after {
    content: '';
    position: absolute;
    bottom: 100%;
    left: 50%;
    transform: translateX(-50%);
    border: 4px solid transparent;
    border-bottom-color: var(--color-surface-invert);
  }
</style>
