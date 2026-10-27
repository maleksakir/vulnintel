<script lang="ts">
  import { tick } from 'svelte';

  interface Props {
    open?: boolean;
    onOpenChange?: (open: boolean) => void;
    title: string;
    description?: string;
    children?: import('svelte').Snippet;
    trigger?: import('svelte').Snippet;
  }

  let {
    open = $bindable(false),
    onOpenChange,
    title,
    description,
    children,
    trigger,
  }: Props = $props();

  let dialogEl = $state<HTMLDialogElement | null>(null);

  $effect(() => {
    if (!dialogEl) return;
    if (open) {
      if (!dialogEl.open) dialogEl.showModal();
    } else {
      if (dialogEl.open) dialogEl.close();
    }
  });

  function close() {
    open = false;
    onOpenChange?.(false);
  }

  function handleBackdropClick(e: MouseEvent) {
    if (e.target === dialogEl) close();
  }
</script>

{#if trigger}
  {@render trigger()}
{/if}

<dialog
  bind:this={dialogEl}
  class="modal-dialog"
  onclose={close}
  oncancel={(e) => { e.preventDefault(); close(); }}
  onclick={handleBackdropClick}
  aria-labelledby="modal-title"
  aria-describedby={description ? 'modal-desc' : undefined}
>
  <div class="modal-panel" role="presentation" onclick={(e) => e.stopPropagation()}>
    <header class="modal-header">
      <h2 id="modal-title" class="modal-title">{title}</h2>
      <button class="modal-close" type="button" aria-label="Close dialog" onclick={close}>
        <svg width="14" height="14" viewBox="0 0 14 14" fill="none" aria-hidden="true">
          <path d="M11 3 3 11M3 3l8 8" stroke="currentColor" stroke-width="1.75" stroke-linecap="round"/>
        </svg>
      </button>
    </header>
    {#if description}
      <p id="modal-desc" class="modal-description">{description}</p>
    {/if}
    {#if children}
      <div class="modal-body">{@render children()}</div>
    {/if}
  </div>
</dialog>

<style>
  .modal-dialog {
    position: fixed;
    inset: 0;
    margin: auto;
    padding: 0;
    border: none;
    background: transparent;
    max-width: min(90vw, 32rem);
    max-height: 85vh;
    width: 100%;
    border-radius: var(--radius-2xl);
    box-shadow: var(--shadow-xl);
    z-index: var(--z-modal);
    overflow: visible;
  }

  .modal-dialog::backdrop {
    background: hsl(222 22% 5% / 0.75);
    backdrop-filter: blur(3px);
    -webkit-backdrop-filter: blur(3px);
  }

  .modal-panel {
    background: var(--color-surface-raised);
    border: 1px solid var(--color-border-default);
    border-radius: var(--radius-2xl);
    padding: var(--space-6);
    overflow-y: auto;
    max-height: 85vh;
    display: flex;
    flex-direction: column;
    gap: 0;
  }

  .modal-header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: var(--space-4);
    margin-block-end: var(--space-4);
  }

  .modal-title {
    font-size: var(--text-lg);
    font-weight: var(--weight-semibold);
    color: var(--color-text-primary);
    margin: 0;
    line-height: var(--leading-snug);
  }

  .modal-close {
    flex-shrink: 0;
    width: 1.75rem;
    height: 1.75rem;
    border-radius: var(--radius-sm);
    color: var(--color-text-tertiary);
    display: flex;
    align-items: center;
    justify-content: center;
    transition: var(--transition-colors);
    margin-top: 0.125rem;
  }

  .modal-close:hover {
    background: var(--color-surface-elevated);
    color: var(--color-text-primary);
  }

  .modal-description {
    font-size: var(--text-sm);
    color: var(--color-text-secondary);
    margin: 0 0 var(--space-4);
    line-height: var(--leading-relaxed);
  }

  .modal-body {
    font-size: var(--text-sm);
    color: var(--color-text-secondary);
    flex: 1;
  }
</style>
