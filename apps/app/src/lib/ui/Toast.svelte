<script lang="ts">
  export type ToastVariant = 'info' | 'success' | 'warning' | 'error';

  interface ToastItem {
    id: string;
    variant: ToastVariant;
    title: string;
    description?: string;
    /** Auto-dismiss after this many ms; 0 = sticky. Default 4000. */
    duration?: number;
  }

  interface Props {
    toasts?: ToastItem[];
    onClose?: (id: string) => void;
    position?: 'bottom-right' | 'bottom-left' | 'top-right' | 'top-left';
  }

  let {
    toasts = [],
    onClose,
    position = 'bottom-right',
  }: Props = $props();

  // Auto-dismiss: track a timer per toast id
  const timers = new Map<string, ReturnType<typeof setTimeout>>();

  $effect(() => {
    const currentIds = new Set(toasts.map(t => t.id));

    // Remove timers for toasts that are gone
    for (const [id, timer] of timers) {
      if (!currentIds.has(id)) {
        clearTimeout(timer);
        timers.delete(id);
      }
    }

    // Schedule dismissal for new toasts
    for (const toast of toasts) {
      if (!timers.has(toast.id)) {
        const delay = toast.duration ?? 4000;
        if (delay > 0) {
          timers.set(
            toast.id,
            setTimeout(() => {
              onClose?.(toast.id);
              timers.delete(toast.id);
            }, delay),
          );
        }
      }
    }

    return () => {
      for (const timer of timers.values()) clearTimeout(timer);
      timers.clear();
    };
  });

  const VARIANT_ICON: Record<ToastVariant, string> = {
    info:    'ℹ',
    success: '✓',
    warning: '⚠',
    error:   '✕',
  };
</script>

<div
  class="toast-region"
  data-position={position}
  aria-live="polite"
  aria-atomic="false"
  role="region"
  aria-label="Notifications"
>
  {#each toasts as toast (toast.id)}
    <div class="toast" data-variant={toast.variant} role="alert">
      <span class="toast-icon" aria-hidden="true">{VARIANT_ICON[toast.variant]}</span>
      <div class="toast-content">
        <strong class="toast-title">{toast.title}</strong>
        {#if toast.description}
          <p class="toast-desc">{toast.description}</p>
        {/if}
      </div>
      <button
        class="toast-dismiss"
        type="button"
        aria-label="Dismiss notification"
        onclick={() => onClose?.(toast.id)}
      >
        <svg width="12" height="12" viewBox="0 0 12 12" fill="none" aria-hidden="true">
          <path d="M9 3 3 9M3 3l6 6" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
        </svg>
      </button>
    </div>
  {/each}
</div>

<style>
  .toast-region {
    position: fixed;
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
    z-index: var(--z-toast);
    max-width: 24rem;
    width: calc(100% - var(--space-12));
    pointer-events: none;
  }

  .toast-region[data-position='bottom-right'] { bottom: var(--space-6); right: var(--space-6); align-items: flex-end; }
  .toast-region[data-position='bottom-left']  { bottom: var(--space-6); left: var(--space-6);  align-items: flex-start; }
  .toast-region[data-position='top-right']    { top: var(--space-6);    right: var(--space-6); align-items: flex-end; }
  .toast-region[data-position='top-left']     { top: var(--space-6);    left: var(--space-6);  align-items: flex-start; }

  .toast {
    background: var(--color-surface-raised);
    border: 1px solid var(--color-border-default);
    border-radius: var(--radius-md);
    padding: var(--space-3) var(--space-4);
    box-shadow: var(--shadow-lg);
    display: flex;
    align-items: flex-start;
    gap: var(--space-3);
    min-width: 16rem;
    pointer-events: all;
    animation: toast-in 180ms var(--ease-spring) both;
  }

  @keyframes toast-in {
    from { opacity: 0; transform: translateY(0.5rem) scale(0.96); }
    to   { opacity: 1; transform: translateY(0) scale(1); }
  }

  .toast[data-variant='info']    { border-left: 3px solid var(--color-brand-500); }
  .toast[data-variant='success'] { border-left: 3px solid var(--color-status-green); }
  .toast[data-variant='warning'] { border-left: 3px solid var(--color-status-amber); }
  .toast[data-variant='error']   { border-left: 3px solid var(--color-status-red); }

  .toast-icon {
    font-size: var(--text-sm);
    flex-shrink: 0;
    margin-top: 0.0625rem;
  }

  .toast[data-variant='info']    .toast-icon { color: var(--color-brand-500); }
  .toast[data-variant='success'] .toast-icon { color: var(--color-status-green); }
  .toast[data-variant='warning'] .toast-icon { color: var(--color-status-amber); }
  .toast[data-variant='error']   .toast-icon { color: var(--color-status-red); }

  .toast-content { flex: 1; min-width: 0; }

  .toast-title {
    font-size: var(--text-sm);
    font-weight: var(--weight-semibold);
    color: var(--color-text-primary);
    display: block;
  }

  .toast-desc {
    font-size: var(--text-xs);
    color: var(--color-text-secondary);
    margin: var(--space-0_5) 0 0;
    line-height: var(--leading-snug);
  }

  .toast-dismiss {
    flex-shrink: 0;
    width: 1.25rem;
    height: 1.25rem;
    border-radius: var(--radius-sm);
    color: var(--color-text-tertiary);
    display: flex;
    align-items: center;
    justify-content: center;
    transition: var(--transition-colors);
    margin-top: 0.0625rem;
  }

  .toast-dismiss:hover {
    background: var(--color-surface-elevated);
    color: var(--color-text-primary);
  }
</style>
