<!--
  The ONE severity badge for the whole app.

  Every page used to hard-code `const SEV_COLOR = { CRITICAL: '#ef4444', … }`
  and an inline `style="color:…"`. That (a) bypassed the design tokens, so the
  Operator Console retheme never reached severity text, and (b) drifted — a
  hex tweaked in one file and not another. This component is the single source
  of truth: it reads the --color-<severity>-* tokens, so re-skinning the theme
  re-skins every severity indicator at once, and the shape/size is identical
  on every page.
-->
<script lang="ts">
  import type { Severity } from '@threat-lens/contracts';

  interface Props {
    severity: Severity | null;
    /** 'badge' = filled pill (default); 'text' = coloured label only (tables). */
    variant?: 'badge' | 'text';
  }
  const { severity, variant = 'badge' }: Props = $props();

  // Lowercase class suffix keys the per-severity token set in app.css.
  const key = $derived((severity ?? 'none').toLowerCase());
</script>

{#if severity === null}
  <span class="sev sev--text sev--empty">—</span>
{:else}
  <span class="sev sev--{variant} sev--{key}" data-severity={severity}>{severity}</span>
{/if}

<style>
  .sev {
    font-family: var(--font-mono);
    font-size: var(--text-2xs);
    font-weight: var(--weight-semibold);
    letter-spacing: var(--tracking-wide);
    white-space: nowrap;
  }

  /* Filled-pill variant — for headers, cards, anywhere it stands alone. */
  .sev--badge {
    display: inline-flex;
    align-items: center;
    padding: 0.1rem 0.5rem;
    border-radius: var(--radius-sm);
    border: 1px solid transparent;
    text-transform: uppercase;
  }
  .sev--badge.sev--critical {
    color: var(--color-critical-text);
    background: var(--color-critical-subtle);
    border-color: var(--color-critical-border);
  }
  .sev--badge.sev--high {
    color: var(--color-high-text);
    background: var(--color-high-subtle);
    border-color: var(--color-high-border);
  }
  .sev--badge.sev--medium {
    color: var(--color-medium-text);
    background: var(--color-medium-subtle);
    border-color: var(--color-medium-border);
  }
  .sev--badge.sev--low {
    color: var(--color-low-text);
    background: var(--color-low-subtle);
    border-color: var(--color-low-border);
  }
  .sev--badge.sev--none {
    color: var(--color-none-text);
    background: var(--color-none-subtle);
    border-color: var(--color-none-border);
  }

  /* Text variant — for dense table cells where a pill would be noisy. */
  .sev--text {
    text-transform: uppercase;
  }
  .sev--text.sev--critical { color: var(--color-critical-text); }
  .sev--text.sev--high { color: var(--color-high-text); }
  .sev--text.sev--medium { color: var(--color-medium-text); }
  .sev--text.sev--low { color: var(--color-low-text); }
  .sev--text.sev--none { color: var(--color-none-text); }
  .sev--empty { color: var(--color-text-tertiary); }
</style>
