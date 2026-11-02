<!--
  The command-center page header, shared by every route so titles, eyebrows
  and the optional telemetry-readout strip are identical app-wide.

  Pages previously each rolled their own `.page-title` with slightly different
  sizes/margins/colors. This fixes the geometry in one place:
    <PageHeader eyebrow="AFFECTED PRODUCTS" title="Exposure Surface">
      {#snippet readouts()} … optional readout chips … {/snippet}
    </PageHeader>
-->
<script lang="ts">
  import type { Snippet } from 'svelte';

  interface Props {
    /** Mono uppercase kicker above the title (the "channel" label). */
    eyebrow: string;
    title: string;
    /** Optional sentence under the title. */
    subtitle?: string;
    /** Pulse the live dot in the eyebrow (dashboards / live feeds). */
    live?: boolean;
    /** Optional right-aligned readout chips. */
    readouts?: Snippet;
  }
  const { eyebrow, title, subtitle, live = false, readouts }: Props = $props();
</script>

<header class="ph hud-grid boot-in">
  <div class="ph__row">
    <div class="ph__main">
      <p class="ph__eyebrow">
        {#if live}<span class="live-dot" aria-hidden="true"></span>{/if}
        {eyebrow}
      </p>
      <h1 class="ph__title">{title}</h1>
      {#if subtitle}<p class="ph__subtitle">{subtitle}</p>{/if}
    </div>
    {#if readouts}
      <div class="ph__readouts">{@render readouts()}</div>
    {/if}
  </div>
</header>

<style>
  .ph {
    margin-block-end: var(--space-7);
    padding: var(--space-5) var(--space-6);
    border: 1px solid var(--color-border-default);
    border-radius: var(--radius-lg);
    background:
      radial-gradient(120% 160% at 0% 0%, var(--color-brand-subtle) 0%, transparent 42%),
      var(--color-surface-raised);
    overflow: hidden;
  }
  .ph__row {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: var(--space-4);
    flex-wrap: wrap;
  }
  .ph__eyebrow {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    margin: 0 0 var(--space-1_5);
    font-family: var(--font-mono);
    font-size: var(--text-xs);
    letter-spacing: var(--tracking-caps);
    text-transform: uppercase;
    color: var(--color-brand-text);
  }
  .ph__title {
    margin: 0;
    font-size: var(--text-3xl);
    font-weight: var(--weight-bold);
    letter-spacing: var(--tracking-tight);
    color: var(--color-text-primary);
  }
  .ph__subtitle {
    margin: var(--space-2) 0 0;
    font-size: var(--text-sm);
    color: var(--color-text-tertiary);
  }
  .ph__readouts {
    display: flex;
    gap: var(--space-5);
    padding: var(--space-3) var(--space-4);
    border: 1px solid var(--color-border-default);
    border-radius: var(--radius-md);
    background: var(--color-surface-sunken);
  }
  @media (max-width: 768px) {
    .ph__readouts { width: 100%; }
    .ph__title { font-size: var(--text-2xl); }
  }
</style>
