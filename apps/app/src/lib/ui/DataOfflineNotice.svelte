<!--
  Shown when a read-through page could not reach D1 on a cache miss — most
  often the free-tier daily read cap (Cloudflare D1 error 7500), occasionally
  a transient outage. Lets a data page render calmly instead of 500ing, and
  tells the operator this is a capacity ceiling, not a bug. Clears itself the
  moment the quota window rolls over or the cache warms again.
-->
<script lang="ts">
  interface Props {
    /** What couldn't load, e.g. "Dashboard telemetry". */
    what: string;
  }
  const { what }: Props = $props();
</script>

<div class="offline" role="status">
  <span class="offline__dot" aria-hidden="true"></span>
  <div>
    <strong>{what} is temporarily offline.</strong>
    <p>
      The live datastore is at its daily capacity limit and will resume automatically at the next
      reset (00:00 UTC). Cached views continue to serve in the meantime — no action needed.
    </p>
  </div>
</div>

<style>
  .offline {
    display: flex;
    gap: var(--space-3);
    align-items: flex-start;
    margin-block-end: var(--space-6);
    padding: var(--space-4) var(--space-5);
    border: 1px solid var(--color-medium-border);
    border-radius: var(--radius-lg);
    background: var(--color-medium-subtle);
    color: var(--color-medium-text);
  }
  .offline__dot {
    flex: none;
    width: 0.55rem;
    height: 0.55rem;
    margin-top: 0.35rem;
    border-radius: var(--radius-full);
    background: currentColor;
    box-shadow: 0 0 10px -1px currentColor;
    animation: live-pulse 2s var(--ease-in-out) infinite;
  }
  .offline strong {
    display: block;
    margin-bottom: 0.2rem;
    font-size: var(--text-sm);
  }
  .offline p {
    margin: 0;
    font-size: var(--text-xs);
    line-height: var(--leading-snug);
    opacity: 0.85;
  }
  @media (prefers-reduced-motion: reduce) {
    .offline__dot {
      animation: none;
    }
  }
</style>
