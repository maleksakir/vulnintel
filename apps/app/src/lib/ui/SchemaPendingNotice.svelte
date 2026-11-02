<!--
  Shown on a feature page when its database tables don't exist yet — i.e. the
  migration that creates them hasn't been applied to this environment. Lets the
  page render its empty state without pretending the emptiness is real, and
  without 500ing (see $lib/server/tableGuard.ts for why this state happens).
-->
<script lang="ts">
  interface Props {
    /** The feature name, e.g. "Watchlists". */
    feature: string;
  }
  const { feature }: Props = $props();
</script>

<div class="notice" role="status">
  <span class="notice__dot" aria-hidden="true"></span>
  <div>
    <strong>{feature} is finishing setup.</strong>
    <p>
      This feature's storage is being provisioned. It'll populate automatically once the
      pending database migration is applied — no action needed. Until then this page shows an
      empty state rather than live data.
    </p>
  </div>
</div>

<style>
  .notice {
    display: flex;
    gap: 0.75rem;
    align-items: flex-start;
    margin: 0 0 1.5rem;
    padding: 0.9rem 1.1rem;
    border: 1px solid var(--amber-border, #7a5c12);
    border-radius: 0.6rem;
    background: var(--amber-bg, #2a210a);
    color: var(--amber-text, #e8c874);
  }
  .notice__dot {
    flex: none;
    width: 0.6rem;
    height: 0.6rem;
    margin-top: 0.35rem;
    border-radius: 50%;
    background: currentColor;
    animation: pulse 1.6s ease-in-out infinite;
  }
  .notice strong {
    display: block;
    margin-bottom: 0.2rem;
  }
  .notice p {
    margin: 0;
    font-size: 0.85rem;
    line-height: 1.45;
    opacity: 0.85;
  }
  @keyframes pulse {
    0%,
    100% {
      opacity: 1;
    }
    50% {
      opacity: 0.35;
    }
  }
</style>
