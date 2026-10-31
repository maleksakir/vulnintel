<script lang="ts">
  import type { WatchlistMatchCounts } from '@threat-lens/contracts';
  import type { PageData } from './$types';

  interface Props {
    data: PageData;
  }
  let { data }: Props = $props();

  function isoToDate(iso: string) {
    return new Date(iso).toLocaleDateString(undefined, { dateStyle: 'medium' });
  }

  // Order the status badges by triage urgency.
  const STATUS_ORDER: Array<keyof WatchlistMatchCounts> = [
    'NEW',
    'TRIAGING',
    'ACKNOWLEDGED',
    'RESOLVED',
    'IGNORED',
  ];

  function totalMatches(counts: WatchlistMatchCounts): number {
    return STATUS_ORDER.reduce((sum, s) => sum + counts[s], 0);
  }
</script>

<svelte:head>
  <title>Watchlists — Threat-Lens CVE Hub</title>
</svelte:head>

<div class="page-watchlists">
  <h1 class="page-title">Watchlists</h1>
  <p class="page-intro">
    Track the CVEs affecting the vendors and products you care about, with a per-CVE triage
    pipeline — instead of re-running the same filtered search every day.
  </p>

  {#if data.watchlists.length === 0}
    <div class="empty-state">
      <p>No watchlists yet.</p>
      <p class="empty-hint">
        Create a watchlist and subscribe it to vendors or products; CVEs that match are collected
        here automatically on each ingest cycle.
      </p>
    </div>
  {:else}
    <ul class="wl-grid" role="list">
      {#each data.watchlists as wl (wl.watchlistId)}
        <li>
          <a class="wl-card" href="/watchlists/{wl.watchlistId}">
            <div class="wl-card__head">
              <h2 class="wl-card__name">{wl.name}</h2>
              <span class="wl-card__count">{totalMatches(wl.matchCounts)} CVEs</span>
            </div>
            {#if wl.description}
              <p class="wl-card__desc">{wl.description}</p>
            {/if}
            <div class="wl-card__meta">
              {wl.subscriptionCount}
              {wl.subscriptionCount === 1 ? 'subscription' : 'subscriptions'}
              · updated {isoToDate(wl.updatedAt)}
            </div>
            <div class="wl-card__badges">
              {#each STATUS_ORDER as status}
                {#if wl.matchCounts[status] > 0}
                  <span class="badge badge--{status.toLowerCase()}">
                    {wl.matchCounts[status]}
                    {status}
                  </span>
                {/if}
              {/each}
            </div>
          </a>
        </li>
      {/each}
    </ul>
  {/if}
</div>

<style>
  .page-title {
    font-size: var(--text-2xl);
    font-weight: var(--weight-semibold);
    margin: 0 0 var(--space-2);
    color: var(--color-text-primary);
  }
  .page-intro {
    font-size: var(--text-sm);
    color: var(--color-text-tertiary);
    margin: 0 0 var(--space-6);
    max-width: 48rem;
  }

  .empty-state {
    padding: var(--space-8);
    border: 1px dashed var(--color-border-default);
    border-radius: var(--radius-lg);
    color: var(--color-text-secondary);
    text-align: center;
  }
  .empty-hint {
    font-size: var(--text-sm);
    color: var(--color-text-tertiary);
    margin-block-start: var(--space-2);
  }

  .wl-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(20rem, 1fr));
    gap: var(--space-4);
    list-style: none;
    margin: 0;
    padding: 0;
  }

  .wl-card {
    display: block;
    padding: var(--space-4);
    background: var(--color-surface-raised);
    border: 1px solid var(--color-border-subtle);
    border-radius: var(--radius-lg);
    text-decoration: none;
    transition: var(--transition-colors);
    height: 100%;
  }
  .wl-card:hover {
    background: var(--color-surface-elevated);
    border-color: var(--color-border-default);
  }

  .wl-card__head {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: var(--space-3);
  }
  .wl-card__name {
    font-size: var(--text-base);
    font-weight: var(--weight-semibold);
    color: var(--color-text-primary);
    margin: 0;
  }
  .wl-card__count {
    font-size: var(--text-xs);
    font-family: var(--font-mono);
    color: var(--color-text-tertiary);
    white-space: nowrap;
  }
  .wl-card__desc {
    font-size: var(--text-sm);
    color: var(--color-text-secondary);
    margin: var(--space-2) 0 0;
  }
  .wl-card__meta {
    font-size: var(--text-xs);
    color: var(--color-text-tertiary);
    margin-block-start: var(--space-3);
  }

  .wl-card__badges {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-1);
    margin-block-start: var(--space-3);
  }
  .badge {
    font-size: var(--text-2xs);
    font-weight: var(--weight-medium);
    padding: 2px var(--space-2);
    border-radius: var(--radius-full);
    white-space: nowrap;
  }
  /* NEW is the attention state; terminal states are muted. */
  .badge--new {
    background: color-mix(in srgb, #ef4444 20%, transparent);
    color: #fca5a5;
  }
  .badge--triaging {
    background: color-mix(in srgb, #f97316 20%, transparent);
    color: #fdba74;
  }
  .badge--acknowledged {
    background: color-mix(in srgb, #eab308 18%, transparent);
    color: #fde047;
  }
  .badge--resolved {
    background: color-mix(in srgb, #22c55e 16%, transparent);
    color: #86efac;
  }
  .badge--ignored {
    background: var(--color-surface-overlay);
    color: var(--color-text-tertiary);
  }
</style>
