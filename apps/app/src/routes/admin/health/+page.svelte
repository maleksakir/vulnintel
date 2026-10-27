<script lang="ts">
  import type { PageData } from './$types';
  import type { IngestSource, IngestStaleness } from '@threat-lens/contracts';

  interface Props { data: PageData }
  let { data }: Props = $props();

  const SOURCES: IngestSource[] = ['NVD', 'MITRE', 'KEV', 'EPSS', 'AGING'];

  const STALENESS_COLOR: Record<IngestStaleness, string> = {
    green: '#22c55e',
    amber: '#eab308',
    red: '#ef4444',
  };

  function isoToDateTime(iso: string | null) {
    if (!iso) return '—';
    return new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
  }

  function queueDepthLabel(n: number) {
    return n === -1 ? 'N/A' : n.toLocaleString();
  }
</script>

<svelte:head>
  <title>Admin Health — Threat-Lens CVE Hub</title>
</svelte:head>

<div class="page-health">
  {#if !data.authed || !data.health}
    <!-- Token entry gate -->
    <header class="health-header">
      <h1 class="page-title">Admin Health</h1>
    </header>
    <div class="auth-gate">
      <p class="auth-note">This page requires an admin bearer token.</p>
      <form class="token-form" method="GET">
        <label class="token-label" for="token-input">Bearer Token</label>
        <div class="token-row">
          <input
            id="token-input"
            class="token-input"
            type="password"
            name="token"
            placeholder="Enter admin token…"
            autocomplete="off"
            required
          />
          <button class="token-btn" type="submit">View Health</button>
        </div>
      </form>
    </div>

  {:else}
    <!-- Health dashboard -->
    {@const health = data.health}

    <header class="health-header">
      <h1 class="page-title">Admin Health</h1>
      <p class="generated-at">Generated {isoToDateTime(health.generatedAt)}</p>
    </header>

    <!-- Database Counts -->
    <section class="health-section" aria-labelledby="counts-heading">
      <h2 id="counts-heading" class="section-title">Database Counts</h2>
      <dl class="counts-grid">
        <div class="count-card">
          <dt class="count-label">CVEs</dt>
          <dd class="count-value">{health.counts.cve.toLocaleString()}</dd>
        </div>
        <div class="count-card">
          <dt class="count-label">CPEs</dt>
          <dd class="count-value">{health.counts.cpe.toLocaleString()}</dd>
        </div>
        <div class="count-card">
          <dt class="count-label">CVE States</dt>
          <dd class="count-value">{health.counts.cveState.toLocaleString()}</dd>
        </div>
        <div class="count-card">
          <dt class="count-label">Quarantine</dt>
          <dd class="count-value">{health.counts.cveQuarantine.toLocaleString()}</dd>
        </div>
        <div class="count-card">
          <dt class="count-label">Audit Log</dt>
          <dd class="count-value">{health.counts.auditLog.toLocaleString()}</dd>
        </div>
      </dl>
    </section>

    <!-- Queue Depths -->
    <section class="health-section" aria-labelledby="queues-heading">
      <h2 id="queues-heading" class="section-title">Queue Depths</h2>
      <dl class="counts-grid">
        <div class="count-card">
          <dt class="count-label">Retry Queue</dt>
          <dd class="count-value" class:count-warn={health.queues.retryDepth > 0}>
            {queueDepthLabel(health.queues.retryDepth)}
          </dd>
        </div>
        <div class="count-card">
          <dt class="count-label">Dead Letter Queue</dt>
          <dd class="count-value" class:count-error={health.queues.dlqDepth > 0}>
            {queueDepthLabel(health.queues.dlqDepth)}
          </dd>
        </div>
      </dl>
    </section>

    <!-- Ingest Sources -->
    <section class="health-section" aria-labelledby="ingest-heading">
      <h2 id="ingest-heading" class="section-title">Ingest Sources</h2>
      <div class="table-wrap">
        <table class="data-table">
          <thead>
            <tr>
              <th>Source</th>
              <th>Status</th>
              <th>Staleness</th>
              <th>Last Started</th>
              <th>Last Finished</th>
              <th>Processed</th>
              <th>Failed</th>
            </tr>
          </thead>
          <tbody>
            {#each SOURCES as src}
              {@const status = health.ingest[src]}
              <tr>
                <td class="source-name">{src}</td>
                <td>
                  {#if status.lastStatus}
                    <span
                      class="status-badge"
                      class:status-ok={status.lastStatus === 'OK'}
                      class:status-partial={status.lastStatus === 'PARTIAL'}
                      class:status-failed={status.lastStatus === 'FAILED'}
                    >{status.lastStatus}</span>
                  {:else}
                    <span class="status-never">Never</span>
                  {/if}
                </td>
                <td>
                  <span
                    class="staleness-dot"
                    style="background:{STALENESS_COLOR[status.staleness]}"
                    title={status.staleness}
                  ></span>
                  {status.staleness}
                </td>
                <td class="mono-cell">{isoToDateTime(status.lastStartedAt)}</td>
                <td class="mono-cell">{isoToDateTime(status.lastFinishedAt)}</td>
                <td>{status.recordsProcessed?.toLocaleString() ?? '—'}</td>
                <td class:cell-warn={status.recordsFailed !== null && status.recordsFailed > 0}>
                  {status.recordsFailed?.toLocaleString() ?? '—'}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </section>

    <!-- Rate Limits -->
    <section class="health-section" aria-labelledby="ratelimit-heading">
      <h2 id="ratelimit-heading" class="section-title">Rate Limits (last 24h)</h2>
      <p class="ratelimit-summary">
        <strong>{health.rateLimits.lastHourBlocks.toLocaleString()}</strong> blocks in the last hour
      </p>
      {#if health.rateLimits.topIps.length > 0}
        <div class="table-wrap">
          <table class="data-table">
            <thead>
              <tr>
                <th>IP Address</th>
                <th>Blocks</th>
              </tr>
            </thead>
            <tbody>
              {#each health.rateLimits.topIps as item}
                <tr>
                  <td class="mono-cell">{item.ip}</td>
                  <td>{item.blocks.toLocaleString()}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {:else}
        <p class="empty-state">No blocked IPs in the last 24 hours.</p>
      {/if}
    </section>
  {/if}
</div>

<style>
  .page-title { font-size: var(--text-2xl); font-weight: var(--weight-semibold); margin: 0; color: var(--color-text-primary); }
  .health-header { display: flex; align-items: baseline; gap: var(--space-4); margin-block-end: var(--space-8); flex-wrap: wrap; }
  .generated-at { font-size: var(--text-sm); color: var(--color-text-tertiary); margin: 0; }

  .auth-gate { max-width: 28rem; }
  .auth-note { font-size: var(--text-sm); color: var(--color-text-secondary); margin-block-end: var(--space-4); }
  .token-label { display: block; font-size: var(--text-xs); color: var(--color-text-tertiary); text-transform: uppercase; letter-spacing: var(--tracking-wide); margin-block-end: var(--space-2); font-weight: var(--weight-medium); }
  .token-form { display: flex; flex-direction: column; }
  .token-row { display: flex; gap: var(--space-2); }
  .token-input { flex: 1; padding: var(--space-2) var(--space-3); background: var(--color-surface-raised); border: 1px solid var(--color-border-default); border-radius: var(--radius-md); font-size: var(--text-sm); color: var(--color-text-primary); font-family: var(--font-mono); }
  .token-input:focus { outline: none; border-color: var(--color-brand-500); }
  .token-btn { padding: var(--space-2) var(--space-4); background: var(--color-brand-500); color: #fff; border: none; border-radius: var(--radius-md); font-size: var(--text-sm); cursor: pointer; white-space: nowrap; }
  .token-btn:hover { background: var(--color-brand-600, #2563eb); }

  .health-section { margin-block-end: var(--space-8); }
  .section-title { font-size: var(--text-xs); font-weight: var(--weight-semibold); text-transform: uppercase; letter-spacing: var(--tracking-wide); color: var(--color-text-tertiary); margin: 0 0 var(--space-4); }

  .counts-grid { display: flex; gap: var(--space-4); flex-wrap: wrap; margin: 0; }
  .count-card { background: var(--color-surface-raised); border: 1px solid var(--color-border-subtle); border-radius: var(--radius-md); padding: var(--space-4) var(--space-5); min-width: 9rem; }
  .count-label { font-size: var(--text-xs); color: var(--color-text-tertiary); text-transform: uppercase; letter-spacing: var(--tracking-wide); }
  .count-value { font-size: var(--text-2xl); font-weight: var(--weight-bold); color: var(--color-text-primary); margin: var(--space-1) 0 0; }
  .count-warn { color: #eab308; }
  .count-error { color: #ef4444; }

  .table-wrap { overflow-x: auto; }
  .data-table { width: 100%; border-collapse: collapse; font-size: var(--text-sm); }
  .data-table th { text-align: left; padding: var(--space-2) var(--space-3); font-size: var(--text-xs); font-weight: var(--weight-medium); color: var(--color-text-tertiary); text-transform: uppercase; letter-spacing: var(--tracking-wide); border-bottom: 1px solid var(--color-border-subtle); white-space: nowrap; }
  .data-table td { padding: var(--space-2) var(--space-3); color: var(--color-text-secondary); border-bottom: 1px solid var(--color-border-subtle); vertical-align: middle; }

  .source-name { font-family: var(--font-mono); font-weight: var(--weight-medium); color: var(--color-text-primary); font-size: var(--text-xs); }
  .mono-cell { font-family: var(--font-mono); font-size: var(--text-xs); }
  .cell-warn { color: #ef4444; }

  .status-badge { display: inline-block; padding: 0.125rem 0.5rem; border-radius: var(--radius-sm); font-size: var(--text-xs); font-weight: var(--weight-medium); text-transform: uppercase; }
  .status-ok { background: #14532d40; color: #86efac; }
  .status-partial { background: #78350f40; color: #fde68a; }
  .status-failed { background: #7f1d1d40; color: #fca5a5; }
  .status-never { color: var(--color-text-tertiary); font-size: var(--text-xs); }

  .staleness-dot { display: inline-block; width: 0.5rem; height: 0.5rem; border-radius: 50%; margin-right: var(--space-1); vertical-align: middle; }

  .ratelimit-summary { font-size: var(--text-sm); color: var(--color-text-secondary); margin-block-end: var(--space-4); }
  .empty-state { color: var(--color-text-secondary); font-size: var(--text-sm); }
</style>
