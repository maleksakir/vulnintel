<script lang="ts">
  import { page } from '$app/stores';
</script>

<svelte:head>
  <title>Error — Threat-Lens CVE Hub</title>
</svelte:head>

<div class="error-page" role="main">
  <div class="error-card">
    <p class="error-status" aria-hidden="true">{$page.status}</p>

    {#if $page.error?.code === 'CVE_NOT_FOUND'}
      <h1 class="error-title">CVE not found</h1>
      <p class="error-body">
        This CVE does not exist in our database or is outside the 24-month active window.
      </p>
      <div class="error-actions">
        <a href="/search" class="btn-primary">Search CVEs</a>
      </div>

    {:else if $page.error?.code === 'FORBIDDEN_NETWORK'}
      <h1 class="error-title">Access denied</h1>
      <p class="error-body">
        This network is not on the access list. Contact your security team if you believe this is an error.
      </p>

    {:else if $page.error?.code === 'RATE_LIMITED'}
      <h1 class="error-title">Rate limit reached</h1>
      <p class="error-body">
        Too many requests. Please wait and try again.
      </p>
      <div class="error-actions">
        <button type="button" class="btn-secondary" onclick={() => history.back()}>
          Go back
        </button>
      </div>

    {:else if $page.error?.code === 'VALIDATION_ERROR'}
      <h1 class="error-title">Invalid request</h1>
      <p class="error-body">{$page.error.message ?? 'The request contained invalid input.'}</p>
      <div class="error-actions">
        <button type="button" class="btn-secondary" onclick={() => history.back()}>
          Go back
        </button>
      </div>

    {:else if $page.status >= 500}
      <h1 class="error-title">Something went wrong</h1>
      <p class="error-body">
        A backend service is unavailable. Check
        <a href="/admin/health">/admin/health</a>
        for system status.
      </p>
      <div class="error-actions">
        <button type="button" class="btn-primary" onclick={() => location.reload()}>
          Retry
        </button>
      </div>

    {:else}
      <h1 class="error-title">{$page.error?.message ?? 'An error occurred'}</h1>
      <p class="error-body">
        {$page.status === 404 ? 'The page you requested could not be found.' : 'Please try again or return to the dashboard.'}
      </p>
      <div class="error-actions">
        <a href="/" class="btn-primary">Return to Dashboard</a>
      </div>
    {/if}

    {#if $page.error?.requestId}
      <p class="error-request-id">Request ID: <code>{$page.error.requestId}</code></p>
    {/if}
  </div>
</div>

<style>
  .error-page {
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: calc(100dvh - var(--layout-nav-height));
    padding: var(--layout-page-gutter);
  }

  .error-card {
    max-width: 36rem;
    width: 100%;
    text-align: center;
  }

  .error-status {
    font-size: var(--text-5xl);
    font-weight: var(--weight-bold);
    color: var(--color-border-subtle);
    line-height: var(--leading-none);
    margin-block-end: var(--space-4);
  }

  .error-title {
    font-size: var(--text-2xl);
    font-weight: var(--weight-semibold);
    color: var(--color-text-primary);
    margin-block-end: var(--space-3);
  }

  .error-body {
    font-size: var(--text-base);
    color: var(--color-text-secondary);
    line-height: var(--leading-relaxed);
    margin-block-end: var(--space-6);
  }

  .error-actions {
    display: flex;
    gap: var(--space-3);
    justify-content: center;
    flex-wrap: wrap;
    margin-block-end: var(--space-6);
  }

  .btn-primary {
    display: inline-flex;
    align-items: center;
    padding: var(--space-2) var(--space-5);
    background: var(--color-brand-default);
    color: var(--color-text-on-brand);
    font-size: var(--text-sm);
    font-weight: var(--weight-medium);
    border-radius: var(--radius-sm);
    text-decoration: none;
    transition: var(--transition-colors);
  }

  .btn-primary:hover {
    background: var(--color-brand-hover);
  }

  .btn-secondary {
    display: inline-flex;
    align-items: center;
    padding: var(--space-2) var(--space-5);
    background: var(--color-surface-elevated);
    color: var(--color-text-primary);
    font-size: var(--text-sm);
    font-weight: var(--weight-medium);
    border-radius: var(--radius-sm);
    border: 1px solid var(--color-border-default);
    transition: var(--transition-colors);
  }

  .btn-secondary:hover {
    background: var(--color-surface-raised);
  }

  .error-request-id {
    font-size: var(--text-xs);
    color: var(--color-text-muted);
  }

  .error-request-id code {
    font-family: var(--font-mono);
    color: var(--color-text-secondary);
  }
</style>
