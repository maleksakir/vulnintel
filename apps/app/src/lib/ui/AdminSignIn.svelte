<!--
  Sign-in prompt for operator-only pages (assets, watchlists, remediation).
  Shown instead of the page body when `data.authed` is false.

  Submitting navigates to `?token=<secret>`; the server validates it, sets the
  admin_session cookie and immediately redirects back without the token (see
  $lib/server/adminSession.ts). We also stash the same value in sessionStorage
  so the mutation forms on the page — which authorize with a Bearer header,
  not the cookie — don't make the operator paste it a second time.
-->
<script lang="ts">
  import { setAdminToken } from '$lib/client/adminToken';

  interface Props {
    /** What's behind the gate, e.g. "the asset inventory". */
    what: string;
  }

  const { what }: Props = $props();

  let token = $state('');

  function signIn(event: SubmitEvent): void {
    event.preventDefault();
    const value = token.trim();
    if (!value) return;
    setAdminToken(value);
    const url = new URL(window.location.href);
    url.searchParams.set('token', value);
    window.location.href = url.toString();
  }
</script>

<section class="gate" aria-labelledby="gate-heading">
  <h1 id="gate-heading" class="gate__title">Operator sign-in required</h1>
  <p class="gate__body">
    {what} describes our own systems, so it isn't public. Enter the admin token to continue.
  </p>
  <form class="gate__form" onsubmit={signIn}>
    <label class="gate__field">
      <span class="gate__label">Admin token</span>
      <!-- svelte-ignore a11y_autofocus -->
      <input
        class="gate__input"
        type="password"
        bind:value={token}
        placeholder="ADMIN_BEARER"
        autocomplete="off"
        autofocus
      />
    </label>
    <button class="gate__submit" type="submit" disabled={!token.trim()}>Sign in</button>
  </form>
</section>

<style>
  .gate {
    max-width: 32rem;
    margin: var(--space-16) auto;
    padding: var(--space-7);
    border: 1px solid var(--color-border-default);
    border-radius: var(--radius-lg);
    background:
      radial-gradient(120% 140% at 0% 0%, var(--color-brand-subtle) 0%, transparent 45%),
      var(--color-surface-raised);
  }
  .gate__title {
    margin: 0 0 var(--space-2);
    font-size: var(--text-xl);
    font-weight: var(--weight-semibold);
    color: var(--color-text-primary);
    letter-spacing: var(--tracking-tight);
  }
  .gate__body {
    margin: 0 0 var(--space-5);
    color: var(--color-text-secondary);
    font-size: var(--text-sm);
    line-height: var(--leading-normal);
  }
  .gate__form {
    display: flex;
    gap: var(--space-3);
    align-items: flex-end;
    flex-wrap: wrap;
  }
  .gate__field {
    display: flex;
    flex-direction: column;
    gap: var(--space-1_5);
    flex: 1 1 16rem;
  }
  .gate__label {
    font-family: var(--font-mono);
    font-size: var(--text-2xs);
    text-transform: uppercase;
    letter-spacing: var(--tracking-wide);
    color: var(--color-text-tertiary);
  }
  .gate__input {
    padding: var(--space-2) var(--space-3);
    border: 1px solid var(--color-border-default);
    border-radius: var(--radius-md);
    background: var(--color-surface-sunken);
    color: var(--color-text-primary);
    font: inherit;
    font-family: var(--font-mono);
    outline: none;
    transition: var(--transition-colors), box-shadow var(--duration-fast) var(--ease-out);
  }
  .gate__input:focus {
    border-color: var(--color-brand-default);
    box-shadow: var(--glow-accent);
  }
  .gate__submit {
    padding: var(--space-2) var(--space-5);
    border: 1px solid var(--color-brand-border);
    border-radius: var(--radius-md);
    background: var(--color-brand-subtle);
    color: var(--color-brand-text);
    font: inherit;
    font-family: var(--font-mono);
    font-weight: var(--weight-medium);
    cursor: pointer;
    transition: var(--transition-colors), box-shadow var(--duration-fast) var(--ease-out);
  }
  .gate__submit:hover:not(:disabled) {
    border-color: var(--color-brand-default);
    box-shadow: var(--glow-accent);
  }
  .gate__submit:disabled {
    opacity: 0.45;
    cursor: not-allowed;
  }
</style>
