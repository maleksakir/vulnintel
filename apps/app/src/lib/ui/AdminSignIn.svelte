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
    margin: 4rem auto;
    padding: 1.75rem;
    border: 1px solid var(--border, #2a2f3a);
    border-radius: 0.75rem;
    background: var(--surface, #151821);
  }
  .gate__title {
    margin: 0 0 0.5rem;
    font-size: 1.25rem;
  }
  .gate__body {
    margin: 0 0 1.25rem;
    color: var(--text-muted, #9aa3b2);
    font-size: 0.9rem;
    line-height: 1.5;
  }
  .gate__form {
    display: flex;
    gap: 0.75rem;
    align-items: flex-end;
    flex-wrap: wrap;
  }
  .gate__field {
    display: flex;
    flex-direction: column;
    gap: 0.35rem;
    flex: 1 1 16rem;
  }
  .gate__label {
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--text-muted, #9aa3b2);
  }
  .gate__input {
    padding: 0.5rem 0.65rem;
    border: 1px solid var(--border, #2a2f3a);
    border-radius: 0.4rem;
    background: var(--bg, #0e1016);
    color: inherit;
    font: inherit;
  }
  .gate__submit {
    padding: 0.55rem 1.1rem;
    border: 0;
    border-radius: 0.4rem;
    background: var(--accent, #3b82f6);
    color: #fff;
    font: inherit;
    cursor: pointer;
  }
  .gate__submit:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
</style>
