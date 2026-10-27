<script lang="ts">
  interface Option {
    value: string;
    label: string;
    disabled?: boolean;
  }

  interface Props {
    value?: string;
    onValueChange?: (value: string) => void;
    options: Option[];
    placeholder?: string;
    label?: string;
    disabled?: boolean;
    name?: string;
  }

  let {
    value = $bindable(''),
    onValueChange,
    options,
    placeholder = 'Select…',
    label,
    disabled = false,
    name,
  }: Props = $props();
</script>

<div class="select-wrap">
  {#if label}
    <label class="select-label" for="select-ctrl">{label}</label>
  {/if}
  <div class="select-field">
    <select
      id="select-ctrl"
      class="select-native"
      {name}
      {disabled}
      bind:value
      onchange={(e) => onValueChange?.((e.currentTarget as HTMLSelectElement).value)}
    >
      {#if !value}
        <option value="" disabled selected>{placeholder}</option>
      {/if}
      {#each options as option (option.value)}
        <option value={option.value} disabled={option.disabled}>{option.label}</option>
      {/each}
    </select>
    <span class="select-arrow" aria-hidden="true">
      <svg width="10" height="6" viewBox="0 0 10 6" fill="none">
        <path d="M1 1l4 4 4-4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
    </span>
  </div>
</div>

<style>
  .select-wrap { display: flex; flex-direction: column; gap: var(--space-1); }

  .select-label { font-size: var(--text-xs); font-weight: var(--weight-medium); color: var(--color-text-tertiary); text-transform: uppercase; letter-spacing: var(--tracking-wide); }

  .select-field { position: relative; display: flex; align-items: center; }

  .select-native {
    width: 100%;
    padding: var(--space-2) var(--space-8) var(--space-2) var(--space-3);
    background: var(--color-surface-raised);
    border: 1px solid var(--color-border-default);
    border-radius: var(--radius-md);
    font-size: var(--text-sm);
    color: var(--color-text-primary);
    cursor: pointer;
    appearance: none;
    -webkit-appearance: none;
    transition: var(--transition-colors);
    outline: none;
  }

  .select-native:focus { border-color: var(--color-border-focus); box-shadow: var(--shadow-focus); }
  .select-native:disabled { opacity: 0.5; cursor: not-allowed; }

  .select-arrow {
    position: absolute;
    right: var(--space-3);
    color: var(--color-text-tertiary);
    pointer-events: none;
    display: flex;
    align-items: center;
  }
</style>
