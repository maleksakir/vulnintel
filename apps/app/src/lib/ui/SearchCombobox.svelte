<script lang="ts">
  interface Item {
    value: string;
    label: string;
    disabled?: boolean;
  }

  interface Props {
    value?: string;
    onValueChange?: (value: string) => void;
    items?: Item[];
    placeholder?: string;
    label?: string;
    /** Debounce delay in ms — 250 per spec §2.2.2 */
    debounce?: number;
    onInput?: (query: string) => void;
    disabled?: boolean;
  }

  let {
    value = $bindable(''),
    onValueChange,
    items = [],
    placeholder = 'Search…',
    label,
    debounce: debounceMs = 250,
    onInput,
    disabled = false,
  }: Props = $props();

  let open = $state(false);
  let activeIndex = $state(-1);
  let inputEl = $state<HTMLInputElement | null>(null);
  let debounceTimer: ReturnType<typeof setTimeout> | null = null;

  const filteredItems = $derived(
    items.filter(item =>
      !value || item.label.toLowerCase().includes(value.toLowerCase()),
    ),
  );

  function handleInput(e: Event) {
    const q = (e.currentTarget as HTMLInputElement).value;
    value = q;
    open = q.length > 0 && items.length > 0;
    activeIndex = -1;

    if (debounceTimer) clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => onInput?.(q), debounceMs);
  }

  function select(item: Item) {
    value = item.label;
    onValueChange?.(item.value);
    open = false;
    activeIndex = -1;
  }

  function handleKeydown(e: KeyboardEvent) {
    if (!open || filteredItems.length === 0) return;
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      activeIndex = Math.min(activeIndex + 1, filteredItems.length - 1);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      activeIndex = Math.max(activeIndex - 1, 0);
    } else if (e.key === 'Enter' && activeIndex >= 0) {
      e.preventDefault();
      const item = filteredItems[activeIndex];
      if (item && !item.disabled) select(item);
    } else if (e.key === 'Escape') {
      open = false;
      activeIndex = -1;
    }
  }

  function handleBlur() {
    setTimeout(() => { open = false; }, 150);
  }
</script>

<div class="combobox-wrap">
  {#if label}
    <label class="combobox-label" for="combobox-input">{label}</label>
  {/if}
  <div class="combobox-field">
    <input
      id="combobox-input"
      bind:this={inputEl}
      class="combobox-input"
      type="text"
      bind:value
      {placeholder}
      {disabled}
      role="combobox"
      aria-expanded={open}
      aria-autocomplete="list"
      aria-controls="combobox-listbox"
      aria-activedescendant={activeIndex >= 0 ? `combobox-option-${activeIndex}` : undefined}
      oninput={handleInput}
      onkeydown={handleKeydown}
      onfocus={() => { if (value && filteredItems.length > 0) open = true; }}
      onblur={handleBlur}
    />
    {#if value}
      <button
        class="combobox-clear"
        type="button"
        aria-label="Clear"
        tabindex="-1"
        onclick={() => { value = ''; open = false; onValueChange?.(''); onInput?.(''); }}
      >
        <svg width="10" height="10" viewBox="0 0 10 10" fill="none" aria-hidden="true">
          <path d="M8 2 2 8M2 2l6 6" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
        </svg>
      </button>
    {/if}
  </div>

  {#if open && filteredItems.length > 0}
    <ul
      id="combobox-listbox"
      class="combobox-listbox"
      role="listbox"
      aria-label={label ?? 'Options'}
    >
      {#each filteredItems as item, i (item.value)}
        <li
          id="combobox-option-{i}"
          class="combobox-option"
          class:combobox-option--active={i === activeIndex}
          class:combobox-option--selected={item.value === value}
          role="option"
          aria-selected={item.value === value}
          aria-disabled={item.disabled}
          onmousedown={(e) => { e.preventDefault(); if (!item.disabled) select(item); }}
        >
          {item.label}
        </li>
      {/each}
    </ul>
  {/if}
</div>

<style>
  .combobox-wrap { position: relative; display: flex; flex-direction: column; gap: var(--space-1); }

  .combobox-label { font-size: var(--text-xs); font-weight: var(--weight-medium); color: var(--color-text-tertiary); text-transform: uppercase; letter-spacing: var(--tracking-wide); }

  .combobox-field { position: relative; display: flex; align-items: center; }

  .combobox-input {
    width: 100%;
    padding: var(--space-2) var(--space-3);
    padding-right: var(--space-7);
    background: var(--color-surface-raised);
    border: 1px solid var(--color-border-default);
    border-radius: var(--radius-md);
    font-size: var(--text-sm);
    color: var(--color-text-primary);
    transition: var(--transition-colors);
    outline: none;
  }

  .combobox-input:focus { border-color: var(--color-border-focus); box-shadow: var(--shadow-focus); }
  .combobox-input:disabled { opacity: 0.5; cursor: not-allowed; }

  .combobox-clear {
    position: absolute;
    right: var(--space-2);
    color: var(--color-text-tertiary);
    width: 1.25rem;
    height: 1.25rem;
    border-radius: var(--radius-sm);
    display: flex;
    align-items: center;
    justify-content: center;
    transition: var(--transition-colors);
  }

  .combobox-clear:hover { color: var(--color-text-primary); background: var(--color-surface-elevated); }

  .combobox-listbox {
    position: absolute;
    top: calc(100% + var(--space-1));
    left: 0;
    right: 0;
    background: var(--color-surface-raised);
    border: 1px solid var(--color-border-default);
    border-radius: var(--radius-md);
    box-shadow: var(--shadow-lg);
    z-index: var(--z-popover);
    max-height: 16rem;
    overflow-y: auto;
    list-style: none;
    padding: var(--space-1) 0;
    margin: 0;
  }

  .combobox-option {
    padding: var(--space-2) var(--space-3);
    font-size: var(--text-sm);
    color: var(--color-text-secondary);
    cursor: pointer;
    transition: var(--transition-colors);
  }

  .combobox-option:hover,
  .combobox-option--active { background: var(--color-surface-elevated); color: var(--color-text-primary); }
  .combobox-option--selected { color: var(--color-brand-500); font-weight: var(--weight-medium); }
  .combobox-option[aria-disabled='true'] { opacity: 0.4; cursor: not-allowed; pointer-events: none; }
</style>
