<script lang="ts">
  interface Tab {
    value: string;
    label: string;
    disabled?: boolean;
    content: import('svelte').Snippet;
  }

  interface Props {
    value?: string;
    onValueChange?: (value: string) => void;
    tabs: Tab[];
    activationMode?: 'automatic' | 'manual';
  }

  let {
    value = $bindable<string | undefined>(),
    onValueChange,
    tabs,
    activationMode = 'automatic',
  }: Props = $props();

  const activeTab = $derived(value ?? tabs[0]?.value);

  function activate(tab: Tab) {
    if (tab.disabled) return;
    value = tab.value;
    onValueChange?.(tab.value);
  }

  function handleKeydown(e: KeyboardEvent, tab: Tab) {
    if (activationMode === 'manual') return;
    const idx = tabs.findIndex(t => t.value === tab.value);
    if (e.key === 'ArrowRight') {
      e.preventDefault();
      const next = tabs.slice(idx + 1).find(t => !t.disabled) ?? tabs.find(t => !t.disabled);
      if (next) activate(next);
    } else if (e.key === 'ArrowLeft') {
      e.preventDefault();
      const prev = [...tabs].slice(0, idx).reverse().find(t => !t.disabled)
        ?? [...tabs].reverse().find(t => !t.disabled);
      if (prev) activate(prev);
    } else if (e.key === 'Home') {
      e.preventDefault();
      const first = tabs.find(t => !t.disabled);
      if (first) activate(first);
    } else if (e.key === 'End') {
      e.preventDefault();
      const last = [...tabs].reverse().find(t => !t.disabled);
      if (last) activate(last);
    }
  }
</script>

<div class="tabs-root">
  <div class="tabs-list" role="tablist">
    {#each tabs as tab (tab.value)}
      <button
        class="tabs-trigger"
        class:tabs-trigger--active={activeTab === tab.value}
        type="button"
        role="tab"
        aria-selected={activeTab === tab.value}
        aria-controls="tabpanel-{tab.value}"
        id="tab-{tab.value}"
        disabled={tab.disabled}
        tabindex={activeTab === tab.value ? 0 : -1}
        onclick={() => activate(tab)}
        onkeydown={(e) => handleKeydown(e, tab)}
      >
        {tab.label}
      </button>
    {/each}
  </div>

  {#each tabs as tab (tab.value)}
    <div
      class="tabs-panel"
      role="tabpanel"
      id="tabpanel-{tab.value}"
      aria-labelledby="tab-{tab.value}"
      hidden={activeTab !== tab.value}
    >
      {@render tab.content()}
    </div>
  {/each}
</div>

<style>
  .tabs-root { display: flex; flex-direction: column; }

  .tabs-list {
    display: flex;
    gap: var(--space-1);
    border-bottom: 1px solid var(--color-border-subtle);
    margin-block-end: var(--space-6);
    overflow-x: auto;
    scrollbar-width: none;
  }

  .tabs-list::-webkit-scrollbar { display: none; }

  .tabs-trigger {
    padding: var(--space-2) var(--space-4);
    font-size: var(--text-sm);
    font-weight: var(--weight-medium);
    color: var(--color-text-secondary);
    border-bottom: 2px solid transparent;
    margin-bottom: -1px;
    border-radius: 0;
    white-space: nowrap;
    transition: var(--transition-colors);
  }

  .tabs-trigger:hover:not(:disabled) { color: var(--color-text-primary); }
  .tabs-trigger--active { color: var(--color-brand-500); border-bottom-color: var(--color-brand-500); }
  .tabs-trigger:disabled { opacity: 0.4; cursor: not-allowed; }
  .tabs-trigger:focus-visible { outline: none; box-shadow: var(--shadow-focus); border-radius: var(--radius-sm); }

  .tabs-panel { outline: none; }
</style>
