<script lang="ts">
  import type { SbomScanResponse } from '@threat-lens/contracts';
  import PageHeader from '$lib/ui/PageHeader.svelte';
  import SeverityBadge from '$lib/ui/SeverityBadge.svelte';

  // Stateless SBOM scan tool. Upload a CycloneDX JSON SBOM; the server matches
  // every component against ingested OSV/CPE data and returns affected
  // components + CVEs. Nothing is stored — no asset, no login.

  let fileName = $state('');
  let busy = $state(false);
  let errorMsg = $state('');
  let result = $state<SbomScanResponse | null>(null);
  let dragging = $state(false);
  // Show only vulnerable components by default (the signal); toggle to see all.
  let showClean = $state(false);

  const MAX_BYTES = 8 * 1024 * 1024;

  const shown = $derived(
    result ? (showClean ? result.components : result.components.filter((c) => c.cves.length > 0)) : [],
  );

  async function scan(file: File) {
    errorMsg = '';
    result = null;
    if (file.size > MAX_BYTES) {
      errorMsg = `File too large (max ${MAX_BYTES / 1024 / 1024} MB).`;
      return;
    }
    fileName = file.name;
    busy = true;
    try {
      const text = await file.text();
      const res = await fetch('/api/sbom/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: text,
      });
      const body = (await res.json()) as SbomScanResponse | { error?: { message?: string } };
      if (!res.ok) {
        errorMsg = (body as { error?: { message?: string } }).error?.message ?? `Scan failed (${res.status})`;
        return;
      }
      result = body as SbomScanResponse;
    } catch (err) {
      errorMsg = err instanceof Error ? err.message : 'Scan failed';
    } finally {
      busy = false;
    }
  }

  function onPick(e: Event) {
    const input = e.target as HTMLInputElement;
    const file = input.files?.[0];
    if (file) scan(file);
  }

  function onDrop(e: DragEvent) {
    e.preventDefault();
    dragging = false;
    const file = e.dataTransfer?.files?.[0];
    if (file) scan(file);
  }

  function reset() {
    result = null;
    errorMsg = '';
    fileName = '';
  }

  function pct(n: number | null): string {
    return n === null ? '—' : `${(n * 100).toFixed(1)}th`;
  }
</script>

<svelte:head>
  <title>SBOM Scan — Threat-Lens CVE Hub</title>
  <meta
    name="description"
    content="Upload a CycloneDX SBOM and instantly see which of its components have known CVEs, matched against OSV and NVD data."
  />
</svelte:head>

<div class="page-sbom">
  <PageHeader
    eyebrow="SBOM SCAN"
    title="Dependency Exposure Scanner"
    subtitle="Upload a CycloneDX SBOM — every component is matched against ingested OSV (package ecosystems) and NVD CPE data. Stateless: nothing is uploaded to storage or retained."
  />

  {#if !result}
    <!-- svelte-ignore a11y_no_static_element_interactions -->
    <div
      class="dropzone"
      class:dropzone--active={dragging}
      ondragover={(e) => {
        e.preventDefault();
        dragging = true;
      }}
      ondragleave={() => (dragging = false)}
      ondrop={onDrop}
    >
      <svg class="dropzone__icon" width="40" height="40" viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <path d="M12 16V4m0 0 4 4m-4-4L8 8" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" />
        <path d="M4 15v3a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-3" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" />
      </svg>
      <p class="dropzone__title">Drop a CycloneDX SBOM here</p>
      <p class="dropzone__hint">or</p>
      <label class="btn-primary">
        {busy ? 'Scanning…' : 'Choose file'}
        <input type="file" accept=".json,application/json" onchange={onPick} disabled={busy} hidden />
      </label>
      <p class="dropzone__formats">CycloneDX JSON · up to 8 MB · {fileName || 'no file selected'}</p>
    </div>

    <div class="helptext">
      <p>
        Generate a CycloneDX SBOM with
        <code class="mono">syft</code>, <code class="mono">cdxgen</code>, Trivy, or your build tooling
        (<code class="mono">bomFormat: "CycloneDX"</code>). Components are matched by
        <strong>PURL</strong> against OSV package ranges and, where an explicit CPE is present, by
        <strong>vendor/product</strong> against NVD. A match means the component's package is affected
        by the CVE; exact-version range evaluation is best-effort.
      </p>
    </div>

    {#if errorMsg}
      <p class="scan-error" role="alert">{errorMsg}</p>
    {/if}
  {:else}
    <!-- Summary bar -->
    <div class="scan-summary">
      <div class="scan-stat">
        <span class="scan-stat__num mono">{result.componentsScanned}</span>
        <span class="scan-stat__label">components scanned</span>
      </div>
      <div class="scan-stat scan-stat--warn">
        <span class="scan-stat__num mono">{result.vulnerableComponents}</span>
        <span class="scan-stat__label">vulnerable</span>
      </div>
      <div class="scan-stat scan-stat--crit">
        <span class="scan-stat__num mono">{result.totalCves}</span>
        <span class="scan-stat__label">distinct CVEs</span>
      </div>
      {#if result.componentsSkipped > 0}
        <div class="scan-stat">
          <span class="scan-stat__num mono">{result.componentsSkipped}</span>
          <span class="scan-stat__label">skipped</span>
        </div>
      {/if}
      <div class="scan-actions">
        <label class="toggle">
          <input type="checkbox" bind:checked={showClean} />
          Show clean components
        </label>
        <button class="btn-secondary" type="button" onclick={reset}>Scan another</button>
      </div>
    </div>

    {#if result.truncated}
      <p class="scan-note" role="status">
        Results truncated at the per-scan match cap. Large SBOMs may show a subset of matches.
      </p>
    {/if}

    {#if result.vulnerableComponents === 0}
      <div class="empty-state">
        <p>No known CVEs matched any component.</p>
        <p class="empty-hint">
          This reflects CVEs currently ingested and linked by package ecosystem (OSV) or explicit CPE —
          not a guarantee of zero risk.
        </p>
      </div>
    {/if}

    {#if shown.length > 0}
      <div class="comp-list">
        {#each shown as c (c.name + (c.version ?? '') + (c.purl ?? ''))}
          <section class="comp" class:comp--clean={c.cves.length === 0}>
            <header class="comp__head">
              <div class="comp__id">
                <span class="comp__name">{c.name}</span>
                {#if c.version}<span class="comp__version mono">{c.version}</span>{/if}
                {#if c.ecosystem}<span class="comp__eco">{c.ecosystem}</span>{/if}
              </div>
              <div class="comp__meta">
                {#if c.hasKev}<span class="kev-chip">KEV</span>{/if}
                {#if c.maxSeverity}<SeverityBadge severity={c.maxSeverity} />{/if}
                <span class="comp__count mono">{c.cves.length} CVE{c.cves.length === 1 ? '' : 's'}</span>
              </div>
            </header>
            {#if c.cves.length > 0}
              <div class="table-wrap">
                <table class="data-table comp__table">
                  <thead>
                    <tr>
                      <th>CVE</th>
                      <th>Severity</th>
                      <th>CVSS</th>
                      <th>KEV</th>
                      <th>EPSS pct</th>
                      <th>Exploit</th>
                      <th>Via</th>
                    </tr>
                  </thead>
                  <tbody>
                    {#each c.cves as v (v.cveId)}
                      <tr>
                        <td><a class="cve-link" href="/cve/{v.cveId}">{v.cveId}</a></td>
                        <td><SeverityBadge severity={v.severity} variant="text" /></td>
                        <td class="mono">{v.cvssBase !== null ? v.cvssBase.toFixed(1) : '—'}</td>
                        <td>{#if v.kevListed}<span class="kev-chip">KEV</span>{:else}—{/if}</td>
                        <td class="mono">{pct(v.epssPercentile)}</td>
                        <td>
                          {#if v.exploitMaturity}
                            <span class="exploit-chip exploit-chip--{v.exploitMaturity}">{v.exploitMaturity}</span>
                          {:else}—{/if}
                        </td>
                        <td><span class="via-chip">{v.matchVia}</span></td>
                      </tr>
                    {/each}
                  </tbody>
                </table>
              </div>
            {/if}
          </section>
        {/each}
      </div>
    {/if}
  {/if}
</div>

<style>
  .page-sbom { max-width: 72rem; }

  /* Dropzone */
  .dropzone {
    display: flex; flex-direction: column; align-items: center; gap: var(--space-2);
    padding: var(--space-10) var(--space-6);
    border: 1.5px dashed var(--color-border-strong);
    border-radius: var(--radius-lg);
    background: var(--color-surface-raised);
    text-align: center;
    transition: var(--transition-colors);
  }
  .dropzone--active { border-color: var(--color-brand-default); background: var(--color-brand-subtle); }
  .dropzone__icon { color: var(--color-brand-default); margin-bottom: var(--space-2); }
  .dropzone__title { font-size: var(--text-lg); color: var(--color-text-primary); margin: 0; font-weight: var(--weight-medium); }
  .dropzone__hint { font-size: var(--text-sm); color: var(--color-text-tertiary); margin: 0; }
  .dropzone__formats { font-size: var(--text-xs); color: var(--color-text-tertiary); margin: var(--space-2) 0 0; font-family: var(--font-mono); }

  .btn-primary {
    display: inline-flex; align-items: center; gap: var(--space-2);
    padding: var(--space-2) var(--space-5);
    background: var(--color-brand-subtle); color: var(--color-brand-text);
    border: 1px solid var(--color-brand-border); border-radius: var(--radius-md);
    font-family: var(--font-mono); font-size: var(--text-sm); font-weight: var(--weight-medium);
    cursor: pointer; transition: var(--transition-colors), box-shadow var(--duration-fast) var(--ease-out);
  }
  .btn-primary:hover { border-color: var(--color-brand-default); box-shadow: var(--glow-accent); }
  .btn-secondary {
    padding: var(--space-2) var(--space-4);
    background: transparent; color: var(--color-text-secondary);
    border: 1px solid var(--color-border-default); border-radius: var(--radius-md);
    font-size: var(--text-sm); cursor: pointer; transition: var(--transition-colors);
  }
  .btn-secondary:hover { color: var(--color-brand-text); border-color: var(--color-brand-border); }

  .helptext { margin-top: var(--space-5); font-size: var(--text-sm); color: var(--color-text-secondary); line-height: var(--leading-relaxed); }
  .helptext code { font-size: var(--text-xs); background: var(--color-surface-elevated); padding: 0.1rem 0.3rem; border-radius: var(--radius-sm); }

  .scan-error { margin-top: var(--space-4); font-size: var(--text-sm); color: var(--color-critical-text); }
  .scan-note { font-size: var(--text-xs); color: var(--color-medium-text); margin: 0 0 var(--space-4); }

  /* Summary */
  .scan-summary {
    display: flex; flex-wrap: wrap; align-items: center; gap: var(--space-6);
    padding: var(--space-4) var(--space-5); margin-block-end: var(--space-6);
    border: 1px solid var(--color-border-default); border-radius: var(--radius-lg);
    background: var(--color-surface-raised);
  }
  .scan-stat { display: flex; flex-direction: column; }
  .scan-stat__num { font-size: var(--text-2xl); font-weight: var(--weight-bold); line-height: 1; }
  .scan-stat__label { font-size: var(--text-2xs); color: var(--color-text-tertiary); text-transform: uppercase; letter-spacing: var(--tracking-wide); margin-top: 2px; }
  .scan-stat--warn .scan-stat__num { color: var(--color-high-text); }
  .scan-stat--crit .scan-stat__num { color: var(--color-critical-text); }
  .scan-actions { margin-left: auto; display: flex; align-items: center; gap: var(--space-4); }
  .toggle { display: flex; align-items: center; gap: var(--space-2); font-size: var(--text-sm); color: var(--color-text-secondary); cursor: pointer; }

  /* Component cards */
  .comp-list { display: flex; flex-direction: column; gap: var(--space-4); }
  .comp {
    border: 1px solid var(--color-border-default); border-radius: var(--radius-lg);
    background: var(--color-surface-raised); overflow: hidden;
  }
  .comp--clean { opacity: 0.6; }
  .comp__head {
    display: flex; align-items: center; justify-content: space-between; gap: var(--space-3);
    flex-wrap: wrap; padding: var(--space-3) var(--space-4);
    border-bottom: 1px solid var(--color-border-subtle);
  }
  .comp__id { display: flex; align-items: baseline; gap: var(--space-3); flex-wrap: wrap; min-width: 0; }
  .comp__name { font-weight: var(--weight-semibold); color: var(--color-text-primary); }
  .comp__version { font-size: var(--text-sm); color: var(--color-text-secondary); }
  .comp__eco {
    font-family: var(--font-mono); font-size: var(--text-2xs); text-transform: uppercase;
    letter-spacing: var(--tracking-wide); color: var(--color-text-tertiary);
    background: var(--color-surface-elevated); padding: 0.1rem 0.4rem; border-radius: var(--radius-sm);
  }
  .comp__meta { display: flex; align-items: center; gap: var(--space-2); flex-shrink: 0; }
  .comp__count { font-size: var(--text-xs); color: var(--color-text-tertiary); }
  .comp__table { font-size: var(--text-sm); }

  .cve-link { color: var(--color-brand-text); font-family: var(--font-mono); }
  .cve-link:hover { color: var(--color-brand-hover); }
  .mono { font-family: var(--font-mono); }
  .kev-chip {
    font-family: var(--font-mono); font-size: var(--text-2xs); letter-spacing: var(--tracking-wide);
    color: var(--color-kev-text); background: var(--color-kev-subtle);
    border: 1px solid var(--color-kev); padding: 0.1rem 0.375rem; border-radius: var(--radius-sm);
  }
  .exploit-chip {
    font-family: var(--font-mono); font-size: var(--text-2xs); text-transform: uppercase;
    letter-spacing: var(--tracking-wide); padding: 0.1rem 0.375rem; border-radius: var(--radius-sm);
  }
  .exploit-chip--weaponized { color: var(--color-critical-text); background: var(--color-critical-subtle); }
  .exploit-chip--poc { color: var(--color-high-text); background: var(--color-high-subtle); }
  .exploit-chip--detection { color: var(--color-medium-text); background: var(--color-medium-subtle); }
  .via-chip {
    font-family: var(--font-mono); font-size: var(--text-2xs); color: var(--color-text-tertiary);
    background: var(--color-surface-elevated); padding: 0.1rem 0.375rem; border-radius: var(--radius-sm);
  }

  @media (max-width: 560px) {
    .scan-actions { margin-left: 0; width: 100%; }
  }
</style>
