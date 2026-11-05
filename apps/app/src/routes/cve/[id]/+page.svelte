<script lang="ts">
  import SeverityBadge from '$lib/ui/SeverityBadge.svelte';
  import type { PageData } from './$types';

  interface Props { data: PageData }
  let { data }: Props = $props();

  function isoToDate(iso: string | null) {
    return iso ? new Date(iso).toLocaleDateString(undefined, { dateStyle: 'medium' }) : '—';
  }

  // Age of the CVE in days since publication — a quick "how old is this" signal.
  const ageDays = $derived(
    Math.max(0, Math.floor((Date.now() - new Date(data.detail.publishedAt).getTime()) / 86_400_000)),
  );

  // ── CVSS vector decoder ──────────────────────────────────────────────────
  // Turn the raw vector (e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
  // into readable attack metrics. All data is already in the vector string —
  // this just makes it human-legible instead of making a researcher decode it.
  const CVSS_LABELS: Record<string, { label: string; values: Record<string, string>; hot?: string[] }> = {
    AV: { label: 'Attack Vector', values: { N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical' }, hot: ['N'] },
    AC: { label: 'Attack Complexity', values: { L: 'Low', H: 'High' }, hot: ['L'] },
    PR: { label: 'Privileges Required', values: { N: 'None', L: 'Low', H: 'High' }, hot: ['N'] },
    UI: { label: 'User Interaction', values: { N: 'None', R: 'Required', P: 'Passive', A: 'Active' }, hot: ['N'] },
    S: { label: 'Scope', values: { U: 'Unchanged', C: 'Changed' }, hot: ['C'] },
    C: { label: 'Confidentiality', values: { H: 'High', L: 'Low', N: 'None' }, hot: ['H'] },
    I: { label: 'Integrity', values: { H: 'High', L: 'Low', N: 'None' }, hot: ['H'] },
    A: { label: 'Availability', values: { H: 'High', L: 'Low', N: 'None' }, hot: ['H'] },
  };
  interface DecodedMetric { key: string; label: string; value: string; hot: boolean }
  const cvssMetrics = $derived.by<DecodedMetric[]>(() => {
    const vec = data.detail.cvss?.vector;
    if (!vec) return [];
    const out: DecodedMetric[] = [];
    for (const part of vec.split('/')) {
      const [k, v] = part.split(':');
      if (!k || !v) continue;
      const def = CVSS_LABELS[k];
      if (!def) continue; // skip CVSS:3.1 prefix and any unknown metric
      out.push({
        key: k,
        label: def.label,
        value: def.values[v] ?? v,
        hot: def.hot?.includes(v) ?? false,
      });
    }
    return out;
  });
</script>

<svelte:head>
  <title>{data.detail.cveId} — Threat-Lens CVE Hub</title>
  <meta name="description" content="{data.detail.description.slice(0, 200)}" />
</svelte:head>

<div class="page-cve">
  <!-- Header -->
  <header class="cve-header">
    <div class="cve-header-top">
      <h1 class="cve-id">{data.detail.cveId}</h1>
      <SeverityBadge severity={data.detail.severity} />
      {#if data.detail.cvss}
        <span class="cve-cvss" title="CVSS {data.detail.cvss.version} base score">CVSS {data.detail.cvss.base.toFixed(1)}</span>
      {/if}
      {#if data.detail.state.kevListed}
        <span class="badge-kev">KEV</span>
      {/if}
    </div>
    <p class="cve-dates">
      Published {isoToDate(data.detail.publishedAt)} · Modified {isoToDate(data.detail.lastModifiedAt)}
    </p>
  </header>

  <!--
    Priority & exploitation intelligence — the "what do I do about this" panel.
    This is the synthesis a raw CVE database (NVD) doesn't give you: a single
    deterministic verdict fusing active-exploitation (KEV), exploit
    probability (EPSS) and intrinsic severity (CVSS), with the reasoning shown.
  -->
  {#if data.priority}
    {@const p = data.priority}
    <section class="intel" aria-label="Priority and exploitation intelligence">
      <div class="intel__score intel__score--{p.band.toLowerCase()}">
        <span class="intel__score-num mono">{p.score}</span>
        <span class="intel__score-band">{p.band}</span>
      </div>
      <div class="intel__body">
        <h2 class="intel__heading">Priority Assessment</h2>
        <p class="intel__rationale">{p.rationale}</p>
        <div class="intel__signals">
          <span class="intel__signal intel__signal--{data.detail.state.kevListed ? 'on' : 'off'}">
            {data.detail.state.kevListed ? '● ' : '○ '}Active exploitation (KEV)
          </span>
          <span class="intel__signal intel__signal--{(data.detail.state.epssPercentile ?? 0) >= 0.5 ? 'on' : 'off'}">
            {(data.detail.state.epssPercentile ?? 0) >= 0.5 ? '● ' : '○ '}Exploit probability{data.detail.state.epssPercentile !== null ? ` (${(data.detail.state.epssPercentile * 100).toFixed(0)}th pct)` : ''}
          </span>
          <span class="intel__signal intel__signal--{data.detail.severity === 'CRITICAL' || data.detail.severity === 'HIGH' ? 'on' : 'off'}">
            {data.detail.severity === 'CRITICAL' || data.detail.severity === 'HIGH' ? '● ' : '○ '}{data.detail.severity} severity
          </span>
        </div>
      </div>
    </section>
  {/if}

  <!--
    Risk acceptance (remediation) — operator-only. The CVE itself is public
    data; our decision to leave it unpatched until a given date is not, so the
    banner and the accept/revoke panel only render for a signed-in operator
    (`?token=<ADMIN_BEARER>`). See src/lib/server/adminSession.ts.
  -->
  <!-- CISA SSVC decision — the agency's own "act now / track" stakeholder
       triage. Shown when NVD carries a CISA-ADP SSVC decision. -->
  {#if data.detail.ssvc}
    {@const s = data.detail.ssvc}
    <section class="ssvc" aria-label="CISA SSVC decision">
      <h2 class="ssvc__heading">CISA SSVC Decision</h2>
      <div class="ssvc__grid">
        <div class="ssvc__point ssvc__point--{s.exploitation === 'active' ? 'hot' : s.exploitation === 'poc' ? 'warm' : 'cool'}">
          <span class="ssvc__label">Exploitation</span>
          <span class="ssvc__value">{s.exploitation ?? '—'}</span>
        </div>
        <div class="ssvc__point ssvc__point--{s.automatable === 'yes' ? 'hot' : 'cool'}">
          <span class="ssvc__label">Automatable</span>
          <span class="ssvc__value">{s.automatable ?? '—'}</span>
        </div>
        <div class="ssvc__point ssvc__point--{s.technicalImpact === 'total' ? 'hot' : 'cool'}">
          <span class="ssvc__label">Technical Impact</span>
          <span class="ssvc__value">{s.technicalImpact ?? '—'}</span>
        </div>
      </div>
      {#if s.decidedAt}<p class="ssvc__date">Decided {isoToDate(s.decidedAt)}</p>{/if}
    </section>
  {/if}

  <!-- Public exploit signals — the differentiator: is there runnable exploit
       code / a PoC in the wild, and where. -->
  {#if data.detail.exploits?.length}
    <section class="cve-section" aria-labelledby="exploit-heading">
      <h2 id="exploit-heading" class="section-title">
        Exploit Intelligence
        <span class="exploit-verdict exploit-verdict--{data.detail.exploitMaturity}">
          {data.detail.exploitMaturity === 'weaponized'
            ? 'Public exploit available'
            : data.detail.exploitMaturity === 'poc'
              ? 'Proof-of-concept available'
              : 'Detection available'}
        </span>
      </h2>
      <ul class="exploit-list">
        {#each data.detail.exploits as ex}
          <li class="exploit-item">
            <span class="exploit-src exploit-src--{ex.source}">{ex.source}</span>
            {#if ex.url}
              <a class="exploit-title" href={ex.url} target="_blank" rel="noopener">{ex.title ?? ex.externalId}</a>
            {:else}
              <span class="exploit-title">{ex.title ?? ex.externalId}</span>
            {/if}
            <span class="exploit-mat exploit-mat--{ex.maturity}">{ex.maturity}</span>
          </li>
        {/each}
      </ul>
    </section>
  {/if}

  <!-- Key facts strip — fast orientation before the detail sections. -->
  <dl class="facts">
    <div class="fact"><dt>Published</dt><dd>{isoToDate(data.detail.publishedAt)} <span class="fact__age">· {ageDays}d ago</span></dd></div>
    <div class="fact"><dt>Last modified</dt><dd>{isoToDate(data.detail.lastModifiedAt)}</dd></div>
    <div class="fact"><dt>CVSS</dt><dd>{data.detail.cvss ? `${data.detail.cvss.base.toFixed(1)} (v${data.detail.cvss.version})` : '—'}</dd></div>
    <div class="fact"><dt>EPSS pct</dt><dd>{data.detail.state.epssPercentile !== null ? `${(data.detail.state.epssPercentile * 100).toFixed(1)}th` : '—'}</dd></div>
    <div class="fact"><dt>Weaknesses</dt><dd>{data.detail.cwes.length || '—'}</dd></div>
    <div class="fact"><dt>Affected products</dt><dd>{data.detail.cpes.length}{data.detail.cpes.length >= 500 ? '+' : ''}</dd></div>
  </dl>

  <!-- Description -->
  <section class="cve-section" aria-labelledby="desc-heading">
    <h2 id="desc-heading" class="section-title">Description</h2>
    <p class="cve-description">{data.detail.description}</p>
  </section>

  <div class="two-col">
    <!-- CVSS Metrics — decoded attack vector -->
    {#if data.detail.cvss}
      <section class="cve-section" aria-labelledby="cvss-heading">
        <h2 id="cvss-heading" class="section-title">
          CVSS {data.detail.cvss.version}
          <span class="cvss-score score-value--{data.detail.severity.toLowerCase()}">{data.detail.cvss.base.toFixed(1)}</span>
        </h2>
        <table class="kv-table">
          <tbody>
            {#each cvssMetrics as m (m.key)}
              <tr>
                <th scope="row">{m.label}</th>
                <td class:kv-hot={m.hot}>{m.value}</td>
              </tr>
            {/each}
            {#if data.detail.cvss.exploitability !== null}
              <tr><th scope="row">Exploitability sub-score</th><td class="mono">{data.detail.cvss.exploitability.toFixed(2)}</td></tr>
            {/if}
            {#if data.detail.cvss.impact !== null}
              <tr><th scope="row">Impact sub-score</th><td class="mono">{data.detail.cvss.impact.toFixed(2)}</td></tr>
            {/if}
          </tbody>
        </table>
        <p class="cvss-vector"><code class="mono">{data.detail.cvss.vector}</code></p>
      </section>
    {/if}

    <!-- Threat Intel -->
    <section class="cve-section" aria-labelledby="threat-heading">
      <h2 id="threat-heading" class="section-title">Threat Intelligence</h2>
      <table class="kv-table">
        <tbody>
          <tr>
            <th scope="row">Known Exploited (KEV)</th>
            <td class:kv-hot={data.detail.state.kevListed}>{data.detail.state.kevListed ? 'Yes — actively exploited' : 'Not listed'}</td>
          </tr>
          {#if data.detail.state.kevDateAdded}
            <tr><th scope="row">KEV date added</th><td>{isoToDate(data.detail.state.kevDateAdded)}</td></tr>
          {/if}
          {#if data.detail.state.kevDueDate}
            <tr><th scope="row">Remediation due</th><td>{isoToDate(data.detail.state.kevDueDate)}</td></tr>
          {/if}
          {#if data.detail.state.epssScore !== null}
            <tr><th scope="row">EPSS score</th><td class="mono">{(data.detail.state.epssScore * 100).toFixed(2)}%</td></tr>
          {/if}
          {#if data.detail.state.epssPercentile !== null}
            <tr><th scope="row">EPSS percentile</th><td class="mono">{(data.detail.state.epssPercentile * 100).toFixed(1)}th</td></tr>
          {/if}
          {#if data.detail.exploitMaturity}
            <tr><th scope="row">Public exploit</th><td class="kv-hot">{data.detail.exploitMaturity === 'weaponized' ? 'Weaponized' : data.detail.exploitMaturity === 'poc' ? 'Proof-of-concept' : 'Detection'}</td></tr>
          {/if}
        </tbody>
      </table>
      {#if data.detail.state.kevRequiredAction}
        <p class="kev-action"><strong>Required Action:</strong> {data.detail.state.kevRequiredAction}</p>
      {/if}
    </section>
  </div>

  <!-- CWEs -->
  {#if data.detail.cwes.length > 0}
    <section class="cve-section" aria-labelledby="cwe-heading">
      <h2 id="cwe-heading" class="section-title">Weaknesses (CWE)</h2>
      <ul class="cwe-list" role="list">
        {#each data.detail.cwes as cwe}
          <li class="cwe-item">
            <code class="cwe-id">{cwe.id}</code>
            <span class="cwe-name">{cwe.name}</span>
            {#if cwe.category}
              <span class="cwe-category">{cwe.category}</span>
            {/if}
          </li>
        {/each}
      </ul>
    </section>
  {/if}

  <!-- CPEs -->
  {#if data.detail.cpes.length > 0}
    <section class="cve-section" aria-labelledby="cpe-heading">
      <h2 id="cpe-heading" class="section-title">Affected Products ({data.detail.cpes.length})</h2>
      <div class="table-wrap">
        <table class="data-table">
          <thead>
            <tr>
              <th>Vendor</th>
              <th>Product</th>
              <th>Version</th>
              <th>Vulnerable</th>
            </tr>
          </thead>
          <tbody>
            {#each data.detail.cpes.slice(0, 100) as cpe}
              <tr>
                <td>
                  <a href="/affected-products?vendor={encodeURIComponent(cpe.vendor)}">{cpe.vendor}</a>
                </td>
                <td>{cpe.product}</td>
                <td class="mono">{cpe.version ?? formatRange(cpe)}</td>
                <td>{cpe.vulnerable ? '✓' : '—'}</td>
              </tr>
            {/each}
          </tbody>
        </table>
        {#if data.detail.cpes.length > 100}
          <p class="table-overflow">Showing 100 of {data.detail.cpes.length} affected products.</p>
        {/if}
      </div>
    </section>
  {/if}

  <!-- OSV / GHSA affected packages — ecosystem-level affected & fixed
       versions that NVD CPE doesn't carry. The "upgrade to X to fix it"
       signal, per package manager. -->
  {#if data.detail.osvPackages.length > 0}
    <section class="cve-section" aria-labelledby="osv-heading">
      <h2 id="osv-heading" class="section-title">Affected Packages (OSV)</h2>
      <div class="table-wrap">
        <table class="data-table">
          <thead>
            <tr>
              <th>Ecosystem</th>
              <th>Package</th>
              <th>Affected range</th>
              <th>Fixed in</th>
            </tr>
          </thead>
          <tbody>
            {#each data.detail.osvPackages as pkg (pkg.ecosystem + pkg.packageName)}
              <tr>
                <td><span class="eco-chip">{pkg.ecosystem}</span></td>
                <td class="mono">{pkg.packageName}</td>
                <td class="mono">{pkg.rangeSummary ?? '—'}</td>
                <td class="mono osv-fixed">{pkg.fixedVersions ?? '—'}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </section>
  {/if}

  <!-- References -->
  {#if data.detail.references.length > 0}
    <section class="cve-section" aria-labelledby="ref-heading">
      <h2 id="ref-heading" class="section-title">References ({data.detail.references.length})</h2>
      <ul class="ref-list" role="list">
        {#each data.detail.references as ref}
          <li class="ref-item">
            <a class="ref-url" href={ref.url} target="_blank" rel="noopener noreferrer">{ref.url}</a>
            {#each ref.tags as tag}
              <span class="ref-tag">{tag}</span>
            {/each}
          </li>
        {/each}
      </ul>
    </section>
  {/if}

  <!-- Data provenance — which upstream sources contributed to this record.
       The "where did this come from" trail that a raw NVD view doesn't give. -->
  {#if data.detail.sources.length > 0}
    <footer class="provenance">
      <span class="provenance__label">Sources</span>
      <ul class="provenance__list" role="list">
        {#each data.detail.sources as src (src.source)}
          <li class="provenance__item">
            <span class="provenance__src">{src.source}</span>
            <span class="provenance__seen">updated {isoToDate(src.lastSeenAt)}</span>
          </li>
        {/each}
      </ul>
    </footer>
  {/if}
</div>

<script module>
  function formatRange(cpe: { versionStartIncluding?: string | null; versionStartExcluding?: string | null; versionEndIncluding?: string | null; versionEndExcluding?: string | null }): string {
    const parts: string[] = [];
    if (cpe.versionStartIncluding) parts.push(`>=${cpe.versionStartIncluding}`);
    if (cpe.versionStartExcluding) parts.push(`>${cpe.versionStartExcluding}`);
    if (cpe.versionEndIncluding) parts.push(`<=${cpe.versionEndIncluding}`);
    if (cpe.versionEndExcluding) parts.push(`<${cpe.versionEndExcluding}`);
    return parts.join(', ') || '*';
  }
</script>

<style>
  /* Centred reading column — the shell caps at 82rem, so without this the
     56rem detail column sat flush-left with a large empty right gutter on
     wide monitors. */
  .page-cve { max-width: 60rem; margin-inline: auto; }
  .cve-header { margin-block-end: var(--space-8); }
  .cve-header-top { display: flex; align-items: center; gap: var(--space-3); flex-wrap: wrap; margin-block-end: var(--space-2); }
  .cve-id { font-size: var(--text-3xl); font-weight: var(--weight-bold); color: var(--color-text-primary); margin: 0; font-family: var(--font-mono); letter-spacing: var(--tracking-tight); }
  .cve-cvss { font-size: var(--text-sm); color: var(--color-text-secondary); font-family: var(--font-mono); padding: 0.125rem 0.5rem; background: var(--color-surface-elevated); border: 1px solid var(--color-border-default); border-radius: var(--radius-sm); }
  .badge-kev { font-family: var(--font-mono); font-size: var(--text-2xs); letter-spacing: var(--tracking-wide); text-transform: uppercase; background: var(--color-kev-subtle); color: var(--color-kev-text); border: 1px solid var(--color-kev); padding: 0.1rem 0.5rem; border-radius: var(--radius-sm); font-weight: var(--weight-semibold); box-shadow: var(--glow-critical); }
  .cve-dates { font-size: var(--text-sm); color: var(--color-text-tertiary); margin: 0; }

  /* Priority & exploitation intelligence panel */
  .intel {
    display: flex;
    gap: var(--space-5);
    align-items: stretch;
    margin-block-end: var(--space-8);
    padding: var(--space-4);
    border: 1px solid var(--color-border-default);
    border-radius: var(--radius-lg);
    background:
      radial-gradient(120% 140% at 0% 0%, var(--color-brand-subtle) 0%, transparent 50%),
      var(--color-surface-raised);
  }
  .intel__score {
    flex: none;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    width: 7rem;
    border-radius: var(--radius-md);
    border: 1px solid var(--color-border-strong);
    background: var(--color-surface-sunken);
  }
  .intel__score-num { font-size: var(--text-4xl); font-weight: var(--weight-bold); line-height: 1; }
  .intel__score-band {
    margin-top: var(--space-1);
    font-family: var(--font-mono);
    font-size: var(--text-2xs);
    letter-spacing: var(--tracking-caps);
    text-transform: uppercase;
  }
  .intel__score--critical { border-color: var(--color-critical-border); }
  .intel__score--critical .intel__score-num, .intel__score--critical .intel__score-band { color: var(--color-critical-text); }
  .intel__score--critical { box-shadow: var(--glow-critical); }
  .intel__score--high { border-color: var(--color-high-border); }
  .intel__score--high .intel__score-num, .intel__score--high .intel__score-band { color: var(--color-high-text); }
  .intel__score--moderate { border-color: var(--color-medium-border); }
  .intel__score--moderate .intel__score-num, .intel__score--moderate .intel__score-band { color: var(--color-medium-text); }
  .intel__score--low { border-color: var(--color-low-border); }
  .intel__score--low .intel__score-num, .intel__score--low .intel__score-band { color: var(--color-low-text); }

  .intel__body { flex: 1; min-width: 0; display: flex; flex-direction: column; justify-content: center; }
  .intel__heading {
    margin: 0 0 var(--space-1);
    font-family: var(--font-mono);
    font-size: var(--text-2xs);
    letter-spacing: var(--tracking-caps);
    text-transform: uppercase;
    color: var(--color-text-tertiary);
  }
  .intel__rationale { margin: 0 0 var(--space-3); font-size: var(--text-base); color: var(--color-text-primary); line-height: var(--leading-snug); }
  .intel__signals { display: flex; flex-wrap: wrap; gap: var(--space-2) var(--space-4); }
  .intel__signal { font-family: var(--font-mono); font-size: var(--text-xs); }
  .intel__signal--on { color: var(--color-brand-text); }
  .intel__signal--off { color: var(--color-text-tertiary); }

  /* Exploit intelligence section */
  .exploit-verdict {
    font-family: var(--font-mono); font-size: var(--text-2xs);
    letter-spacing: var(--tracking-wide); text-transform: uppercase;
    padding: 0.1rem 0.5rem; border-radius: var(--radius-sm); border: 1px solid transparent;
  }
  .exploit-verdict--weaponized { color: var(--color-critical-text); background: var(--color-critical-subtle); border-color: var(--color-critical-border); }
  .exploit-verdict--poc { color: var(--color-high-text); background: var(--color-high-subtle); border-color: var(--color-high-border); }
  .exploit-verdict--detection { color: var(--color-medium-text); background: var(--color-medium-subtle); border-color: var(--color-medium-border); }

  .exploit-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; }
  .exploit-item {
    display: flex; align-items: center; gap: var(--space-3);
    padding: var(--space-2_5) 0; border-bottom: 1px solid var(--color-border-subtle);
    font-size: var(--text-sm); flex-wrap: wrap;
  }
  .exploit-item:last-child { border-bottom: none; }
  .exploit-src {
    flex: none; width: 6rem; font-family: var(--font-mono); font-size: var(--text-2xs);
    text-transform: uppercase; letter-spacing: var(--tracking-wide); color: var(--color-brand-text);
  }
  .exploit-title { flex: 1; min-width: 12rem; color: var(--color-text-primary); }
  a.exploit-title:hover { color: var(--color-brand-text); }
  .exploit-mat {
    flex: none; font-family: var(--font-mono); font-size: var(--text-2xs);
    text-transform: uppercase; letter-spacing: var(--tracking-wide); color: var(--color-text-tertiary);
  }
  .exploit-mat--weaponized { color: var(--color-critical-text); }

  @media (max-width: 560px) {
    .intel { flex-direction: column; gap: var(--space-3); }
    .intel__score { width: 100%; flex-direction: row; gap: var(--space-3); padding: var(--space-3); }
  }

  .cve-section { margin-block-end: var(--space-8); }
  .section-title { display: flex; align-items: center; gap: var(--space-3); flex-wrap: wrap; font-size: var(--text-xs); font-weight: var(--weight-semibold); text-transform: uppercase; letter-spacing: var(--tracking-wide); color: var(--color-text-tertiary); margin: 0 0 var(--space-4); }
  .cve-description { font-size: var(--text-base); line-height: var(--leading-relaxed); color: var(--color-text-secondary); margin: 0; }

  .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: var(--layout-card-gap); margin-block-end: var(--space-8); }
  /* Key facts strip */
  .facts {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(9rem, 1fr));
    gap: var(--space-1) var(--space-5); margin: 0 0 var(--space-8);
    padding: var(--space-4) var(--space-5);
    border: 1px solid var(--color-border-default); border-radius: var(--radius-lg);
    background: var(--color-surface-raised);
  }
  .fact { display: flex; flex-direction: column; gap: 2px; }
  .fact dt { font-size: var(--text-2xs); text-transform: uppercase; letter-spacing: var(--tracking-wide); color: var(--color-text-tertiary); margin: 0; }
  .fact dd { font-size: var(--text-sm); font-weight: var(--weight-medium); color: var(--color-text-primary); margin: 0; }
  .fact__age { color: var(--color-text-tertiary); font-weight: var(--weight-regular); }

  /* Key/value metric table (CVSS decoded + threat intel) */
  .kv-table { width: 100%; border-collapse: collapse; font-size: var(--text-sm); }
  .kv-table th[scope='row'] { text-align: left; font-weight: var(--weight-regular); color: var(--color-text-tertiary); padding: var(--space-1_5) var(--space-3) var(--space-1_5) 0; white-space: nowrap; vertical-align: top; }
  .kv-table td { color: var(--color-text-primary); padding: var(--space-1_5) 0; }
  .kv-table tr + tr th, .kv-table tr + tr td { border-top: 1px solid var(--color-border-subtle); }
  .kv-hot { color: var(--color-critical-text); font-weight: var(--weight-semibold); }

  .cvss-score { margin-left: auto; font-size: var(--text-xl); font-weight: var(--weight-bold); font-variant-numeric: tabular-nums; }
  .score-value--critical { color: var(--color-critical-text); }
  .score-value--high { color: var(--color-high-text); }
  .score-value--medium { color: var(--color-medium-text); }
  .score-value--low { color: var(--color-low-text); }
  .score-value--none { color: var(--color-none-text); }
  .cvss-vector { margin: var(--space-3) 0 0; }
  .cvss-vector code { font-size: var(--text-2xs); color: var(--color-text-tertiary); background: var(--color-surface-sunken); padding: 0.2rem 0.4rem; border-radius: var(--radius-sm); word-break: break-all; }
  .mono { font-family: var(--font-mono); font-size: var(--text-xs); word-break: break-all; }
  .kev-action { font-size: var(--text-sm); color: var(--color-text-secondary); margin: var(--space-3) 0 0; line-height: 1.5; }

  .cwe-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: var(--space-2); }
  .cwe-item { display: flex; align-items: center; gap: var(--space-3); font-size: var(--text-sm); }
  .cwe-id { font-family: var(--font-mono); color: var(--color-brand-text); background: var(--color-surface-elevated); padding: 0.125rem 0.375rem; border-radius: var(--radius-sm); }
  .cwe-name { color: var(--color-text-primary); }
  .cwe-category { font-size: var(--text-xs); color: var(--color-text-tertiary); background: var(--color-surface-elevated); padding: 0.125rem 0.375rem; border-radius: var(--radius-full); }

  /* Inherits the global .data-grid/.data-table look (app.css §15). */
  .table-overflow { font-size: var(--text-xs); color: var(--color-text-tertiary); margin: var(--space-2) 0 0; }

  .ref-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: var(--space-2); }
  .ref-item { display: flex; align-items: flex-start; gap: var(--space-2); font-size: var(--text-sm); flex-wrap: wrap; }
  .ref-url { color: var(--color-brand-text); word-break: break-all; flex: 1; min-width: 0; }
  .ref-url:hover { color: var(--color-brand-hover); }
  .ref-tag { font-family: var(--font-mono); font-size: var(--text-2xs); color: var(--color-text-tertiary); background: var(--color-surface-elevated); padding: 0.125rem 0.375rem; border-radius: var(--radius-sm); flex-shrink: 0; text-transform: uppercase; letter-spacing: var(--tracking-wide); }

  /* CISA SSVC decision panel. Heading matches .section-title exactly so every
     section header on the page shares one style + bottom margin. */
  .ssvc { margin-block-end: var(--space-8); }
  .ssvc__heading { font-size: var(--text-xs); font-weight: var(--weight-semibold); text-transform: uppercase; letter-spacing: var(--tracking-wide); color: var(--color-text-tertiary); margin: 0 0 var(--space-4); }
  .ssvc__grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: var(--space-3); }
  .ssvc__point { display: flex; flex-direction: column; gap: var(--space-1); padding: var(--space-3) var(--space-4); border: 1px solid var(--color-border-default); border-radius: var(--radius-md); background: var(--color-surface-raised); }
  .ssvc__label { font-size: var(--text-2xs); text-transform: uppercase; letter-spacing: var(--tracking-wide); color: var(--color-text-tertiary); }
  .ssvc__value { font-size: var(--text-lg); font-weight: var(--weight-semibold); text-transform: capitalize; color: var(--color-text-primary); }
  .ssvc__point--hot { border-color: var(--color-critical-border); }
  .ssvc__point--hot .ssvc__value { color: var(--color-critical-text); }
  .ssvc__point--warm { border-color: var(--color-high-border); }
  .ssvc__point--warm .ssvc__value { color: var(--color-high-text); }
  .ssvc__date { font-size: var(--text-xs); color: var(--color-text-tertiary); margin: var(--space-2) 0 0; }

  /* OSV affected packages */
  .eco-chip { font-family: var(--font-mono); font-size: var(--text-2xs); text-transform: uppercase; letter-spacing: var(--tracking-wide); color: var(--color-brand-text); background: var(--color-brand-subtle); padding: 0.1rem 0.4rem; border-radius: var(--radius-sm); }
  .osv-fixed { color: var(--color-low-text); }

  /* Data provenance footer */
  .provenance { display: flex; align-items: baseline; gap: var(--space-3); flex-wrap: wrap; margin-top: var(--space-4); padding-top: var(--space-4); border-top: 1px solid var(--color-border-subtle); }
  .provenance__label { font-size: var(--text-2xs); text-transform: uppercase; letter-spacing: var(--tracking-wide); color: var(--color-text-tertiary); }
  .provenance__list { list-style: none; margin: 0; padding: 0; display: flex; flex-wrap: wrap; gap: var(--space-2); }
  .provenance__item { display: inline-flex; align-items: baseline; gap: var(--space-1); font-size: var(--text-xs); background: var(--color-surface-elevated); padding: 0.15rem 0.5rem; border-radius: var(--radius-sm); }
  .provenance__src { font-family: var(--font-mono); color: var(--color-text-secondary); }
  .provenance__seen { color: var(--color-text-tertiary); }

  @media (max-width: 700px) {
    .two-col { grid-template-columns: 1fr; }
    .ssvc__grid { grid-template-columns: 1fr; }
  }
</style>
