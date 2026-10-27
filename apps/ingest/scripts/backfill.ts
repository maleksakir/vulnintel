/**
 * Full NVD Corpus Backfill
 *
 * Loads the entire NVD CVE corpus into D1 + Vectorize via the same
 * two-hash processRecord path used by daily ingest.
 *
 * Usage (run from repo root):
 *   pnpm --filter threat-lens-ingest exec ts-node -e "import('./src/scripts/backfill').then(m => m.run())"
 *
 * Or as a Wrangler script via:
 *   wrangler dev --script-path scripts/backfill.ts
 *
 * Checkpoint key:  BACKFILL_CURSOR  (stored in KV)
 * Format:          JSON  { startIndex: number; totalResults: number; ts: number }
 *
 * The script pages through NVD 2000 records at a time starting from
 * the saved checkpoint. After each page it writes the next startIndex
 * back to KV so a restart resumes exactly where it left off.
 *
 * KEV + EPSS passes run after the main NVD pass completes.
 * Use SKIP_KEV=1 / SKIP_EPSS=1 env vars to skip those passes.
 *
 * Rate limiting:
 *   NVD API with key: 50 req / 30 s  →  1 req / 600 ms
 *   This script targets one page per 650 ms (margin of safety).
 *
 * Concurrency:
 *   processRecord is called sequentially (one at a time) to avoid
 *   hammering D1 + Vectorize. The AI call (embedding) is the bottleneck;
 *   two-hash means only records with changed text embed — most records on
 *   a re-run are skipped entirely.
 */

import type { NormalizedCpe, NormalizedCveRecord, Severity } from '@threat-lens/contracts';
import { fetchEpssCsv } from '../src/adapters/epss';
import { fetchKevCatalog } from '../src/adapters/kev';
import { applyEpssPatch, applyKevPatch, processRecord } from '../src/lib/server/processRecord';
import type { Env } from '../src/types';

const NVD_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const RESULTS_PER_PAGE = 2000;
const PAGE_DELAY_MS = 650;
const CHECKPOINT_KEY = 'backfill:nvd:cursor';

// ── NVD response types (mirrors adapters/nvd.ts, kept local to avoid import issues) ──

interface NvdCveResponse {
  resultsPerPage: number;
  startIndex: number;
  totalResults: number;
  vulnerabilities: Array<{ cve: NvdCve }>;
}

interface NvdCve {
  id: string;
  published: string;
  lastModified: string;
  descriptions: Array<{ lang: string; value: string }>;
  metrics?: {
    cvssMetricV31?: NvdCvssMetric[];
    cvssMetricV40?: NvdCvssV4Metric[];
  };
  weaknesses?: Array<{ description: Array<{ lang: string; value: string }> }>;
  configurations?: { nodes?: NvdNode[] }[];
  references?: Array<{ url: string; tags?: string[] }>;
}

interface NvdCvssMetric {
  type: string;
  cvssData: { version: string; vectorString: string; baseScore: number };
  exploitabilityScore?: number;
  impactScore?: number;
}

interface NvdCvssV4Metric {
  cvssData: { version: string; vectorString: string; baseScore: number };
}

interface NvdNode {
  cpeMatch?: NvdCpeMatch[];
  nodes?: NvdNode[];
}

interface NvdCpeMatch {
  vulnerable: boolean;
  criteria: string;
  versionStartIncluding?: string;
  versionStartExcluding?: string;
  versionEndIncluding?: string;
  versionEndExcluding?: string;
}

interface BackfillCheckpoint {
  startIndex: number;
  totalResults: number;
  ts: number;
}

// ── Entry point ───────────────────────────────────────────────────────────────

export async function run(env: Env): Promise<void> {
  const apiKey = env.NVD_API_KEY;
  const ctx = buildMockCtx();

  console.log('[backfill] Starting NVD full-corpus backfill…');

  // Restore checkpoint
  const raw = await env.CACHE.get(CHECKPOINT_KEY);
  const checkpoint: BackfillCheckpoint = raw
    ? (JSON.parse(raw) as BackfillCheckpoint)
    : { startIndex: 0, totalResults: Infinity, ts: Date.now() };

  if (checkpoint.startIndex > 0) {
    console.log(
      `[backfill] Resuming from startIndex=${checkpoint.startIndex} / totalResults=${checkpoint.totalResults}`,
    );
  }

  let startIndex = checkpoint.startIndex;
  let total = checkpoint.totalResults;
  let pageCount = 0;
  let processed = 0;
  let failed = 0;

  while (startIndex < total) {
    const url = new URL(NVD_BASE);
    url.searchParams.set('startIndex', String(startIndex));
    url.searchParams.set('resultsPerPage', String(RESULTS_PER_PAGE));

    let body: NvdCveResponse;
    try {
      const res = await fetchWithRetry(url.toString(), apiKey);
      body = (await res.json()) as NvdCveResponse;
    } catch (err) {
      console.error(`[backfill] Page fetch failed at startIndex=${startIndex}:`, err);
      // Save checkpoint and abort — restart will retry this page
      await saveCheckpoint(env, { startIndex, totalResults: total, ts: Date.now() });
      throw err;
    }

    total = body.totalResults;
    pageCount++;

    console.log(
      `[backfill] Page ${pageCount}: records ${startIndex}–${Math.min(startIndex + body.resultsPerPage, total) - 1} / ${total}`,
    );

    for (const { cve } of body.vulnerabilities) {
      const record = normalizeNvdCve(cve);
      if (!record) continue;
      try {
        await processRecord(record, env, ctx);
        processed++;
      } catch (err) {
        console.error(`[backfill] processRecord failed for ${record.cveId}:`, err);
        failed++;
      }
    }

    startIndex += body.resultsPerPage;

    // Persist checkpoint after every page
    await saveCheckpoint(env, { startIndex, totalResults: total, ts: Date.now() });

    if (startIndex < total) await sleep(PAGE_DELAY_MS);
  }

  console.log(
    `[backfill] NVD pass complete. processed=${processed} failed=${failed} pages=${pageCount}`,
  );

  // Clear checkpoint — NVD pass done
  await env.CACHE.delete(CHECKPOINT_KEY);

  // ── KEV overlay ─────────────────────────────────────────────────────────────
  if (!process.env['SKIP_KEV']) {
    console.log('[backfill] Applying KEV overlay…');
    let kevOk = 0;
    let kevFail = 0;
    try {
      const patches = await fetchKevCatalog();
      for (const patch of patches) {
        try {
          await applyKevPatch(patch, env, ctx);
          kevOk++;
        } catch (err) {
          console.error(`[backfill] KEV patch failed for ${patch.cveId}:`, err);
          kevFail++;
        }
      }
      console.log(`[backfill] KEV overlay complete. applied=${kevOk} failed=${kevFail}`);
    } catch (err) {
      console.error('[backfill] KEV fetch failed:', err);
    }
  }

  // ── EPSS overlay ─────────────────────────────────────────────────────────────
  if (!process.env['SKIP_EPSS']) {
    console.log('[backfill] Applying EPSS overlay…');
    let epssOk = 0;
    let epssFail = 0;
    try {
      for await (const patch of fetchEpssCsv()) {
        try {
          await applyEpssPatch(patch, env, ctx);
          epssOk++;
        } catch (err) {
          console.error(`[backfill] EPSS patch failed for ${patch.cveId}:`, err);
          epssFail++;
        }
      }
      console.log(`[backfill] EPSS overlay complete. applied=${epssOk} failed=${epssFail}`);
    } catch (err) {
      console.error('[backfill] EPSS fetch failed:', err);
    }
  }

  console.log('[backfill] All passes complete.');
}

// ── Helpers ───────────────────────────────────────────────────────────────────

async function saveCheckpoint(env: Env, cp: BackfillCheckpoint): Promise<void> {
  await env.CACHE.put(CHECKPOINT_KEY, JSON.stringify(cp), { expirationTtl: 86_400 * 14 });
}

async function fetchWithRetry(url: string, apiKey: string, maxAttempts = 8): Promise<Response> {
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const res = await fetch(url, { headers: { apiKey, Accept: 'application/json' } });

    if (res.status === 429 || res.status === 503) {
      const retryAfter = parseInt(res.headers.get('Retry-After') ?? '30', 10);
      console.warn(`[backfill] Rate limited (${res.status}), waiting ${retryAfter}s…`);
      await sleep(retryAfter * 1_000);
      continue;
    }

    if (!res.ok) throw new Error(`NVD HTTP ${res.status} for ${url}`);
    return res;
  }
  throw new Error(`NVD API unreachable after ${maxAttempts} attempts`);
}

function normalizeNvdCve(cve: NvdCve): NormalizedCveRecord | null {
  const enDesc = cve.descriptions.find((d) => d.lang === 'en');
  if (!enDesc) return null;

  let cvss: NormalizedCveRecord['cvss'] = null;
  const m4 = cve.metrics?.cvssMetricV40?.[0];
  const m31 =
    cve.metrics?.cvssMetricV31?.find((m) => m.type === 'Primary') ??
    cve.metrics?.cvssMetricV31?.[0];

  if (m4) {
    cvss = {
      version: '4.0',
      vector: m4.cvssData.vectorString,
      base: m4.cvssData.baseScore,
      exploitability: null,
      impact: null,
    };
  } else if (m31) {
    cvss = {
      version: '3.1',
      vector: m31.cvssData.vectorString,
      base: m31.cvssData.baseScore,
      exploitability: m31.exploitabilityScore ?? null,
      impact: m31.impactScore ?? null,
    };
  }

  const severity = cvssToSeverity(cvss?.base ?? null, cvss?.version ?? null);

  const cwes: string[] = [];
  for (const w of cve.weaknesses ?? []) {
    for (const d of w.description) {
      if (d.lang === 'en' && d.value.startsWith('CWE-')) cwes.push(d.value);
    }
  }

  const cpeMatches: NvdCpeMatch[] = [];
  for (const config of cve.configurations ?? []) {
    extractCpeMatches(config.nodes ?? [], cpeMatches);
  }
  const cpes = cpeMatches.map(parseCpeMatch).filter((c): c is NormalizedCpe => c !== null);

  const references = (cve.references ?? []).map((r) => ({ url: r.url, tags: r.tags ?? [] }));

  return {
    cveId: cve.id,
    publishedAt: new Date(cve.published).getTime(),
    lastModifiedAt: new Date(cve.lastModified).getTime(),
    description: enDesc.value,
    cvss,
    severity,
    source: 'NVD',
    cwes: [...new Set(cwes)],
    cpes,
    references,
  };
}

function extractCpeMatches(nodes: NvdNode[], acc: NvdCpeMatch[]): void {
  for (const node of nodes) {
    if (node.cpeMatch) acc.push(...node.cpeMatch);
    if (node.nodes) extractCpeMatches(node.nodes, acc);
  }
}

function parseCpeMatch(match: NvdCpeMatch): NormalizedCpe | null {
  const parts = match.criteria.split(':');
  if (parts.length < 6 || parts[0] !== 'cpe' || parts[1] !== '2.3') return null;
  const rawPart = parts[2] ?? '*';
  const vendor = decodeCpe(parts[3] ?? '*');
  const product = decodeCpe(parts[4] ?? '*');
  const version = parts[5] === '*' || parts[5] === '-' ? null : decodeCpe(parts[5] ?? '');
  return {
    cpeUri: match.criteria,
    part: rawPart === 'a' || rawPart === 'o' || rawPart === 'h' ? rawPart : null,
    vendor,
    product,
    version,
    ...(match.versionStartIncluding !== undefined && {
      versionStartIncluding: match.versionStartIncluding,
    }),
    ...(match.versionStartExcluding !== undefined && {
      versionStartExcluding: match.versionStartExcluding,
    }),
    ...(match.versionEndIncluding !== undefined && {
      versionEndIncluding: match.versionEndIncluding,
    }),
    ...(match.versionEndExcluding !== undefined && {
      versionEndExcluding: match.versionEndExcluding,
    }),
    vulnerable: match.vulnerable,
    extras: {},
  };
}

function decodeCpe(s: string): string {
  return s.replace(/%([0-9A-Fa-f]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
}

function cvssToSeverity(base: number | null, version: string | null): Severity {
  if (base === null) return 'NONE';
  if (base === 0) return 'NONE';
  if (base < 4.0) return 'LOW';
  if (base < 7.0) return 'MEDIUM';
  if (base < 9.0) return 'HIGH';
  return 'CRITICAL';
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function buildMockCtx(): ExecutionContext {
  return {
    waitUntil: (p: Promise<unknown>) => {
      p.catch(() => {});
    },
    passThroughOnException: () => {},
  } as ExecutionContext;
}
