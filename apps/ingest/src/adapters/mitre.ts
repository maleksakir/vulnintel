/**
 * MITRE CWE gap-fill adapter.
 *
 * This file used to pull a full MITRE CVE delta from
 * `https://cveawg.mitre.org/api/cve` with `time_modified.start`/`.end`/
 * `pageSize`/`pageNumber` query params — that is MITRE's Secretariat/
 * Bulk-Download-only LIST endpoint, which returns HTTP 400 for ordinary
 * public callers (confirmed live 2026-10-30; it was never actually working
 * in production). It also fabricated synthetic CPE URIs
 * (`cpe:2.3:a:vendor:product:*:*...`) from bare vendor/product strings —
 * nothing like NVD's real CPE match data — and, because MITRE-sourced
 * records flowed through the same processRecord()/writeD1 path NVD's do,
 * writing them would have OVERWRITTEN NVD's superior description/CVSS/
 * severity/source and DELETE-then-REINSERTed cpe/cve_reference rows with
 * that inferior synthetic data, flipping text_hash back and forth between
 * the NVD- and MITRE-sourced hash on alternating days and triggering a
 * wasted re-embed + Vectorize upsert + KV delete on every such flip. See
 * docs/EXECUTION_PLAN.md's MITRE investigation (2026-10-30) for the full
 * analysis: a live-verified sample found NVD's own `weaknesses[]` field
 * (apps/ingest/src/adapters/nvd.ts) already surfaces essentially every CWE
 * MITRE's CNA+ADP containers carry — the one genuine, recoverable gap is a
 * CNA that wrote a CWE as free text in a description field (e.g. "CWE-79
 * Cross-Site Scripting (XSS)") with no structured `cweId` NVD could pick
 * up. This file now does ONLY that narrow lookup: fetch MITRE's PUBLIC
 * single-record endpoint (`GET /api/cve/{id}`, verified 2026-10-30 to need
 * no auth/special access) for one CVE ID at a time and extract any CWEs
 * from it — used from pipelines/mitreQueue.ts's consumer as a supplement,
 * never as a record source. See pipelines/daily.ts for how candidate CVE
 * IDs (NVD records with zero CWEs) are collected and handed off.
 */

const MITRE_SINGLE_RECORD_BASE = 'https://cveawg.mitre.org/api/cve';

/** Defensive cap on a single MITRE record's response body — task-specified;
 *  real CVE records are a few KB, this only guards against a pathological
 *  or corrupted response. Enforced via Content-Length (when present) AND a
 *  running byte count while streaming (Content-Length can be absent or
 *  wrong) — same pattern as adapters/osv.ts's fetchOsvRecord. */
const MITRE_RECORD_MAX_BYTES = 1_000_000;

/** MITRE's own real CVE IDs can have 6+ digit sequence numbers (e.g.
 *  CVE-2026-115274) — do not use a 4-digit-only pattern. Exported so
 *  pipelines/mitreQueue.ts can validate a dequeued message's CVE IDs
 *  BEFORE any of them is ever used to build a URL, same defensive
 *  reasoning as adapters/osv.ts's OSV_ID_ALLOW check inside
 *  fetchOsvRecord. */
export const CVE_ID_SHAPE = /^CVE-\d{4}-\d{4,}$/;

/** Defensive per-CVE cap on extracted CWEs — mirrors processRecord.ts's
 *  cpe(500)/reference(200) caps on NormalizedCveRecord and
 *  adapters/osv.ts's OSV_MAX_AFFECTED-style bounds: a guard against a
 *  pathological record, not an expected real-world count. */
const MITRE_CWES_MAX_PER_CVE = 10;

/** A structured `problemTypes[].descriptions[].cweId` value. Deliberately
 *  does NOT match MITRE's own "no info" sentinels (`CWE-noinfo`,
 *  `NVD-CWE-*`) — those aren't `CWE-<digits>` shaped, so they fail this
 *  test and are skipped without any separate exclusion list. */
const CWE_ID_STRUCTURED = /^CWE-\d+$/;

/** Free-text fallback: extracts a leading `CWE-<digits>` from a
 *  human-written description (e.g. "CWE-79 Cross-Site Scripting (XSS)").
 *  This is the entire point of this adapter — NVD's own parsing
 *  (adapters/nvd.ts) only reads structured `weaknesses[]` entries, never
 *  free text, so this is the one case it can't already cover. */
const CWE_ID_FREE_TEXT = /^CWE-(\d+)\b/;

export type MitreCweOutcome = 'OK' | 'NOT_FOUND' | 'REJECTED' | 'MALFORMED';

export interface MitreCweResult {
  cveId: string;
  outcome: MitreCweOutcome;
  /** Deduped, capped at MITRE_CWES_MAX_PER_CVE. Empty for every outcome
   *  except OK-with-at-least-one-recoverable-CWE. */
  cwes: string[];
}

/**
 * Fetches MITRE's public single-record endpoint for one CVE ID and
 * extracts any CWE ids from `containers.cna.problemTypes[].descriptions[]`
 * and every entry of `containers.adp[]` (if present) — same container
 * structure adapters/osv.ts already reads ADP-shaped data from.
 *
 * Returns a result object (never throws) for every outcome this path
 * considers "nothing to add, move on": HTTP 404 (CVE_RECORD_DNE) and a
 * REJECTED record state. Throws on anything else non-2xx (429/5xx) or a
 * response over the size cap — callers (pipelines/mitreQueue.ts) let that
 * propagate so the whole queue message gets retried, matching this
 * codebase's other queue consumers' retryable-vs-terminal distinction.
 */
export async function fetchMitreCweSupplement(cveId: string): Promise<MitreCweResult> {
  if (!CVE_ID_SHAPE.test(cveId)) {
    throw new Error(
      `fetchMitreCweSupplement: refusing to fetch malformed CVE id: ${JSON.stringify(cveId)}`,
    );
  }

  const res = await fetch(`${MITRE_SINGLE_RECORD_BASE}/${cveId}`, {
    headers: { Accept: 'application/json' },
  });

  if (res.status === 404) {
    return { cveId, outcome: 'NOT_FOUND', cwes: [] };
  }
  if (!res.ok) {
    // 429/5xx (or anything else unexpected) — retryable, let it propagate.
    throw new Error(`MITRE API ${res.status} fetching ${cveId}`);
  }

  const contentLength = res.headers.get('Content-Length');
  if (contentLength && Number(contentLength) > MITRE_RECORD_MAX_BYTES) {
    throw new Error(
      `MITRE record ${cveId} too large: Content-Length ${contentLength} bytes (cap ${MITRE_RECORD_MAX_BYTES})`,
    );
  }
  if (!res.body) throw new Error(`MITRE API response for ${cveId} has no body`);

  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MITRE_RECORD_MAX_BYTES) {
      await reader.cancel().catch(() => {});
      throw new Error(
        `MITRE record ${cveId} exceeded ${MITRE_RECORD_MAX_BYTES}-byte cap while streaming`,
      );
    }
    chunks.push(value);
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }

  const raw = JSON.parse(new TextDecoder('utf-8').decode(bytes));
  return normalizeMitreCweSupplement(cveId, raw);
}

/**
 * Pure normalizer: raw MITRE CVE JSON 5.0 body → MitreCweResult. Separated
 * from the fetch so it's independently testable, same split
 * adapters/osv.ts uses between fetchOsvRecord and normalizeOsvRecord.
 */
export function normalizeMitreCweSupplement(cveId: string, raw: unknown): MitreCweResult {
  if (typeof raw !== 'object' || raw === null) {
    return { cveId, outcome: 'MALFORMED', cwes: [] };
  }
  const rec = raw as Record<string, unknown>;

  const metadata = rec.cveMetadata;
  const state =
    typeof metadata === 'object' && metadata !== null
      ? (metadata as Record<string, unknown>).state
      : undefined;

  if (state === 'REJECTED') {
    return { cveId, outcome: 'REJECTED', cwes: [] };
  }

  const containers = rec.containers;
  const containersObj =
    typeof containers === 'object' && containers !== null
      ? (containers as Record<string, unknown>)
      : undefined;

  const cwes = new Set<string>();
  collectCwesFromContainer(containersObj?.cna, cwes);
  const adp = containersObj?.adp;
  if (Array.isArray(adp)) {
    for (const entry of adp) collectCwesFromContainer(entry, cwes);
  }

  return { cveId, outcome: 'OK', cwes: [...cwes].slice(0, MITRE_CWES_MAX_PER_CVE) };
}

function collectCwesFromContainer(container: unknown, out: Set<string>): void {
  if (typeof container !== 'object' || container === null) return;
  const c = container as Record<string, unknown>;
  const problemTypes = c.problemTypes;
  if (!Array.isArray(problemTypes)) return;

  for (const pt of problemTypes) {
    if (typeof pt !== 'object' || pt === null) continue;
    const descriptions = (pt as Record<string, unknown>).descriptions;
    if (!Array.isArray(descriptions)) continue;

    for (const d of descriptions) {
      if (typeof d !== 'object' || d === null) continue;
      const desc = d as Record<string, unknown>;

      // Prefer the structured cweId field when it's genuinely CWE-<digits>
      // shaped (CWE_ID_STRUCTURED already excludes 'CWE-noinfo' and
      // 'NVD-CWE-*' pseudo-IDs — neither is digits-only).
      const structured = desc.cweId;
      if (typeof structured === 'string' && CWE_ID_STRUCTURED.test(structured)) {
        out.add(structured);
        continue;
      }

      // Free-text fallback — the entire point of this adapter. Explicitly
      // ignore the known non-CWE sentinel values a `description` field can
      // hold when no real CWE was assigned, before attempting the regex.
      const text = desc.description;
      if (typeof text !== 'string') continue;
      if (text === 'CWE-noinfo' || text === 'n/a' || text.startsWith('NVD-CWE-')) continue;

      const match = text.match(CWE_ID_FREE_TEXT);
      if (match) out.add(`CWE-${match[1]}`);
    }
  }
}
