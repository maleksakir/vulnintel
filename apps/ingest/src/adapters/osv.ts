import type { OsvAffectedPackage, OsvPatch, OsvRange, OsvRangeEvent } from '@threat-lens/contracts';

/**
 * OSV.dev adapter. GHSA-scoped (8 ecosystem directories), CVE-alias-linked
 * only — see pipelines/osv.ts for the discovery/fetch orchestration that
 * uses these.
 *
 * OSV's REST query API (`/v1/query`, `/v1/querybatch`) is lookup-only, not a
 * delta feed — there is no "give me everything modified since X" endpoint
 * there. The actual delta source is the per-ecosystem GCS export
 * (`modified_id.csv`, newest-first); individual records are then fetched
 * one at a time from `/v1/vulns/{id}`. Verified directly against both
 * endpoints 2026-10-29 (see EXECUTION_PLAN.md — this replaces an earlier,
 * incorrect `/v1/querybatch`-based plan).
 */

/** The 8 OSV ecosystem directories this adapter scans (package-manager
 *  ecosystems only — OS/distro ecosystems like Debian/Alpine are out of
 *  scope for v1). Names are GCS bucket path segments — case-sensitive,
 *  exactly as OSV publishes them. */
export const OSV_ECOSYSTEM_DIRS = [
  'npm',
  'PyPI',
  'Maven',
  'Go',
  'crates.io',
  'Packagist',
  'NuGet',
  'RubyGems',
] as const;

export type OsvEcosystemDir = (typeof OSV_ECOSYSTEM_DIRS)[number];

/** GHSA-${4}-${4}-${4}, lowercase hex-ish base32. Also doubles as the
 *  defensive check against unsafe URL interpolation — every osv_id this
 *  adapter puts into a fetch() URL is validated against this first. */
export const OSV_ID_ALLOW = /^GHSA(-[0-9a-z]{4}){3}$/;

/** Plain CVE-NNNN-NNNN+ shape (NVD's own id format) — used to pick CVE
 *  aliases out of an OSV record's `aliases[]`. */
const CVE_ID_SHAPE = /^CVE-\d{4}-\d{4,}$/;

const OSV_GCS_BASE = 'https://storage.googleapis.com/osv-vulnerabilities';
const OSV_API_BASE = 'https://api.osv.dev';

/** Defensive cap on a single OSV record's response body — task-specified;
 *  real GHSA records are a few KB, this only guards against a pathological
 *  or corrupted response. Enforced via Content-Length (when present) AND a
 *  running byte count while streaming (Content-Length can be absent or
 *  wrong). */
const OSV_RECORD_MAX_BYTES = 1_000_000;

/** Row/write-size guards, mirroring processRecord.ts's cpes(500)/
 *  references(200) caps on NormalizedCveRecord. */
const OSV_MAX_AFFECTED = 50;
const OSV_MAX_EVENTS_PER_RANGE = 20;
/** Cap on a single affected-package entry's `ranges` array length, applied
 *  BEFORE normalizeRange/boundRangesJsonSize ever see it — mirrors the
 *  OSV_MAX_AFFECTED/OSV_MAX_EVENTS_PER_RANGE pattern at the ranges-array
 *  level. Bounds boundRangesJsonSize's input to a known constant regardless
 *  of how many ranges an upstream record claims, independent of (and in
 *  addition to) the byte-budget trim below — see that function's own
 *  comment for why both caps exist. */
const OSV_MAX_RANGES_PER_AFFECTED = 50;
/** Cap on a single affected-package entry's serialized `ranges` — this is
 *  what ends up in cve_osv_affected.ranges_json. */
const RANGES_JSON_MAX_BYTES = 8192;

interface OsvCsvEntry {
  osvId: string;
  ecosystemDir: OsvEcosystemDir;
  modified: string;
  modifiedMs: number;
}

/**
 * Streams `<dir>/modified_id.csv` ("<iso-timestamp>,<id>", newest-first)
 * from the top, yielding entries newer than `sinceMs`. Stops at the first
 * entry at-or-older than `sinceMs` (safe because the file is sorted
 * newest-first — nothing after that point can be newer) or after `maxLines`
 * entries, whichever comes first. `maxLines` is a pure safety backstop: in
 * steady state the sinceMs cutoff is hit almost immediately.
 */
export async function* fetchOsvModifiedSince(
  dir: OsvEcosystemDir,
  sinceMs: number,
  maxLines: number,
): AsyncGenerator<OsvCsvEntry> {
  const res = await fetch(`${OSV_GCS_BASE}/${dir}/modified_id.csv`, {
    headers: { Accept: 'text/csv' },
  });
  if (!res.ok) throw new Error(`OSV modified_id.csv fetch failed for ${dir}: HTTP ${res.status}`);
  if (!res.body) throw new Error(`OSV modified_id.csv response for ${dir} has no body`);

  const reader = res.body.getReader();
  const decoder = new TextDecoder('utf-8');
  let remainder = '';
  let yielded = 0;
  let stop = false;

  while (!stop) {
    const { done, value } = await reader.read();
    if (done) break;

    remainder += decoder.decode(value, { stream: true });
    const lines = remainder.split('\n');
    remainder = lines.pop() ?? '';

    for (const rawLine of lines) {
      const entry = parseOsvCsvLine(rawLine, dir);
      if (!entry) continue;
      if (entry.modifiedMs <= sinceMs || yielded >= maxLines) {
        stop = true;
        break;
      }
      yield entry;
      yielded++;
    }
  }

  if (!stop && yielded < maxLines) {
    const entry = parseOsvCsvLine(remainder, dir);
    if (entry && entry.modifiedMs > sinceMs) yield entry;
  }

  if (stop) {
    await reader.cancel().catch(() => {});
  }
}

function parseOsvCsvLine(line: string, dir: OsvEcosystemDir): OsvCsvEntry | null {
  const trimmed = line.trim();
  if (!trimmed) return null;

  const commaIdx = trimmed.indexOf(',');
  if (commaIdx < 0) return null;

  const modified = trimmed.slice(0, commaIdx).trim();
  const osvId = trimmed.slice(commaIdx + 1).trim();
  if (!modified || !osvId) return null;

  // Date.parse() truncates OSV's nanosecond-precision `modified` to ms —
  // safe here because this value is only ever used as an ordering/cursor
  // key, never for equality (equality uses the verbatim string elsewhere).
  const modifiedMs = Date.parse(modified);
  if (Number.isNaN(modifiedMs)) return null;

  return { osvId, ecosystemDir: dir, modified, modifiedMs };
}

/**
 * Fetches one OSV record. Returns the parsed JSON body, `null` on 404
 * (withdrawn/not found — a valid, expected outcome, not an error), and
 * throws on any other non-2xx or a body over the size cap.
 */
export async function fetchOsvRecord(osvId: string): Promise<unknown | null> {
  if (!OSV_ID_ALLOW.test(osvId)) {
    throw new Error(`fetchOsvRecord: refusing to fetch malformed OSV id: ${JSON.stringify(osvId)}`);
  }

  const res = await fetch(`${OSV_API_BASE}/v1/vulns/${osvId}`, {
    headers: { Accept: 'application/json' },
  });

  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`OSV API ${res.status} fetching ${osvId}`);

  const contentLength = res.headers.get('Content-Length');
  if (contentLength && Number(contentLength) > OSV_RECORD_MAX_BYTES) {
    throw new Error(
      `OSV record ${osvId} too large: Content-Length ${contentLength} bytes (cap ${OSV_RECORD_MAX_BYTES})`,
    );
  }
  if (!res.body) throw new Error(`OSV API response for ${osvId} has no body`);

  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > OSV_RECORD_MAX_BYTES) {
      await reader.cancel().catch(() => {});
      throw new Error(
        `OSV record ${osvId} exceeded ${OSV_RECORD_MAX_BYTES}-byte cap while streaming`,
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

  return JSON.parse(new TextDecoder('utf-8').decode(bytes));
}

/**
 * Pure normalizer: raw OSV JSON → OsvPatch, or `null` for a record that
 * doesn't even have the minimal shape this adapter needs (missing/invalid
 * `id` or `modified`) — a genuine parse failure, distinct from "no CVE
 * alias" (which is a valid OsvPatch with `cveIds: []`).
 */
export function normalizeOsvRecord(raw: unknown): OsvPatch | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const r = raw as Record<string, unknown>;

  const osvId = r.id;
  if (typeof osvId !== 'string' || !OSV_ID_ALLOW.test(osvId)) return null;

  const modified = r.modified;
  if (typeof modified !== 'string' || modified.length === 0) return null;

  const published = typeof r.published === 'string' ? r.published : null;
  const withdrawn = typeof r.withdrawn === 'string' && r.withdrawn.length > 0;

  const aliasesRaw = Array.isArray(r.aliases) ? r.aliases : [];
  const cveIds = [
    ...new Set(
      aliasesRaw.filter((a): a is string => typeof a === 'string' && CVE_ID_SHAPE.test(a)),
    ),
  ].sort();

  const affectedRaw = Array.isArray(r.affected) ? r.affected : [];
  const affected = affectedRaw
    .slice(0, OSV_MAX_AFFECTED)
    .map(normalizeAffectedEntry)
    .filter((a): a is OsvAffectedPackage => a !== null);

  return { osvId, modified, published, withdrawn, cveIds, affected };
}

function normalizeAffectedEntry(entry: unknown): OsvAffectedPackage | null {
  if (typeof entry !== 'object' || entry === null) return null;
  const e = entry as Record<string, unknown>;

  const pkg = e.package;
  if (typeof pkg !== 'object' || pkg === null) return null;
  const p = pkg as Record<string, unknown>;

  const ecosystem = typeof p.ecosystem === 'string' ? p.ecosystem : null;
  const name = typeof p.name === 'string' ? p.name : null;
  if (!ecosystem || !name) return null;
  const purl = typeof p.purl === 'string' ? p.purl : null;

  const rangesRaw = Array.isArray(e.ranges) ? e.ranges : [];
  const ranges = boundRangesJsonSize(
    rangesRaw
      .slice(0, OSV_MAX_RANGES_PER_AFFECTED)
      .map(normalizeRange)
      .filter((rg): rg is OsvRange => rg !== null),
  );

  const fixedVersions = [
    ...new Set(
      ranges.flatMap((rg) =>
        rg.events.filter((ev) => typeof ev.fixed === 'string').map((ev) => ev.fixed as string),
      ),
    ),
  ].sort();

  return { ecosystem, name, purl, ranges, fixedVersions };
}

const VALID_RANGE_TYPES = new Set(['SEMVER', 'ECOSYSTEM', 'GIT']);

function normalizeRange(raw: unknown): OsvRange | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const r = raw as Record<string, unknown>;

  const type = r.type;
  if (typeof type !== 'string' || !VALID_RANGE_TYPES.has(type)) return null;

  const eventsRaw = Array.isArray(r.events) ? r.events : [];
  const events = eventsRaw
    .slice(0, OSV_MAX_EVENTS_PER_RANGE)
    .map(normalizeEvent)
    .filter((ev): ev is OsvRangeEvent => ev !== null);

  const repo = typeof r.repo === 'string' ? r.repo : undefined;

  return { type: type as OsvRange['type'], ...(repo !== undefined && { repo }), events };
}

function normalizeEvent(raw: unknown): OsvRangeEvent | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const r = raw as Record<string, unknown>;

  const out: OsvRangeEvent = {};
  if (typeof r.introduced === 'string') out.introduced = r.introduced;
  if (typeof r.fixed === 'string') out.fixed = r.fixed;
  if (typeof r.last_affected === 'string') out.last_affected = r.last_affected;
  if (typeof r.limit === 'string') out.limit = r.limit;

  return Object.keys(out).length > 0 ? out : null;
}

/** Keeps the leading ranges (OSV's own ordering) that fit under
 *  RANGES_JSON_MAX_BYTES, dropping the first one that would push the
 *  running total over budget and everything after it.
 *
 *  O(n): each range is JSON.stringify'd exactly once and its byte cost
 *  accumulated into a running total — which also tracks the '[' + ']'
 *  brackets and inter-element commas a real `JSON.stringify(array)` call
 *  would add — instead of the previous approach, which re-ran
 *  `JSON.stringify` on the WHOLE remaining array on every trim iteration
 *  (O(n²); reproduced standalone: 1.2s at n=2000, ~20s at n=8000 of
 *  synchronous CPU, inside a single queue-consumer invocation processing a
 *  20-item batch). Because JSON.stringify(array) with no replacer/space
 *  argument never inserts whitespace, the accumulated running total is
 *  byte-for-byte the same number the old `byteLength(JSON.stringify(bounded))`
 *  would have computed for that same prefix, so this returns the identical
 *  result — the largest prefix (in OSV's given order) whose serialized form
 *  still fits — just without ever re-serializing already-counted elements.
 *
 *  rangesRaw is now also capped at OSV_MAX_RANGES_PER_AFFECTED before it
 *  reaches this function, and per-range event count is bounded by
 *  OSV_MAX_EVENTS_PER_RANGE, so in practice this rarely has to drop
 *  anything — it's a backstop against a pathological record whose
 *  individual ranges/events still add up to more bytes than expected. */
function boundRangesJsonSize(ranges: OsvRange[]): OsvRange[] {
  let total = 2; // '[' + ']'
  let count = 0;
  for (const range of ranges) {
    const cost = byteLength(JSON.stringify(range)) + (count > 0 ? 1 : 0); // +1 inter-element comma
    if (total + cost > RANGES_JSON_MAX_BYTES) break;
    total += cost;
    count++;
  }
  return count === ranges.length ? ranges : ranges.slice(0, count);
}

function byteLength(s: string): number {
  return new TextEncoder().encode(s).length;
}
