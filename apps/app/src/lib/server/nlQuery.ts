/**
 * Natural-language query parsing for /search.
 *
 * Turns a free-text query like "critical apache RCE from 2024" into a clean
 * semantic search string plus structured filters (severity, vendor, KEV,
 * minCvss, publishedSince) using a small Workers AI instruct model. The parsed
 * filters are MERGED with (never override) any explicit UI filters, and the
 * cleaned query feeds the existing FTS5 + vector pipeline.
 *
 * Budget + safety (same discipline as rerank.ts): Workers AI's ~10k neuron/day
 * allocation is account-wide and shared with ingest's embeddings. So this:
 *   - only runs when the query looks natural-language (has a filter-ish cue
 *     word), never on a bare keyword or a CVE id — most searches skip it;
 *   - is gated by the caller on the same pre-increment daily count rerank uses
 *     (no new counter);
 *   - has a short client timeout and NEVER throws — any failure returns null
 *     and search proceeds with the raw query exactly as before.
 */

/** Cheapest instruct model that reliably returns small JSON. */
export const NL_QUERY_MODEL = '@cf/meta/llama-3.2-3b-instruct' as const;

export const NL_QUERY_TIMEOUT_MS = 1200;
export const NL_QUERY_MAX_CHARS = 256;

export interface ParsedQuery {
  /** Cleaned search text (filter words stripped), or null to keep original. */
  query: string | null;
  severity: Array<'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE'>;
  vendor: string[];
  kev: boolean | null;
  minCvss: number | null;
  /** ISO date (YYYY-01-01 for a bare year), or null. */
  publishedSince: string | null;
}

const SEVERITIES = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE']);

// Cue words that suggest the query carries intent beyond bare keywords, so the
// NL parse is worth a neuron. A query with none of these (e.g. "log4j",
// "CVE-2021-44228", "xml parser") skips the LLM entirely.
const NL_CUES =
  /\b(critical|high|medium|low|severity|kev|exploited|actively|cvss|score|from|since|after|before|in\s+20\d\d|20\d\d|last\s+\w+|recent|vendor|by\s+\w+|rce|remote|privilege|overflow|injection|bypass|disclosure)\b/i;

/** True when the query is worth sending to the NL parser. */
export function looksNaturalLanguage(query: string): boolean {
  const q = query.trim();
  if (q.length < 8) return false; // too short to carry structure
  if (/^CVE-\d{4}-\d+$/i.test(q)) return false; // exact id
  // Multi-word AND at least one cue word.
  return q.split(/\s+/).length >= 2 && NL_CUES.test(q);
}

type NlAiLike = {
  run: (
    model: string,
    input: { messages: { role: string; content: string }[]; max_tokens?: number },
    options?: { signal?: AbortSignal; tags?: string[] },
  ) => Promise<{ response?: string }>;
};

const SYSTEM_PROMPT = `You convert a vulnerability search query into JSON filters. Output ONLY a JSON object, no prose. Schema:
{"query": string, "severity": string[], "vendor": string[], "kev": boolean|null, "minCvss": number|null, "publishedSince": string|null}
Rules:
- "query": the search text with filter words (severity, dates, vendor, "kev", "exploited") removed, keeping the core technical terms. If nothing meaningful remains, use "".
- "severity": any of CRITICAL,HIGH,MEDIUM,LOW,NONE mentioned (uppercase). "critical" -> ["CRITICAL"].
- "vendor": product/vendor names mentioned, lowercased (e.g. "apache","microsoft","cisco").
- "kev": true if "actively exploited"/"kev"/"in the wild" is implied, else null.
- "minCvss": a number 0-10 if a score threshold is implied (e.g. "cvss over 9" -> 9), else null.
- "publishedSince": ISO date. A bare year like "2024" -> "2024-01-01". "last year", relative terms -> null. Else null.
Example: "critical apache rce from 2024" -> {"query":"rce","severity":["CRITICAL"],"vendor":["apache"],"kev":null,"minCvss":null,"publishedSince":"2024-01-01"}`;

/** Safely coerce the model's JSON into a ParsedQuery. Returns null if the
 *  output isn't usable. */
function coerce(raw: string): ParsedQuery | null {
  // The model may wrap JSON in ```json fences or prose — extract the first {...}.
  const start = raw.indexOf('{');
  const end = raw.lastIndexOf('}');
  if (start < 0 || end <= start) return null;
  let obj: Record<string, unknown>;
  try {
    obj = JSON.parse(raw.slice(start, end + 1)) as Record<string, unknown>;
  } catch {
    return null;
  }

  const severity = Array.isArray(obj.severity)
    ? obj.severity
        .filter((s): s is string => typeof s === 'string')
        .map((s) => s.toUpperCase())
        .filter((s) => SEVERITIES.has(s))
    : [];
  const vendor = Array.isArray(obj.vendor)
    ? obj.vendor
        .filter((v): v is string => typeof v === 'string')
        .map((v) => v.trim().toLowerCase())
        .filter((v) => v.length > 0 && v.length <= 80)
        .slice(0, 5)
    : [];

  let minCvss: number | null = null;
  if (typeof obj.minCvss === 'number' && Number.isFinite(obj.minCvss)) {
    minCvss = Math.min(10, Math.max(0, obj.minCvss));
  }

  let publishedSince: string | null = null;
  if (typeof obj.publishedSince === 'string' && !Number.isNaN(Date.parse(obj.publishedSince))) {
    publishedSince = obj.publishedSince;
  }

  const query =
    typeof obj.query === 'string' ? obj.query.trim().slice(0, NL_QUERY_MAX_CHARS) || null : null;

  return {
    query,
    severity: severity as ParsedQuery['severity'],
    vendor,
    kev: obj.kev === true ? true : null,
    minCvss,
    publishedSince,
  };
}

/**
 * Parse a natural-language query into filters. Returns null on any failure or
 * timeout — never throws. The caller gates this on the shared daily budget.
 */
export async function parseNlQuery(ai: Ai, query: string): Promise<ParsedQuery | null> {
  const start = Date.now();
  try {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<'timeout'>((resolve) => {
      timer = setTimeout(() => {
        controller.abort();
        resolve('timeout');
      }, NL_QUERY_TIMEOUT_MS);
    });

    const call: Promise<{ response?: string } | 'error'> = (ai as NlAiLike)
      .run(
        NL_QUERY_MODEL,
        {
          messages: [
            { role: 'system', content: SYSTEM_PROMPT },
            { role: 'user', content: query.slice(0, NL_QUERY_MAX_CHARS) },
          ],
          max_tokens: 200,
        },
        { signal: controller.signal, tags: ['search-nlq'] },
      )
      .catch((): 'error' => 'error');

    const result = await Promise.race([call, timeout]);
    if (timer) clearTimeout(timer);

    const outcome = result === 'timeout' ? 'timeout' : result === 'error' ? 'error' : 'ok';
    if (result === 'timeout' || result === 'error') {
      console.log(JSON.stringify({ event: 'search-nlq', outcome, latencyMs: Date.now() - start }));
      return null;
    }

    const parsed = typeof result.response === 'string' ? coerce(result.response) : null;
    console.log(
      JSON.stringify({
        event: 'search-nlq',
        outcome: parsed ? 'ok' : 'malformed',
        latencyMs: Date.now() - start,
      }),
    );
    return parsed;
  } catch {
    console.log(
      JSON.stringify({ event: 'search-nlq', outcome: 'error', latencyMs: Date.now() - start }),
    );
    return null;
  }
}
