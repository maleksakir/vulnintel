import type { EpssPatch } from '@threat-lens/contracts';

const EPSS_CSV_URL = 'https://epss.cyentia.com/epss_scores-current.csv.gz';

/**
 * Fetches the FIRST EPSS daily CSV (gzip-compressed) and yields EpssPatch records.
 * The CSV header line is: #model_version:...,score_date:YYYY-MM-DDTHH:MM:SS+0000
 * Column header line is:  cve,epss,percentile
 * Data lines are:         CVE-YYYY-NNNNN,0.97343,0.99993
 *
 * Uses WHATWG DecompressionStream (available in Cloudflare Workers runtime).
 */
export async function* fetchEpssCsv(): AsyncGenerator<EpssPatch> {
  const res = await fetch(EPSS_CSV_URL, {
    headers: { Accept: 'application/octet-stream' },
  });

  if (!res.ok) throw new Error(`EPSS fetch failed: HTTP ${res.status}`);
  if (!res.body) throw new Error('EPSS response has no body');

  const updatedAt = parseScoreDate(res.headers.get('Last-Modified'));
  const decompressed = res.body.pipeThrough(new DecompressionStream('gzip'));
  const reader = decompressed.getReader();
  const decoder = new TextDecoder('utf-8');

  let remainder = '';
  let scoreDate: number | null = null;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    remainder += decoder.decode(value, { stream: true });
    const lines = remainder.split('\n');
    remainder = lines.pop() ?? '';

    for (const line of lines) {
      if (!line) continue;

      // #model_version:...,score_date:2024-01-01T00:00:00+0000
      if (line.startsWith('#')) {
        const m = /score_date:(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})/.exec(line);
        if (m?.[1]) scoreDate = new Date(m[1] + 'Z').getTime();
        continue;
      }

      // skip column header
      if (line.startsWith('cve,')) continue;

      const cols = line.split(',');
      const cveId = cols[0]?.trim();
      const epssScore = parseFloat(cols[1] ?? '');
      const epssPercentile = parseFloat(cols[2] ?? '');

      if (!cveId?.startsWith('CVE-') || isNaN(epssScore) || isNaN(epssPercentile)) continue;

      yield {
        cveId,
        epssScore,
        epssPercentile,
        epssUpdatedAt: scoreDate ?? updatedAt,
      };
    }
  }

  // flush any remaining partial line
  if (remainder.trim() && remainder.startsWith('CVE-')) {
    const cols = remainder.split(',');
    const cveId = cols[0]?.trim();
    const epssScore = parseFloat(cols[1] ?? '');
    const epssPercentile = parseFloat(cols[2] ?? '');
    if (cveId?.startsWith('CVE-') && !isNaN(epssScore) && !isNaN(epssPercentile)) {
      yield {
        cveId,
        epssScore,
        epssPercentile,
        epssUpdatedAt: scoreDate ?? updatedAt,
      };
    }
  }
}

function parseScoreDate(header: string | null): number {
  if (!header) return Date.now();
  const d = new Date(header);
  return isNaN(d.getTime()) ? Date.now() : d.getTime();
}
