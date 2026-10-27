import type { NormalizedCveRecord } from '@threat-lens/contracts';

/** sha-256 of description + sorted-CWEs + sorted-top-5-vendors. Changes when core content changes. */
export async function computeTextHash(record: NormalizedCveRecord): Promise<string> {
  const topVendors = [...new Set(record.cpes.map(c => c.vendor))].sort().slice(0, 5);
  const raw = [
    record.description,
    record.cwes.slice().sort().join(','),
    topVendors.join(','),
  ].join('|');
  return sha256hex(raw);
}

/** sha-256 of severity + cvss_base + kev_listed + epss_score + top_vendor. Changes when risk posture changes. */
export async function computeStateHash(
  severity: string,
  cvssBase: number | null,
  kevListed: boolean,
  epssScore: number | null,
  topVendor: string | null,
): Promise<string> {
  const raw = [
    severity,
    cvssBase != null ? cvssBase.toFixed(1) : 'null',
    kevListed ? '1' : '0',
    epssScore != null ? epssScore.toFixed(4) : 'null',
    topVendor ?? 'null',
  ].join('|');
  return sha256hex(raw);
}

async function sha256hex(text: string): Promise<string> {
  const data = new TextEncoder().encode(text);
  const buf = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}
