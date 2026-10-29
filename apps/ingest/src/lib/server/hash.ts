import type { NormalizedCveRecord, OsvPatch } from '@threat-lens/contracts';

/** sha-256 of description + sorted-CWEs + sorted-top-5-vendors. Changes when core content changes. */
export async function computeTextHash(record: NormalizedCveRecord): Promise<string> {
  const topVendors = [...new Set(record.cpes.map((c) => c.vendor))].sort().slice(0, 5);
  const raw = [record.description, record.cwes.slice().sort().join(','), topVendors.join(',')].join(
    '|',
  );
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

/** sha-256 over {cveIds, withdrawn, affected sorted by ecosystem+name}.
 *  Deliberately excludes `modified`/description/references — OSV re-exports
 *  full snapshots, not deltas, so a record whose `modified` timestamp
 *  changed but whose actual CVE links/affected-package data didn't must not
 *  trigger a write (same skip-if-unchanged philosophy as computeTextHash/
 *  computeStateHash above). */
export async function computeOsvContentHash(
  patch: Pick<OsvPatch, 'cveIds' | 'withdrawn' | 'affected'>,
): Promise<string> {
  const sortedAffected = patch.affected
    .slice()
    .sort((a, b) => `${a.ecosystem}|${a.name}`.localeCompare(`${b.ecosystem}|${b.name}`));
  const raw = JSON.stringify({
    cveIds: patch.cveIds.slice().sort(),
    withdrawn: patch.withdrawn,
    affected: sortedAffected,
  });
  return sha256hex(raw);
}

async function sha256hex(text: string): Promise<string> {
  const data = new TextEncoder().encode(text);
  const buf = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
