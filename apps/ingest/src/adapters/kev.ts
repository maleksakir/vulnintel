import type { KevPatch } from '@threat-lens/contracts';

const KEV_URL =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

interface KevCatalog {
  title: string;
  catalogVersion: string;
  dateReleased: string;
  count: number;
  vulnerabilities: KevEntry[];
}

interface KevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string; // 'YYYY-MM-DD'
  shortDescription: string;
  requiredAction: string;
  dueDate: string | null; // 'YYYY-MM-DD' or null
  knownRansomwareCampaignUse: string;
  notes: string;
}

/**
 * Fetches the full CISA KEV catalog and returns a KevPatch for every entry.
 * The KEV catalog is a complete snapshot — callers should apply each patch
 * with INSERT OR REPLACE / UPSERT semantics.
 */
export async function fetchKevCatalog(): Promise<KevPatch[]> {
  const res = await fetch(KEV_URL, {
    headers: { Accept: 'application/json' },
    // CF Workers will follow redirects by default.
  });

  if (!res.ok) throw new Error(`KEV fetch failed: HTTP ${res.status}`);

  const catalog = await res.json<KevCatalog>();

  return catalog.vulnerabilities.map((entry) => ({
    cveId: entry.cveID,
    kevDateAdded: parseKevDate(entry.dateAdded),
    kevDueDate: entry.dueDate ? parseKevDate(entry.dueDate) : null,
    kevRequiredAction: entry.requiredAction,
  }));
}

/** Parses 'YYYY-MM-DD' (UTC midnight) into unix ms. */
function parseKevDate(dateStr: string): number {
  return new Date(`${dateStr}T00:00:00.000Z`).getTime();
}
