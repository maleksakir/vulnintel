import type { AssetComponentInput, SbomImportResult } from '@threat-lens/contracts';

// Asset write-side: create assets and import SBOMs. The import does the
// PURL-first / CPE-fallback matching against already-ingested data
// (cve_osv_affected from OSV ingestion; cpe from NVD) — no external fetch, no
// cron dependency, so it's fully exercisable offline.

const WRITE_SUB_BATCH = 100;
// Cap CVE matches materialized per component so one very-common package can't
// blow the import's work budget (the full set is still queryable live if ever
// needed; this bounds what gets persisted per component).
const MAX_MATCHES_PER_COMPONENT = 200;

export async function createAsset(
  db: D1Database,
  name: string,
  description: string | undefined,
): Promise<number> {
  const now = Date.now();
  const row = await db
    .prepare(
      `INSERT INTO asset (name, description, created_at, updated_at)
       VALUES (?, ?, ?, ?) RETURNING asset_id`,
    )
    .bind(name, description ?? null, now, now)
    .first<{ asset_id: number }>();
  if (!row) throw new Error('asset insert returned no id');
  return row.asset_id;
}

export async function assetExists(db: D1Database, assetId: number): Promise<boolean> {
  const row = await db
    .prepare(`SELECT 1 AS x FROM asset WHERE asset_id = ?`)
    .bind(assetId)
    .first<{ x: number }>();
  return row !== null;
}

export async function deleteAsset(db: D1Database, assetId: number): Promise<boolean> {
  const res = await db.prepare(`DELETE FROM asset WHERE asset_id = ?`).bind(assetId).run();
  return (res.meta.changes ?? 0) > 0;
}

/**
 * Replace an asset's components with a freshly-parsed SBOM and re-match every
 * component to CVEs. Idempotent: re-importing the same SBOM yields the same
 * state (components + matches are rebuilt from scratch for the asset).
 *
 * Matching per component:
 *   1. PURL (primary): join cve_osv_affected on purl OR (ecosystem + package
 *      name). OSV ingestion populates that table with the GHSA→CVE links.
 *   2. CPE (fallback): if no PURL matches (or no purl), match the derived
 *      cpe_vendor/cpe_product against the cpe table.
 *
 * Work is bounded: components are capped at import time (parseCycloneDxSbom),
 * matches per component capped at MAX_MATCHES_PER_COMPONENT, writes batched.
 */
export async function importSbom(
  db: D1Database,
  assetId: number,
  components: AssetComponentInput[],
  skipped: number,
): Promise<SbomImportResult> {
  const now = Date.now();

  // Replace the asset's components: clear old (CASCADE clears matches), then
  // insert new. Done first so matching runs against the just-stored rows.
  await db.prepare(`DELETE FROM asset_component WHERE asset_id = ?`).bind(assetId).run();

  // Insert components in batches, collecting their new ids by index.
  const insertedIds: number[] = [];
  for (const c of components) {
    const row = await db
      .prepare(
        `INSERT INTO asset_component
           (asset_id, name, version, purl, ecosystem, cpe_vendor, cpe_product, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING component_id`,
      )
      .bind(assetId, c.name, c.version, c.purl, c.ecosystem, c.cpeVendor, c.cpeProduct, now)
      .first<{ component_id: number }>();
    if (row) insertedIds.push(row.component_id);
  }

  // Match each component. To stay bounded we do one PURL query + one CPE query
  // per component (both indexed), each LIMITed. For a typical SBOM (tens to a
  // few hundred components) this is well within a request's budget; the
  // MAX_SBOM_COMPONENTS cap at parse time is the hard ceiling.
  let matchesFound = 0;
  const matchRows: Array<{ componentId: number; cveId: string; via: 'PURL' | 'CPE' }> = [];

  for (let i = 0; i < components.length; i++) {
    const c = components[i]!;
    const componentId = insertedIds[i];
    if (componentId === undefined) continue;

    const seen = new Set<string>();

    // 1. PURL-primary: match against cve_osv_affected.
    if (c.purl !== null || c.ecosystem !== null) {
      const osvRes = await db
        .prepare(
          `SELECT DISTINCT cve_id FROM cve_osv_affected
           WHERE purl = ? OR (ecosystem = ? AND package_name = ?)
           LIMIT ?`,
        )
        .bind(c.purl, c.ecosystem, c.cpeProduct, MAX_MATCHES_PER_COMPONENT)
        .all<{ cve_id: string }>();
      for (const r of osvRes.results) {
        if (!seen.has(r.cve_id)) {
          seen.add(r.cve_id);
          matchRows.push({ componentId, cveId: r.cve_id, via: 'PURL' });
        }
      }
    }

    // 2. CPE fallback: only if PURL found nothing and we have vendor/product.
    if (seen.size === 0 && c.cpeVendor !== null && c.cpeProduct !== null) {
      const cpeRes = await db
        .prepare(
          `SELECT DISTINCT cve_id FROM cpe
           WHERE vendor = ? AND product = ?
           LIMIT ?`,
        )
        .bind(c.cpeVendor, c.cpeProduct, MAX_MATCHES_PER_COMPONENT)
        .all<{ cve_id: string }>();
      for (const r of cpeRes.results) {
        if (!seen.has(r.cve_id)) {
          seen.add(r.cve_id);
          matchRows.push({ componentId, cveId: r.cve_id, via: 'CPE' });
        }
      }
    }
  }

  // Batched insert of matches.
  for (let i = 0; i < matchRows.length; i += WRITE_SUB_BATCH) {
    const chunk = matchRows.slice(i, i + WRITE_SUB_BATCH);
    await db.batch(
      chunk.map((m) =>
        db
          .prepare(
            `INSERT INTO asset_component_match (component_id, cve_id, match_via, first_matched_at)
             VALUES (?, ?, ?, ?)
             ON CONFLICT (component_id, cve_id) DO NOTHING`,
          )
          .bind(m.componentId, m.cveId, m.via, now),
      ),
    );
    matchesFound += chunk.length;
  }

  // Stamp the asset's import metadata.
  await db
    .prepare(
      `UPDATE asset SET last_import_at = ?, last_component_count = ?, updated_at = ?
       WHERE asset_id = ?`,
    )
    .bind(now, components.length, now, assetId)
    .run();

  return {
    componentsImported: components.length,
    componentsSkipped: skipped,
    matchesFound,
  };
}
