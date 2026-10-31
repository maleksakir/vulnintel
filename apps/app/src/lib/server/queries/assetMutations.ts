import type { AssetComponentInput, SbomImportResult } from '@threat-lens/contracts';
import { osvPackageName, parsePurl } from '../sbom';

// Asset write-side: create assets and import SBOMs. The import does the
// PURL-first / CPE-fallback matching against already-ingested data
// (cve_osv_affected from OSV ingestion; cpe from NVD) — no external fetch, no
// cron dependency, so it's fully exercisable offline.

const WRITE_SUB_BATCH = 500;
// D1 binds at most 100 params per query.
const PARAM_CHUNK = 100;
// Half that for the CPE query, which binds a vendor set AND a product set.
const CPE_PAIR_CHUNK = 50;
// Per-component and whole-import match ceilings. These bound WRITE volume: the
// previous 2000 components x 200 matches/component was 400,000 rows from one
// request — 4x the entire 100k/day free-tier write quota.
const MAX_MATCHES_PER_COMPONENT = 25;
const MAX_TOTAL_MATCHES = 2000;
// Bound the CPE fallback's result set per chunk.
const CPE_ROW_LIMIT = 5000;

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

interface StoredComponent {
  component_id: number;
  version: string | null;
  purl: string | null;
  ecosystem: string | null;
  cpe_vendor: string | null;
  cpe_product: string | null;
}

interface OsvAffectedRow {
  cve_id: string;
  ecosystem: string;
  package_name: string;
  fixed_versions: string | null;
}

interface Candidate {
  componentId: number;
  version: string | null;
  osvEcosystem: string | null;
  osvName: string | null;
  cpeVendor: string | null;
  cpeProduct: string | null;
}

/**
 * Replace an asset's components with a freshly-parsed SBOM and re-match every
 * component to CVEs. Idempotent: re-importing the same SBOM yields the same
 * state.
 *
 * Matching is SET-BASED, not per-component. The previous version ran one
 * INSERT…RETURNING plus one or two SELECTs *per component*, which at the old
 * 2000-component cap was ~10,000 D1 queries against the Free plan's
 * 50-queries-per-invocation cap — the invocation was killed at the 50th
 * component, so any real SBOM failed, and because the component DELETE had
 * already committed the asset was left with a truncated inventory. This is
 * the same failure mode CLAUDE.md records four production incidents for.
 *
 * D1 query budget now, at MAX_SBOM_COMPONENTS = 500:
 *   1  batch  — DELETE + up to 500 component INSERTs (one db.batch = 1 query)
 *   1  read   — the stored components back (to get their ids)
 *   ≤5 reads  — PURL matching, chunked at 100 package names per query
 *   ≤10 reads — CPE fallback, chunked at 50 components (vendor+product sets)
 *   ≤4 batches— match inserts (MAX_TOTAL_MATCHES 2000 / 500 per batch)
 *   1  write  — the asset's import stamp
 *   ────────────────────────────────────────────────────────────────────────
 *   ~22 queries worst case, independent of how the 500 components distribute.
 *
 * Version awareness is PARTIAL: a component already on a version OSV lists in
 * `fixed_versions` is excluded, but `ranges_json` is not evaluated, so a match
 * means "this package is affected by this CVE", not "this exact version is".
 * The UI labels matches accordingly.
 */
export async function importSbom(
  db: D1Database,
  assetId: number,
  components: AssetComponentInput[],
  skipped: number,
): Promise<SbomImportResult> {
  const now = Date.now();

  // ── 1. Replace the component set ─────────────────────────────────────────
  // The DELETE rides in the SAME batch as the inserts so a failure can't
  // leave the asset's old components wiped with no new ones in their place.
  const insertStmts: D1PreparedStatement[] = [
    db.prepare(`DELETE FROM asset_component WHERE asset_id = ?`).bind(assetId),
  ];
  for (const c of components) {
    insertStmts.push(
      db
        .prepare(
          `INSERT INTO asset_component
             (asset_id, name, version, purl, ecosystem, cpe_vendor, cpe_product, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(assetId, c.name, c.version, c.purl, c.ecosystem, c.cpeVendor, c.cpeProduct, now),
    );
  }
  for (let i = 0; i < insertStmts.length; i += WRITE_SUB_BATCH) {
    await db.batch(insertStmts.slice(i, i + WRITE_SUB_BATCH));
  }

  // ── 2. Read the stored components back (one query) ───────────────────────
  const storedRes = await db
    .prepare(
      `SELECT component_id, version, purl, ecosystem, cpe_vendor, cpe_product
       FROM asset_component WHERE asset_id = ?`,
    )
    .bind(assetId)
    .all<StoredComponent>();
  const stored = storedRes.results;

  // Derive each component's OSV match key (ecosystem + OSV-shaped package
  // name) from its purl at match time, so fixing the derivation never needs a
  // migration.
  const candidates: Candidate[] = stored.map((s) => {
    const p = s.purl ? parsePurl(s.purl) : null;
    return {
      componentId: s.component_id,
      version: s.version,
      osvEcosystem: s.ecosystem,
      osvName: p ? osvPackageName(p.ecosystem, p.namespace, p.name) : null,
      cpeVendor: s.cpe_vendor,
      cpeProduct: s.cpe_product,
    };
  });

  const matchRows: Array<{ componentId: number; cveId: string; via: 'PURL' | 'CPE' }> = [];
  const perComponent = new Map<number, Set<string>>();

  const canTake = (componentId: number, cveId: string): boolean => {
    if (matchRows.length >= MAX_TOTAL_MATCHES) return false;
    let seen = perComponent.get(componentId);
    if (!seen) {
      seen = new Set();
      perComponent.set(componentId, seen);
    }
    if (seen.size >= MAX_MATCHES_PER_COMPONENT || seen.has(cveId)) return false;
    seen.add(cveId);
    return true;
  };

  // ── 3. PURL-primary matching (set-based) ─────────────────────────────────
  // One query per 100 package names. The ecosystem is compared in memory
  // against OSV's exact casing ('Maven', 'PyPI', 'crates.io') — comparing a
  // lowercased purl type in SQL, as this previously did, could only ever
  // match 'npm'.
  const purlCandidates = candidates.filter((c) => c.osvName !== null && c.osvEcosystem !== null);
  const byOsvKey = new Map<string, Candidate[]>();
  for (const c of purlCandidates) {
    const key = `${c.osvEcosystem}\u0000${c.osvName}`;
    const list = byOsvKey.get(key);
    if (list) list.push(c);
    else byOsvKey.set(key, [c]);
  }
  const osvNames = [...new Set(purlCandidates.map((c) => c.osvName as string))];

  for (let i = 0; i < osvNames.length; i += PARAM_CHUNK) {
    const chunk = osvNames.slice(i, i + PARAM_CHUNK);
    const placeholders = chunk.map(() => '?').join(',');
    const res = await db
      .prepare(
        `SELECT cve_id, ecosystem, package_name, fixed_versions
         FROM cve_osv_affected WHERE package_name IN (${placeholders})`,
      )
      .bind(...chunk)
      .all<OsvAffectedRow>();

    for (const r of res.results) {
      const targets = byOsvKey.get(`${r.ecosystem}\u0000${r.package_name}`);
      if (!targets) continue; // name matched, different ecosystem
      for (const c of targets) {
        // Already on a version OSV lists as fixed → not affected.
        if (isFixedVersion(c.version, r.fixed_versions)) continue;
        if (canTake(c.componentId, r.cve_id)) {
          matchRows.push({ componentId: c.componentId, cveId: r.cve_id, via: 'PURL' });
        }
      }
    }
  }

  // ── 4. CPE fallback (set-based) ──────────────────────────────────────────
  // Only for components that carried an EXPLICIT cpe in the SBOM and got no
  // PURL match. Binds vendor and product sets together so the (vendor,
  // product) index is used and the result stays selective; exact pairs are
  // filtered in memory.
  const cpeCandidates = candidates.filter(
    (c) =>
      c.cpeVendor !== null &&
      c.cpeProduct !== null &&
      (perComponent.get(c.componentId)?.size ?? 0) === 0,
  );
  const byCpePair = new Map<string, Candidate[]>();
  for (const c of cpeCandidates) {
    const key = `${c.cpeVendor}\u0000${c.cpeProduct}`;
    const list = byCpePair.get(key);
    if (list) list.push(c);
    else byCpePair.set(key, [c]);
  }

  for (let i = 0; i < cpeCandidates.length; i += CPE_PAIR_CHUNK) {
    const chunk = cpeCandidates.slice(i, i + CPE_PAIR_CHUNK);
    const vendors = [...new Set(chunk.map((c) => c.cpeVendor as string))];
    const products = [...new Set(chunk.map((c) => c.cpeProduct as string))];
    const vPlace = vendors.map(() => '?').join(',');
    const pPlace = products.map(() => '?').join(',');
    const res = await db
      .prepare(
        `SELECT DISTINCT cve_id, vendor, product FROM cpe
         WHERE vendor IN (${vPlace}) AND product IN (${pPlace})
         LIMIT ?`,
      )
      .bind(...vendors, ...products, CPE_ROW_LIMIT)
      .all<{ cve_id: string; vendor: string; product: string }>();

    for (const r of res.results) {
      const targets = byCpePair.get(`${r.vendor}\u0000${r.product}`);
      if (!targets) continue; // a cross-product pair we didn't ask for
      for (const c of targets) {
        if (canTake(c.componentId, r.cve_id)) {
          matchRows.push({ componentId: c.componentId, cveId: r.cve_id, via: 'CPE' });
        }
      }
    }
  }

  // ── 5. Persist matches + stamp the asset ─────────────────────────────────
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
  }

  await db
    .prepare(
      `UPDATE asset SET last_import_at = ?, last_component_count = ?, updated_at = ?
       WHERE asset_id = ?`,
    )
    .bind(now, stored.length, now, assetId)
    .run();

  return {
    componentsImported: stored.length,
    componentsSkipped: skipped,
    matchesFound: matchRows.length,
  };
}

/** True when the component's exact version appears in OSV's comma-joined
 *  fixed_versions list. The cheap, correct-direction half of version
 *  awareness; full range evaluation (ranges_json) is not implemented. */
function isFixedVersion(version: string | null, fixedVersions: string | null): boolean {
  if (version === null || fixedVersions === null) return false;
  return fixedVersions
    .split(',')
    .map((v) => v.trim())
    .some((v) => v.length > 0 && v === version);
}
