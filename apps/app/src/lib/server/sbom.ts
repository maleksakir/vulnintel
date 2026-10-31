import type { AssetComponentInput } from '@threat-lens/contracts';

// CycloneDX SBOM parsing + PURL handling. Pure, no I/O — the actual matching
// against cve_osv_affected / cpe lives in assetMutations.ts.

// Bound a single import so a pathological SBOM can't blow the request budget
// (component count drives per-component match work downstream).
export const MAX_SBOM_COMPONENTS = 2000;

interface CycloneDxComponent {
  name?: unknown;
  version?: unknown;
  purl?: unknown;
  type?: unknown;
  cpe?: unknown;
}

interface CycloneDxBom {
  bomFormat?: unknown;
  specVersion?: unknown;
  components?: unknown;
}

export interface ParsedSbom {
  ok: boolean;
  error?: string;
  components: AssetComponentInput[];
  /** Components present in the SBOM but unusable (no name) — counted, skipped. */
  skipped: number;
}

/**
 * Parse a CycloneDX JSON BOM into storable components. Accepts the minimal
 * valid shape (`bomFormat: "CycloneDX"` + a `components` array); tolerates
 * missing optional fields per-component. SPDX is intentionally out of scope
 * for v1 (CycloneDX is the format Dependency-Track/most CI tooling emits by
 * default, and the one the roadmap named).
 */
export function parseCycloneDxSbom(raw: unknown): ParsedSbom {
  if (typeof raw !== 'object' || raw === null) {
    return { ok: false, error: 'Body is not a JSON object', components: [], skipped: 0 };
  }
  const bom = raw as CycloneDxBom;
  if (bom.bomFormat !== 'CycloneDX') {
    return {
      ok: false,
      error: 'Not a CycloneDX SBOM (bomFormat must be "CycloneDX")',
      components: [],
      skipped: 0,
    };
  }
  if (!Array.isArray(bom.components)) {
    return { ok: false, error: 'SBOM has no components array', components: [], skipped: 0 };
  }

  const out: AssetComponentInput[] = [];
  let skipped = 0;

  for (const c of bom.components as CycloneDxComponent[]) {
    if (out.length >= MAX_SBOM_COMPONENTS) {
      // Remaining components beyond the cap are counted as skipped.
      skipped++;
      continue;
    }
    if (typeof c !== 'object' || c === null || typeof c.name !== 'string' || c.name.length === 0) {
      skipped++;
      continue;
    }
    const purl = typeof c.purl === 'string' && c.purl.length > 0 ? c.purl : null;
    const version = typeof c.version === 'string' && c.version.length > 0 ? c.version : null;
    const parsed = purl ? parsePurl(purl) : null;

    // CPE fallback identity: prefer the parsed purl namespace/name; if the
    // component carries an explicit CPE, that's a stronger vendor/product
    // signal, but parsing a full CPE 2.3 URI is deferred — the purl-derived
    // vendor/product covers the common case and OS packages rarely carry a
    // purl anyway.
    out.push({
      name: c.name,
      version,
      purl,
      ecosystem: parsed?.ecosystem ?? null,
      cpeVendor: parsed?.vendor ?? null,
      cpeProduct: parsed?.product ?? null,
    });
  }

  return { ok: true, components: out, skipped };
}

export interface ParsedPurl {
  ecosystem: string; // npm, pypi, maven, golang, cargo, composer, nuget, gem, …
  namespace: string | null;
  name: string;
  version: string | null;
  /** Best-effort CPE vendor (lowercased): the purl namespace, or the name. */
  vendor: string;
  /** Best-effort CPE product (lowercased): the purl name. */
  product: string;
}

/**
 * Parse a package-url (purl-spec) string:
 *   pkg:<type>/<namespace>/<name>@<version>?<qualifiers>#<subpath>
 * Returns null if it isn't a well-formed `pkg:` URL. Lowercases ecosystem /
 * vendor / product to match NVD's cpe normalization (the CPE fallback path
 * compares case-sensitively against cpe.vendor/product).
 */
export function parsePurl(purl: string): ParsedPurl | null {
  if (!purl.startsWith('pkg:')) return null;
  // Strip scheme, then qualifiers (?) and subpath (#).
  let rest = purl.slice('pkg:'.length);
  const hashIdx = rest.indexOf('#');
  if (hashIdx >= 0) rest = rest.slice(0, hashIdx);
  const qIdx = rest.indexOf('?');
  if (qIdx >= 0) rest = rest.slice(0, qIdx);

  // Split off version (last @).
  let version: string | null = null;
  const atIdx = rest.lastIndexOf('@');
  if (atIdx >= 0) {
    version = decodeURIComponent(rest.slice(atIdx + 1));
    rest = rest.slice(0, atIdx);
  }

  // rest = type/[namespace/...]/name
  const parts = rest.split('/').filter((p) => p.length > 0);
  if (parts.length < 2) return null; // need at least type + name

  const ecosystem = parts[0]!.toLowerCase();
  const name = decodeURIComponent(parts[parts.length - 1]!);
  const namespaceParts = parts.slice(1, -1).map((p) => decodeURIComponent(p));
  const namespace = namespaceParts.length > 0 ? namespaceParts.join('/') : null;

  return {
    ecosystem,
    namespace,
    name,
    version,
    // Vendor: the namespace (e.g. the Maven groupId / npm scope) when present,
    // else the package name itself. Product: the package name.
    vendor: (namespace ?? name).toLowerCase(),
    product: name.toLowerCase(),
  };
}
