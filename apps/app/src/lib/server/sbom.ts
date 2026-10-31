import type { AssetComponentInput } from '@threat-lens/contracts';

// CycloneDX SBOM parsing + PURL handling. Pure, no I/O — the actual matching
// against cve_osv_affected / cpe lives in assetMutations.ts.

// Bound a single import. This is the hard ceiling on the work importSbom does
// in one request; see that function's query-budget comment for how 500
// components maps to a bounded D1 query count under the 50-per-invocation cap.
export const MAX_SBOM_COMPONENTS = 500;

/**
 * purl type → OSV ecosystem string, EXACTLY as OSV publishes it (and as
 * `cve_osv_affected.ecosystem` stores it — `osvPatch.ts` writes
 * `pkg.ecosystem` raw). These are case-sensitive on OSV's side ('Maven',
 * 'PyPI', 'crates.io'), so a lowercased purl type can never equal them
 * directly — this map is what makes PURL matching actually work against
 * ingested data. Mirrors adapters/osv.ts's OSV_ECOSYSTEM_DIRS.
 */
const PURL_TYPE_TO_OSV_ECOSYSTEM: Record<string, string> = {
  npm: 'npm',
  pypi: 'PyPI',
  maven: 'Maven',
  golang: 'Go',
  cargo: 'crates.io',
  composer: 'Packagist',
  nuget: 'NuGet',
  gem: 'RubyGems',
};

/** The OSV ecosystem for a purl type, or null when OSV doesn't cover it. */
export function osvEcosystemForPurlType(purlType: string): string | null {
  return PURL_TYPE_TO_OSV_ECOSYSTEM[purlType.toLowerCase()] ?? null;
}

/**
 * The package name as OSV stores it for this ecosystem, which is NOT always
 * the bare purl name:
 *   - Maven:  groupId:artifactId   (purl namespace + ':' + name)
 *   - npm:    @scope/name          (purl namespace + '/' + name)
 *   - Go:     full module path     (purl namespace + '/' + name)
 *   - others: the bare name
 */
export function osvPackageName(purlType: string, namespace: string | null, name: string): string {
  if (namespace === null || namespace.length === 0) return name;
  switch (purlType.toLowerCase()) {
    case 'maven':
      return `${namespace}:${name}`;
    case 'npm':
    case 'golang':
      return `${namespace}/${name}`;
    default:
      return name;
  }
}

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

    // CPE identity comes ONLY from an explicit `cpe` field on the component,
    // never guessed from the purl. A purl namespace is a groupId/scope
    // ('org.apache.logging.log4j', '@babel') and never equals NVD's CPE vendor
    // ('apache'), so guessing produced either zero matches or — worse, if
    // matched loosely on product alone — cross-vendor false positives. A
    // component with neither a usable purl nor an explicit CPE simply doesn't
    // match, which is the honest outcome.
    const cpe = typeof c.cpe === 'string' ? parseCpe23(c.cpe) : null;

    // `ecosystem` stores the OSV ecosystem string (OSV's exact casing), not
    // the lowercased purl type, because that's what cve_osv_affected holds.
    out.push({
      name: c.name,
      version,
      purl,
      ecosystem: parsed ? osvEcosystemForPurlType(parsed.ecosystem) : null,
      cpeVendor: cpe?.vendor ?? null,
      cpeProduct: cpe?.product ?? null,
    });
  }

  return { ok: true, components: out, skipped };
}

/**
 * Parse the vendor/product out of a CPE 2.3 formatted-string URI:
 *   cpe:2.3:part:vendor:product:version:...
 * Returns null for anything that isn't a cpe:2.3 string with both fields
 * present. Lowercased to match NVD's normalization of `cpe.vendor`/`product`.
 */
export function parseCpe23(cpe: string): { vendor: string; product: string } | null {
  if (!cpe.startsWith('cpe:2.3:')) return null;
  // Split on unescaped colons. CPE escapes literal colons as '\:'.
  const parts = cpe.split(/(?<!\\):/);
  // [cpe, 2.3, part, vendor, product, ...]
  const vendor = parts[3];
  const product = parts[4];
  if (!vendor || !product || vendor === '*' || product === '*') return null;
  return {
    vendor: vendor.replace(/\\/g, '').toLowerCase(),
    product: product.replace(/\\/g, '').toLowerCase(),
  };
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
