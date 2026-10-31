import { describe, expect, it } from 'vitest';
import { parseCycloneDxSbom, parsePurl } from '../src/lib/server/sbom';

// Pure CycloneDX/PURL parsing — no bindings, no I/O.

describe('parsePurl', () => {
  it('parses a scoped npm purl', () => {
    const p = parsePurl('pkg:npm/%40babel/core@7.21.0');
    expect(p).not.toBeNull();
    expect(p!.ecosystem).toBe('npm');
    expect(p!.namespace).toBe('@babel');
    expect(p!.name).toBe('core');
    expect(p!.version).toBe('7.21.0');
    expect(p!.vendor).toBe('@babel');
    expect(p!.product).toBe('core');
  });

  it('parses a maven purl with a group namespace', () => {
    const p = parsePurl('pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1');
    expect(p!.ecosystem).toBe('maven');
    expect(p!.namespace).toBe('org.apache.logging.log4j');
    expect(p!.product).toBe('log4j-core');
    expect(p!.version).toBe('2.14.1');
  });

  it('parses a namespaceless pypi purl', () => {
    const p = parsePurl('pkg:pypi/django@4.2.1');
    expect(p!.namespace).toBeNull();
    expect(p!.name).toBe('django');
    expect(p!.vendor).toBe('django'); // falls back to name when no namespace
  });

  it('strips qualifiers and subpath', () => {
    const p = parsePurl('pkg:golang/github.com/gin-gonic/gin@v1.9.0?type=module#subdir');
    expect(p!.ecosystem).toBe('golang');
    expect(p!.name).toBe('gin');
    expect(p!.version).toBe('v1.9.0');
  });

  it('lowercases ecosystem/vendor/product', () => {
    const p = parsePurl('pkg:NuGet/Newtonsoft.Json@13.0.1');
    expect(p!.ecosystem).toBe('nuget');
    expect(p!.product).toBe('newtonsoft.json');
  });

  it('returns null for a non-purl string', () => {
    expect(parsePurl('not-a-purl')).toBeNull();
    expect(parsePurl('pkg:npm')).toBeNull(); // no name
  });
});

describe('parseCycloneDxSbom', () => {
  it('rejects non-CycloneDX input', () => {
    expect(parseCycloneDxSbom({ bomFormat: 'SPDX' }).ok).toBe(false);
    expect(parseCycloneDxSbom('string').ok).toBe(false);
    expect(parseCycloneDxSbom({ bomFormat: 'CycloneDX' }).ok).toBe(false); // no components array
  });

  it('parses a minimal valid BOM and derives ecosystem/vendor/product from purls', () => {
    const sbom = {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      version: 1,
      components: [
        {
          type: 'library',
          name: 'log4j-core',
          version: '2.14.1',
          purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
        },
        { type: 'library', name: 'django', version: '4.2.1', purl: 'pkg:pypi/django@4.2.1' },
      ],
    };
    const r = parseCycloneDxSbom(sbom);
    expect(r.ok).toBe(true);
    expect(r.components).toHaveLength(2);
    expect(r.components[0]).toMatchObject({
      name: 'log4j-core',
      version: '2.14.1',
      ecosystem: 'maven',
      cpeVendor: 'org.apache.logging.log4j',
      cpeProduct: 'log4j-core',
    });
    expect(r.components[1]!.ecosystem).toBe('pypi');
  });

  it('skips components with no name, counting them', () => {
    const r = parseCycloneDxSbom({
      bomFormat: 'CycloneDX',
      components: [
        { type: 'library', version: '1.0' },
        { name: 'ok', version: '1.0' },
      ],
    });
    expect(r.components).toHaveLength(1);
    expect(r.skipped).toBe(1);
  });

  it('handles a component with no purl (null identity fields)', () => {
    const r = parseCycloneDxSbom({
      bomFormat: 'CycloneDX',
      components: [{ type: 'application', name: 'my-app', version: '1.0' }],
    });
    expect(r.components[0]).toMatchObject({
      name: 'my-app',
      purl: null,
      ecosystem: null,
      cpeVendor: null,
    });
  });
});
