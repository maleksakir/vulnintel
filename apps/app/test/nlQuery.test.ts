import { describe, expect, it } from 'vitest';
import { looksNaturalLanguage } from '../src/lib/server/nlQuery';

// Pure gate that decides whether a query is worth an AI parse — no AI call.

describe('looksNaturalLanguage', () => {
  it('accepts a multi-word query with a cue word', () => {
    expect(looksNaturalLanguage('critical apache rce from 2024')).toBe(true);
    expect(looksNaturalLanguage('actively exploited microsoft flaws')).toBe(true);
    expect(looksNaturalLanguage('remote code execution in nginx')).toBe(true);
  });

  it('rejects a bare keyword (no cue, too short)', () => {
    expect(looksNaturalLanguage('log4j')).toBe(false);
    expect(looksNaturalLanguage('xml')).toBe(false);
  });

  it('rejects an exact CVE id', () => {
    expect(looksNaturalLanguage('CVE-2021-44228')).toBe(false);
  });

  it('rejects a short multi-word query with no cue', () => {
    expect(looksNaturalLanguage('xml parser')).toBe(false);
  });

  it('accepts a year-bearing query', () => {
    expect(looksNaturalLanguage('spring vulnerabilities 2023')).toBe(true);
  });
});
