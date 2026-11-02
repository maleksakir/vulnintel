import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { runAgingSweep } from '../src/pipelines/aging';
import { testEnv, useCleanBindings } from './helpers';

// Migration 0013: the cve_search trigger cost fix.
//
// `cve_search` is fts5(cve_id UNINDEXED, description). An FTS5 UNINDEXED
// column has no index, so the original triggers' `WHERE cve_id = ?` was a FULL
// SCAN of the FTS index — measured at 3,834 rows read per single-CVE write on
// production. The upsert in writeD1 assigns `description` unconditionally and
// SQLite's `AFTER UPDATE OF description` fires on ASSIGNMENT rather than on a
// value change, so that scan ran on every one of ~2,960 daily writes: ~11.3M
// rows/day against a 5M/day cap, from index maintenance alone. It is why
// ingestion could not finish a day.
//
// These tests pin the two behaviours that fix it. They assert through
// OBSERVABLE state (did cve_search change?) rather than by counting queries,
// because the trigger runs inside SQLite where no spy can reach it: a
// sentinel written directly into cve_search survives iff the trigger didn't
// fire.

const now = Date.now();
const TWENTY_SIX_MONTHS_MS = 26 * 30.44 * 24 * 60 * 60 * 1000;

async function seedCve(cveId: string, description: string, publishedAt = now): Promise<void> {
  await testEnv.DB.prepare(
    `INSERT INTO cve
       (cve_id, published_at, last_modified_at, description, severity, source,
        text_hash, state_hash, ingested_at)
     VALUES (?, ?, ?, ?, 'HIGH', 'NVD', 'h', 'h', ?)`,
  )
    .bind(cveId, publishedAt, publishedAt, description, now)
    .run();
}

async function ftsDescription(cveId: string): Promise<string | null> {
  const row = await testEnv.DB.prepare(`SELECT description FROM cve_search WHERE cve_id = ?`)
    .bind(cveId)
    .first<{ description: string }>();
  return row?.description ?? null;
}

describe('cve_search trigger cost (migration 0013)', () => {
  useCleanBindings();

  it('indexes a new CVE on insert', async () => {
    await seedCve('CVE-2026-9001', 'heap overflow in the parser');
    expect(await ftsDescription('CVE-2026-9001')).toBe('heap overflow in the parser');
  });

  it('does NOT touch the FTS index when the description is re-assigned unchanged', async () => {
    await seedCve('CVE-2026-9002', 'original text');

    // Sentinel: if the trigger fires, it overwrites this with 'original text'.
    await testEnv.DB.prepare(`UPDATE cve_search SET description = ? WHERE cve_id = ?`)
      .bind('SENTINEL', 'CVE-2026-9002')
      .run();

    // The shape writeD1's upsert produces: description assigned the value it
    // already holds, because the write was really caused by a severity /
    // CVSS / EPSS change.
    await testEnv.DB.prepare(
      `UPDATE cve SET description = 'original text', severity = 'CRITICAL' WHERE cve_id = ?`,
    )
      .bind('CVE-2026-9002')
      .run();

    expect(await ftsDescription('CVE-2026-9002')).toBe('SENTINEL');
  });

  it('DOES re-index when the description genuinely changes', async () => {
    await seedCve('CVE-2026-9003', 'first wording');
    await testEnv.DB.prepare(`UPDATE cve SET description = ? WHERE cve_id = ?`)
      .bind('second wording', 'CVE-2026-9003')
      .run();

    expect(await ftsDescription('CVE-2026-9003')).toBe('second wording');
    // And it is findable by the new words, not the old ones.
    const hit = await testEnv.DB.prepare(
      `SELECT cve_id FROM cve_search WHERE cve_search MATCH 'second'`,
    ).first<{ cve_id: string }>();
    expect(hit?.cve_id).toBe('CVE-2026-9003');
    const stale = await testEnv.DB.prepare(
      `SELECT cve_id FROM cve_search WHERE cve_search MATCH 'first'`,
    ).first<{ cve_id: string }>();
    expect(stale).toBeNull();
  });

  it('leaves no per-row delete trigger — the aging sweep owns FTS cleanup', async () => {
    // 0013 drops cve_fts_delete because it full-scanned the FTS index once per
    // deleted row, which is what had been killing the aging sweep mid-run.
    const triggers = await testEnv.DB.prepare(
      `SELECT name FROM sqlite_master WHERE type = 'trigger' AND name LIKE 'cve_fts%'
       ORDER BY name`,
    ).all<{ name: string }>();
    expect(triggers.results.map((t) => t.name)).toEqual(['cve_fts_insert', 'cve_fts_update']);
  });

  it('the aging sweep removes the FTS rows of the CVEs it deletes', async () => {
    const aged = now - TWENTY_SIX_MONTHS_MS;
    await seedCve('CVE-2023-9101', 'ancient advisory text', aged);
    await seedCve('CVE-2026-9102', 'current advisory text', now);
    expect(await ftsDescription('CVE-2023-9101')).not.toBeNull();

    const ctx = createExecutionContext();
    await runAgingSweep(testEnv, ctx);
    await waitOnExecutionContext(ctx);

    // Aged CVE and its search row both gone; the in-window one untouched.
    expect(await ftsDescription('CVE-2023-9101')).toBeNull();
    expect(await ftsDescription('CVE-2026-9102')).toBe('current advisory text');

    // No orphan left behind for search to surface either.
    const orphan = await testEnv.DB.prepare(
      `SELECT COUNT(*) AS n FROM cve_search WHERE cve_id = 'CVE-2023-9101'`,
    ).first<{ n: number }>();
    expect(orphan?.n).toBe(0);
  });
});
