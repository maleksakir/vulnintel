import { createExecutionContext } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { reconcileWatchlistMatches } from '../src/lib/server/watchlistReconcile';
import { spyOnBindings, testEnv, useCleanBindings } from './helpers';

// Watchlist match reconciliation engine (lib/server/watchlistReconcile.ts),
// end to end against real local D1 — same convention as the other
// processRecord/applyKevPatchBatch suites.

async function seedCve(cveId: string, lastModifiedAt: number, severity = 'HIGH'): Promise<void> {
  await testEnv.DB.prepare(
    `INSERT INTO cve (cve_id, published_at, last_modified_at, description, severity, source,
                      text_hash, state_hash, ingested_at)
     VALUES (?, ?, ?, 'desc', ?, 'NVD', 'h', 'h', ?)`,
  )
    .bind(cveId, lastModifiedAt, lastModifiedAt, severity, lastModifiedAt)
    .run();
}

async function seedCpe(cveId: string, vendor: string, product: string): Promise<void> {
  await testEnv.DB.prepare(
    `INSERT INTO cpe (cve_id, cpe_uri, part, vendor, product)
     VALUES (?, ?, 'a', ?, ?)`,
  )
    .bind(cveId, `cpe:2.3:a:${vendor}:${product}:*:*:*:*:*:*:*:*`, vendor, product)
    .run();
}

async function createWatchlist(name: string): Promise<number> {
  const now = Date.now();
  const res = await testEnv.DB.prepare(
    `INSERT INTO watchlist (name, created_at, updated_at) VALUES (?, ?, ?) RETURNING watchlist_id`,
  )
    .bind(name, now, now)
    .first<{ watchlist_id: number }>();
  if (!res) throw new Error('failed to create watchlist');
  return res.watchlist_id;
}

async function subscribe(
  watchlistId: number,
  vendor: string,
  product: string | null,
): Promise<void> {
  await testEnv.DB.prepare(
    `INSERT INTO watchlist_subscription (watchlist_id, vendor, product, created_at)
     VALUES (?, ?, ?, ?)`,
  )
    .bind(watchlistId, vendor, product, Date.now())
    .run();
}

async function getMatches(watchlistId: number): Promise<Array<{ cve_id: string; status: string }>> {
  const res = await testEnv.DB.prepare(
    `SELECT cve_id, status FROM watchlist_match WHERE watchlist_id = ? ORDER BY cve_id`,
  )
    .bind(watchlistId)
    .all<{ cve_id: string; status: string }>();
  return res.results;
}

describe('reconcileWatchlistMatches', () => {
  useCleanBindings();

  it('no subscriptions: a true no-op for matching, but advances the cursor', async () => {
    const now = Date.now();
    await seedCve('CVE-2026-0001', now - 1000);
    await seedCpe('CVE-2026-0001', 'acme', 'widget');

    const result = await reconcileWatchlistMatches(testEnv, now);

    expect(result).toEqual({ cvesScanned: 0, matchesWritten: 0, cursorAdvancedToMs: now });
    const cursor = await testEnv.DB.prepare(
      `SELECT last_cursor_ms FROM watchlist_sync_state WHERE key = 'watchlist_match'`,
    ).first<{ last_cursor_ms: number }>();
    expect(cursor?.last_cursor_ms).toBe(now);
  });

  it('vendor+product subscription matches exactly that product, not siblings', async () => {
    const now = Date.now();
    const wl = await createWatchlist('exact');
    await subscribe(wl, 'acme', 'widget');

    // in window, matches
    await seedCve('CVE-2026-1001', now - 1000);
    await seedCpe('CVE-2026-1001', 'acme', 'widget');
    // same vendor, different product — must NOT match a vendor+product sub
    await seedCve('CVE-2026-1002', now - 1000);
    await seedCpe('CVE-2026-1002', 'acme', 'gadget');

    const result = await reconcileWatchlistMatches(testEnv, now);

    expect(result.matchesWritten).toBe(1);
    expect(await getMatches(wl)).toEqual([{ cve_id: 'CVE-2026-1001', status: 'NEW' }]);
  });

  it('vendor-only subscription (product NULL) matches every product for that vendor', async () => {
    const now = Date.now();
    const wl = await createWatchlist('vendor-wide');
    await subscribe(wl, 'acme', null);

    await seedCve('CVE-2026-2001', now - 1000);
    await seedCpe('CVE-2026-2001', 'acme', 'widget');
    await seedCve('CVE-2026-2002', now - 1000);
    await seedCpe('CVE-2026-2002', 'acme', 'gadget');
    // different vendor — not matched
    await seedCve('CVE-2026-2003', now - 1000);
    await seedCpe('CVE-2026-2003', 'globex', 'thing');

    await reconcileWatchlistMatches(testEnv, now);

    expect(await getMatches(wl)).toEqual([
      { cve_id: 'CVE-2026-2001', status: 'NEW' },
      { cve_id: 'CVE-2026-2002', status: 'NEW' },
    ]);
  });

  it('only scans CVEs modified since the cursor — older CVEs are ignored on the next run', async () => {
    const now = Date.now();
    const wl = await createWatchlist('incremental');
    await subscribe(wl, 'acme', null);

    // First run: one CVE modified just before `now`.
    await seedCve('CVE-2026-3001', now - 5000);
    await seedCpe('CVE-2026-3001', 'acme', 'widget');
    await reconcileWatchlistMatches(testEnv, now);
    expect((await getMatches(wl)).map((m) => m.cve_id)).toEqual(['CVE-2026-3001']);

    // A second CVE modified AFTER the first run's cursor; an older one should
    // not be re-scanned. Run again at now+10s.
    const later = now + 10_000;
    await seedCve('CVE-2026-3002', now + 1000); // after cursor → matched
    await seedCpe('CVE-2026-3002', 'acme', 'gadget');
    await reconcileWatchlistMatches(testEnv, later);

    expect((await getMatches(wl)).map((m) => m.cve_id).sort()).toEqual([
      'CVE-2026-3001',
      'CVE-2026-3002',
    ]);
  });

  it('idempotent: a re-run never resets an analyst-changed triage status (ON CONFLICT DO NOTHING)', async () => {
    const now = Date.now();
    const wl = await createWatchlist('triage');
    await subscribe(wl, 'acme', 'widget');
    await seedCve('CVE-2026-4001', now - 1000);
    await seedCpe('CVE-2026-4001', 'acme', 'widget');

    await reconcileWatchlistMatches(testEnv, now);
    // Analyst triages it to RESOLVED.
    await testEnv.DB.prepare(
      `UPDATE watchlist_match SET status = 'RESOLVED', status_updated_at = ?
       WHERE watchlist_id = ? AND cve_id = ?`,
    )
      .bind(now + 1, wl, 'CVE-2026-4001')
      .run();

    // The CVE is modified again (new last_modified_at), reconciliation re-runs.
    await testEnv.DB.prepare(`UPDATE cve SET last_modified_at = ? WHERE cve_id = ?`)
      .bind(now + 5000, 'CVE-2026-4001')
      .run();
    await reconcileWatchlistMatches(testEnv, now + 10_000);

    const matches = await getMatches(wl);
    expect(matches).toEqual([{ cve_id: 'CVE-2026-4001', status: 'RESOLVED' }]); // NOT reset to NEW
  });

  it('a CVE matching two different watchlists produces one match row per watchlist', async () => {
    const now = Date.now();
    const wlA = await createWatchlist('A');
    const wlB = await createWatchlist('B');
    await subscribe(wlA, 'acme', null);
    await subscribe(wlB, 'acme', 'widget');

    await seedCve('CVE-2026-5001', now - 1000);
    await seedCpe('CVE-2026-5001', 'acme', 'widget');

    await reconcileWatchlistMatches(testEnv, now);

    expect(await getMatches(wlA)).toEqual([{ cve_id: 'CVE-2026-5001', status: 'NEW' }]);
    expect(await getMatches(wlB)).toEqual([{ cve_id: 'CVE-2026-5001', status: 'NEW' }]);
  });

  it('stays well under the 50-D1-query budget even with many subscribed vendors and matches', async () => {
    const now = Date.now();
    const wl = await createWatchlist('budget');
    // 150 distinct vendors → forces the vendor IN(...) read to chunk at 100
    // (2 chunks), and 150 matching CVEs → one batched write.
    for (let i = 0; i < 150; i++) {
      const vendor = `vendor${i}`;
      await subscribe(wl, vendor, null);
      await seedCve(`CVE-2026-6${String(i).padStart(3, '0')}`, now - 1000);
      await seedCpe(`CVE-2026-6${String(i).padStart(3, '0')}`, vendor, 'product');
    }

    const spies = spyOnBindings();
    const result = await reconcileWatchlistMatches(testEnv, now);

    expect(result.matchesWritten).toBe(150);
    // Total D1 queries = standalone .first/.all/.run + db.batch() calls. The
    // point under test: this count is bounded by the subscribed-VENDOR set
    // (chunked at 98) and a single batched write, NOT by the 150 matched CVEs
    // — if it ever became O(CVEs) it would be ~150+. A single-digit count for
    // 150 matches proves the bound holds, comfortably under the 50-query cap.
    const total = spies.queryCalls.length + spies.dbBatch.mock.calls.length;
    expect(total).toBeLessThanOrEqual(10);
  }, 30_000);
});

describe('reconcileWatchlistMatches cursor advance under a saturated scan', () => {
  useCleanBindings();

  /**
   * The per-chunk LIMIT means each vendor chunk has its own high-water mark.
   * Advancing the cursor to the GLOBAL maximum, as this used to, skipped every
   * row a saturated chunk hadn't read yet — permanently, and silently, for
   * anyone with more than 98 subscribed vendors. The cursor may only move to
   * the lowest saturated chunk's mark.
   *
   * vendorChunkSize/maxCvesPerRun are clamped test overrides, so this
   * reproduces a two-chunk saturated scan with four CVEs instead of 4,000.
   */
  it('advances only to the lowest saturated chunk high-water mark', async () => {
    const now = Date.now();
    const wl = await createWatchlist('saturated');
    await subscribe(wl, 'alpha', null);
    await subscribe(wl, 'beta', null);

    // Chunk 1 = [alpha]: rows at T+1000 and T+2000 (it will be cut at 1).
    await seedCve('CVE-2026-6001', now - 4000);
    await seedCpe('CVE-2026-6001', 'alpha', 'one');
    await seedCve('CVE-2026-6002', now - 3000);
    await seedCpe('CVE-2026-6002', 'alpha', 'two');
    // Chunk 2 = [beta]: rows strictly newer than chunk 1's.
    await seedCve('CVE-2026-6003', now - 2000);
    await seedCpe('CVE-2026-6003', 'beta', 'three');
    await seedCve('CVE-2026-6004', now - 1000);
    await seedCpe('CVE-2026-6004', 'beta', 'four');

    const result = await reconcileWatchlistMatches(testEnv, now, {
      vendorChunkSize: 1,
      maxCvesPerRun: 1,
    });

    // Each chunk read exactly one (its oldest) row and reported saturated.
    // The floor is alpha's mark; beta's newer mark must NOT be used, or
    // CVE-2026-6002 is never seen again.
    expect(result.cursorAdvancedToMs).toBe(now - 4000);
    const cursor = await testEnv.DB.prepare(
      `SELECT last_cursor_ms FROM watchlist_sync_state WHERE key = 'watchlist_match'`,
    ).first<{ last_cursor_ms: number }>();
    expect(cursor?.last_cursor_ms).toBe(now - 4000);

    // The skipped rows are still reachable: re-running with the real bounds
    // picks up everything (the 1h safety overlap also replays the oldest).
    await reconcileWatchlistMatches(testEnv, now);
    expect((await getMatches(wl)).map((m) => m.cve_id)).toEqual([
      'CVE-2026-6001',
      'CVE-2026-6002',
      'CVE-2026-6003',
      'CVE-2026-6004',
    ]);
  });

  it('advances to the newest processed CVE when no chunk saturates', async () => {
    const now = Date.now();
    const wl = await createWatchlist('unsaturated');
    await subscribe(wl, 'acme', null);

    await seedCve('CVE-2026-6101', now - 3000);
    await seedCpe('CVE-2026-6101', 'acme', 'one');
    await seedCve('CVE-2026-6102', now - 2000);
    await seedCpe('CVE-2026-6102', 'acme', 'two');

    const result = await reconcileWatchlistMatches(testEnv, now);
    expect(result.cursorAdvancedToMs).toBe(now - 2000);
    expect((await getMatches(wl)).length).toBe(2);
  });
});
