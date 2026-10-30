import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import type { NormalizedCveRecord, NvdQueueMessage } from '@threat-lens/contracts';
import { describe, expect, it } from 'vitest';
import { runNvdConsumer } from '../src/pipelines/nvdQueue';
import { makeRecord, spyOnBindings, testEnv, useCleanBindings } from './helpers';

// NVD queue CONSUMER coverage (pipelines/nvdQueue.ts's runNvdConsumer), end
// to end against real local D1 (@cloudflare/vitest-plugin's workerd) — same
// convention as processRecord.test.ts/epssQueueConsumer.test.ts.
//
// processRecord()'s OWN internals (hash gating, writeD1, Vectorize,
// retry-enqueue) are already covered by test/processRecord.test.ts and are
// NOT re-tested here. What's unique to this file is runNvdConsumer's own
// contract: it calls processRecord() once per record in the batch, isolates
// one record's failure from the rest, and — the actual regression test for
// the bug this fix exists to close — the chosen batch size must not blow
// the Workers Free plan's 50-D1-query-per-invocation budget.

// Must track NVD_QUEUE_MAX_RECORDS in pipelines/daily.ts (currently 8) — the
// whole point of this test is to check the implementer's CHOSEN batch size
// against the real budget, so if that constant changes, this needs to move
// with it (a mismatch here is itself worth noticing, not silently masking).
const CHOSEN_BATCH_SIZE = 8;

function richRecord(
  cveId: string,
  overrides: Partial<NormalizedCveRecord> = {},
): NormalizedCveRecord {
  // cwes/cpes/references all non-empty so writeD1 issues all 4 of its
  // db.batch() calls (main row+state+provenance, CWEs, CPEs, references) —
  // the actual worst case the NVD_QUEUE_MAX_RECORDS budget math in
  // daily.ts's comments is based on, not the 1-CWE/1-CPE/0-reference
  // fixture test/helpers.ts's makeRecord() otherwise defaults to.
  return makeRecord({
    cveId,
    cwes: ['CWE-79', 'CWE-89'],
    cpes: [
      {
        cpeUri: 'cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*',
        part: 'a',
        vendor: 'acme',
        product: 'widget',
        version: '1.0',
        vulnerable: true,
        extras: {},
      },
      {
        cpeUri: 'cpe:2.3:a:acme:gadget:2.0:*:*:*:*:*:*:*',
        part: 'a',
        vendor: 'acme',
        product: 'gadget',
        version: '2.0',
        vulnerable: true,
        extras: {},
      },
    ],
    references: [{ url: 'https://example.com/advisory', tags: [] }],
    ...overrides,
  });
}

describe('runNvdConsumer', () => {
  useCleanBindings();

  it(`a worst-case ALL-CHANGED batch of ${CHOSEN_BATCH_SIZE} records (the implementer's chosen NVD_QUEUE_MAX_RECORDS) costs at most 5 D1 queries/record and stays comfortably under the 50-query Free-tier budget — the actual regression test for the bug this fix exists to close`, async () => {
    const spies = spyOnBindings();
    const records = Array.from({ length: CHOSEN_BATCH_SIZE }, (_, i) =>
      richRecord(`CVE-2026-8${String(i).padStart(4, '0')}`),
    );
    const message: NvdQueueMessage = { records };

    const ctx = createExecutionContext();
    await runNvdConsumer(message, testEnv, ctx);
    await waitOnExecutionContext(ctx);

    // Every record is brand-new (no prior row) → text+state both "changed" →
    // each record costs exactly 1 standalone `.first()` (the initial cur
    // SELECT) + 4 `db.batch()` calls (cve/state/provenance, CWEs, CPEs,
    // references) = 5 real D1 queries, per the budget accounting documented
    // on NVD_QUEUE_MAX_RECORDS in daily.ts and WRITE_SUB_BATCH_SIZE in
    // processRecord.ts (`db.batch()` = ONE query regardless of statement count).
    const totalD1Queries = spies.queryCalls.length + spies.dbBatch.mock.calls.length;

    // Pin the exact number, not just "<=50" — if writeD1's shape changes
    // (e.g. an extra batch call added later) this breaks loudly instead of
    // silently eating into the safety margin.
    expect(totalD1Queries).toBe(CHOSEN_BATCH_SIZE * 5);
    expect(totalD1Queries).toBeLessThanOrEqual(50);

    // Sanity: every record actually got processed (not silently dropped).
    const persisted = await testEnv.DB.prepare(
      `SELECT COUNT(*) AS n FROM cve WHERE cve_id IN (${records.map(() => '?').join(',')})`,
    )
      .bind(...records.map((r) => r.cveId))
      .first<{ n: number }>();
    expect(persisted?.n).toBe(CHOSEN_BATCH_SIZE);
  }, 30_000);

  it("calls processRecord() once per record and isolates one record's failure from the rest of the batch (per-record catch, no abort, no duplicate retry-enqueue)", async () => {
    const spies = spyOnBindings();
    const failing = richRecord('CVE-2026-81002');
    const ok1 = richRecord('CVE-2026-81001');
    const ok2 = richRecord('CVE-2026-81003');

    // Force only the FIRST-PROCESSED record's embed call to fail —
    // `mockRejectedValueOnce` queues onto the NEXT aiRun call chronologically,
    // which (since records are processed sequentially, in array order) is
    // `failing`'s, placed first in the batch below. processRecord's own
    // writeD1 already committed by the time embed() runs (D1 write happens
    // before the Vectorize/AI step — see processRecord.ts), so this exercises
    // "the AI call failed but D1 already succeeded" without needing a
    // D1-level fault injection.
    spies.aiRun.mockRejectedValueOnce(new Error('simulated embed failure'));

    const message: NvdQueueMessage = { records: [failing, ok1, ok2] };
    const ctx = createExecutionContext();
    await runNvdConsumer(message, testEnv, ctx);
    await waitOnExecutionContext(ctx);

    // All three D1 writes landed — writeD1 ran for every record regardless
    // of the embed outcome.
    const rows = await testEnv.DB.prepare(`SELECT cve_id FROM cve WHERE cve_id IN (?, ?, ?)`)
      .bind(ok1.cveId, failing.cveId, ok2.cveId)
      .all<{ cve_id: string }>();
    expect(new Set(rows.results.map((r) => r.cve_id))).toEqual(
      new Set([ok1.cveId, failing.cveId, ok2.cveId]),
    );

    // processRecord() already enqueues its own VECTORIZE_ONLY retry on an
    // embed failure (see processRecord.ts) — runNvdConsumer must not
    // duplicate that, just catch-and-count so the other records still run.
    expect(spies.retryQueueSend).toHaveBeenCalledTimes(1);
    const retryBody = spies.retryQueueSend.mock.calls[0]?.[0] as { cveId: string; opType: string };
    expect(retryBody.cveId).toBe(failing.cveId);
    expect(retryBody.opType).toBe('VECTORIZE_ONLY');

    // Consumer-level bookkeeping reflects 2 processed / 1 failed, PARTIAL.
    // (processRecord() itself also emits a `record_processed` analytics
    // point per successful call — those are a separate, already-covered
    // concern; this isolates nvdQueue.ts's OWN summary point by index.)
    const consumerPoints = spies.analyticsWrite.mock.calls
      .map(([p]) => p as { blobs: string[]; doubles: number[]; indexes: string[] })
      .filter((p) => p.indexes[0] === 'nvd_consumer_processed');
    expect(consumerPoints).toHaveLength(1);
    const point = consumerPoints[0];
    expect(point).toBeDefined();
    expect(point?.blobs[0]).toBe('NVD_QUEUE');
    expect(point?.blobs[1]).toBe('PARTIAL');
    expect(point?.doubles[1]).toBe(2); // processed
    expect(point?.doubles[2]).toBe(1); // failed
  });

  it('a malformed message (missing/non-array `records`, or an element missing required fields) is acked (dropped) without calling processRecord at all', async () => {
    const spies = spyOnBindings();

    const missingRecords = {} as NvdQueueMessage;
    await expect(
      runNvdConsumer(missingRecords, testEnv, createExecutionContext()),
    ).resolves.toBeUndefined();

    const badElement = {
      records: [{ cveId: 'CVE-2026-82000' /* missing description/cwes/cpes/references */ }],
    } as unknown as NvdQueueMessage;
    await expect(
      runNvdConsumer(badElement, testEnv, createExecutionContext()),
    ).resolves.toBeUndefined();

    expect(spies.dbPrepare).not.toHaveBeenCalled();
    expect(spies.dbBatch).not.toHaveBeenCalled();
    expect(spies.aiRun).not.toHaveBeenCalled();

    expect(spies.analyticsWrite).toHaveBeenCalledTimes(2);
    for (const call of spies.analyticsWrite.mock.calls) {
      const point = call[0] as { blobs: string[] };
      expect(point.blobs[0]).toBe('NVD_QUEUE');
      expect(point.blobs[1]).toBe('MALFORMED_MESSAGE');
    }
  });
});
