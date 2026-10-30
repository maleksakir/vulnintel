import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import type { KevPatch, KevQueueMessage } from '@threat-lens/contracts';
import { describe, expect, it } from 'vitest';
import { runKevConsumer } from '../src/pipelines/kevQueue';
import { seedCveRow, seedCveState, spyOnBindings, testEnv, useCleanBindings } from './helpers';

// KEV queue CONSUMER coverage (pipelines/kevQueue.ts's runKevConsumer), end
// to end against real local D1 — same convention as epssQueueConsumer.ts.

const TOTAL = 500; // ~ one KEV_MESSAGE_CHUNK_SIZE message
const CHANGED_EVERY = 4; // every 4th entry differs from seeded state

function cveIdFor(i: number): string {
  return `CVE-2026-8${String(i).padStart(4, '0')}`;
}

describe('runKevConsumer', () => {
  useCleanBindings();

  it('processes a full chunk of mixed changed/unchanged KEV entries: unchanged produce no write/no cache delete, changed get listed + cache-invalidated (skip-if-unchanged holds)', async () => {
    const baseDate = 1_700_000_000_000;
    const seededAction = new Map<string, string>();

    await Promise.all(
      Array.from({ length: TOTAL }, (_, i) => i).map(async (i) => {
        const cveId = cveIdFor(i);
        const action = `Action ${i}`;
        seededAction.set(cveId, action);
        await seedCveRow({ cveId });
        await seedCveState({
          cveId,
          kevListed: 1,
          kevDateAdded: baseDate,
          kevDueDate: null,
          kevRequiredAction: action,
        });
      }),
    );

    const patches: KevPatch[] = Array.from({ length: TOTAL }, (_, i) => {
      const cveId = cveIdFor(i);
      const isChanged = i % CHANGED_EVERY === 0;
      return {
        cveId,
        kevDateAdded: baseDate,
        kevDueDate: null,
        // changed entries get a different requiredAction; unchanged match seed exactly
        kevRequiredAction: isChanged ? `UPDATED ${i}` : (seededAction.get(cveId) ?? ''),
      };
    });

    const changedIds = patches.filter((_, i) => i % CHANGED_EVERY === 0).map((p) => p.cveId);
    const unchangedIds = patches.filter((_, i) => i % CHANGED_EVERY !== 0).map((p) => p.cveId);
    expect(changedIds.length).toBeGreaterThan(0);
    expect(unchangedIds.length).toBeGreaterThan(0);

    const spies = spyOnBindings();
    const ctx = createExecutionContext();
    await runKevConsumer({ patches }, testEnv, ctx);
    await waitOnExecutionContext(ctx);

    // skip-if-unchanged: one cve:{id} delete per CHANGED entry + exactly one
    // shared threat:kev:list delete (not one per entry).
    const deletedKeys = spies.cacheDelete.mock.calls.map(([key]) => key);
    expect(deletedKeys.filter((k) => k === 'threat:kev:list')).toHaveLength(1);
    const cveDeletes = deletedKeys.filter((k) => k !== 'threat:kev:list');
    expect(new Set(cveDeletes)).toEqual(new Set(changedIds.map((id) => `cve:${id}`)));

    // Real D1 spot-check: changed entries carry the new action; unchanged unchanged.
    for (const id of [...changedIds.slice(0, 3), ...changedIds.slice(-3)]) {
      const i = Number(id.slice('CVE-2026-8'.length));
      const row = await testEnv.DB.prepare(
        'SELECT kev_required_action FROM cve_state WHERE cve_id = ?',
      )
        .bind(id)
        .first<{ kev_required_action: string }>();
      expect(row?.kev_required_action).toBe(`UPDATED ${i}`);
    }
    for (const id of [...unchangedIds.slice(0, 3), ...unchangedIds.slice(-3)]) {
      const row = await testEnv.DB.prepare(
        'SELECT kev_required_action FROM cve_state WHERE cve_id = ?',
      )
        .bind(id)
        .first<{ kev_required_action: string }>();
      expect(row?.kev_required_action).toBe(seededAction.get(id));
    }

    const point = spies.analyticsWrite.mock.calls.find(
      ([p]) => (p as { blobs: string[] }).blobs[0] === 'KEV_QUEUE',
    )?.[0] as { blobs: string[]; doubles: number[] } | undefined;
    expect(point?.blobs[1]).toBe('OK');
    expect(point?.doubles[1]).toBe(TOTAL); // processed
    expect(point?.doubles[2]).toBe(changedIds.length); // changed
  }, 60_000);

  it("on a D1 failure: rethrows (so index.ts's queue() retries the message) and emits a FAILED analytics point", async () => {
    const cveId = 'CVE-2026-89999';
    await seedCveRow({ cveId });

    const spies = spyOnBindings();
    spies.dbPrepare.mockImplementationOnce(() => {
      throw new Error('simulated D1 outage');
    });

    const message: KevQueueMessage = {
      patches: [
        { cveId, kevDateAdded: 1_700_000_000_000, kevDueDate: null, kevRequiredAction: 'Patch' },
      ],
    };

    await expect(runKevConsumer(message, testEnv, createExecutionContext())).rejects.toThrow(
      'simulated D1 outage',
    );

    const point = spies.analyticsWrite.mock.calls[0]?.[0] as { blobs: string[] } | undefined;
    expect(point?.blobs?.[0]).toBe('KEV_QUEUE');
    expect(point?.blobs?.[1]).toBe('FAILED');
  });

  it('on a malformed message (missing/non-array patches, or a wrong-typed field): acks (no throw) and emits MALFORMED_MESSAGE without touching D1', async () => {
    const spies = spyOnBindings();

    await expect(
      runKevConsumer({} as KevQueueMessage, testEnv, createExecutionContext()),
    ).resolves.toBeUndefined();

    const wrongTyped = {
      patches: [
        {
          cveId: 'CVE-2026-80001',
          kevDateAdded: 'not-a-number',
          kevDueDate: null,
          kevRequiredAction: 'Patch',
        },
      ],
    } as unknown as KevQueueMessage;
    await expect(
      runKevConsumer(wrongTyped, testEnv, createExecutionContext()),
    ).resolves.toBeUndefined();

    expect(spies.dbPrepare).not.toHaveBeenCalled();
    expect(spies.cacheDelete).not.toHaveBeenCalled();
    expect(spies.analyticsWrite).toHaveBeenCalledTimes(2);
    for (const call of spies.analyticsWrite.mock.calls) {
      const point = call[0] as { blobs: string[] };
      expect(point.blobs[0]).toBe('KEV_QUEUE');
      expect(point.blobs[1]).toBe('MALFORMED_MESSAGE');
    }
  });
});
