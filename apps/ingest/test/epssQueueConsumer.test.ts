import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import type { EpssPatch, EpssQueueMessage } from '@threat-lens/contracts';
import { describe, expect, it } from 'vitest';
import { runEpssConsumer } from '../src/pipelines/epssQueue';
import { seedCveRow, seedCveState, spyOnBindings, testEnv, useCleanBindings } from './helpers';

// EPSS queue CONSUMER coverage (pipelines/epssQueue.ts's runEpssConsumer),
// end to end against real local D1 (@cloudflare/vitest-plugin's workerd),
// not a hand-rolled mock — consistent with processRecord.test.ts/
// kevPatch.test.ts's convention.

const TOTAL = 1500; // ~ one EPSS_MESSAGE_CHUNK_SIZE-and-a-half message
const CHANGED_EVERY = 3; // every 3rd row actually changes vs seeded state

function cveIdFor(i: number): string {
  return `CVE-2026-5${String(i).padStart(4, '0')}`;
}

async function seedMixedState(): Promise<
  Map<string, { epssScore: number; epssPercentile: number }>
> {
  const seeded = new Map<string, { epssScore: number; epssPercentile: number }>();
  await Promise.all(
    Array.from({ length: TOTAL }, (_, i) => i).map(async (i) => {
      const cveId = cveIdFor(i);
      const score = { epssScore: 0.1 + (i % 50) / 1000, epssPercentile: 0.2 + (i % 50) / 1000 };
      seeded.set(cveId, score);
      await seedCveRow({ cveId });
      await seedCveState({
        cveId,
        epssScore: score.epssScore,
        epssPercentile: score.epssPercentile,
      });
    }),
  );
  return seeded;
}

describe('runEpssConsumer', () => {
  useCleanBindings();

  it('processes ~1500 mixed changed/unchanged patches: unchanged rows produce no writes/no cache deletes, changed rows get written and their cache key invalidated — skip-if-unchanged holds', async () => {
    const seeded = await seedMixedState();

    const now = Date.now();
    const patches: EpssPatch[] = Array.from({ length: TOTAL }, (_, i) => {
      const cveId = cveIdFor(i);
      const base = seeded.get(cveId);
      if (!base) throw new Error(`test setup bug: no seeded score for ${cveId}`);
      const isChanged = i % CHANGED_EVERY === 0;
      return {
        cveId,
        epssScore: isChanged ? base.epssScore + 0.01 : base.epssScore,
        epssPercentile: isChanged ? base.epssPercentile + 0.01 : base.epssPercentile,
        epssUpdatedAt: now,
      };
    });

    const changedIds = patches.filter((_, i) => i % CHANGED_EVERY === 0).map((p) => p.cveId);
    const unchangedIds = patches.filter((_, i) => i % CHANGED_EVERY !== 0).map((p) => p.cveId);
    expect(changedIds.length + unchangedIds.length).toBe(TOTAL);
    expect(changedIds.length).toBeGreaterThan(0);
    expect(unchangedIds.length).toBeGreaterThan(0);

    const spies = spyOnBindings();
    const ctx = createExecutionContext();
    const message: EpssQueueMessage = { patches };

    await runEpssConsumer(message, testEnv, ctx);
    await waitOnExecutionContext(ctx);

    // skip-if-unchanged: exactly one cache delete per CHANGED row, none for unchanged rows.
    expect(spies.cacheDelete).toHaveBeenCalledTimes(changedIds.length);
    const deletedKeys = spies.cacheDelete.mock.calls.map(([key]) => key);
    expect(new Set(deletedKeys)).toEqual(new Set(changedIds.map((id) => `cve:${id}`)));

    // Spot-check real D1 state (sampled, not all 1500, to keep the assertion
    // phase fast — the write path itself is exercised for the whole batch
    // above via the cache-delete count, which only fires per actual write).
    const changedSample = [...changedIds.slice(0, 5), ...changedIds.slice(-5)];
    for (const id of changedSample) {
      const base = seeded.get(id);
      if (!base) throw new Error(`missing seed for ${id}`);
      const row = await testEnv.DB.prepare(
        'SELECT epss_score, epss_percentile FROM cve_state WHERE cve_id = ?',
      )
        .bind(id)
        .first<{ epss_score: number; epss_percentile: number }>();
      expect(row?.epss_score).toBeCloseTo(base.epssScore + 0.01, 6);
      expect(row?.epss_percentile).toBeCloseTo(base.epssPercentile + 0.01, 6);
    }

    const unchangedSample = [...unchangedIds.slice(0, 5), ...unchangedIds.slice(-5)];
    for (const id of unchangedSample) {
      const base = seeded.get(id);
      if (!base) throw new Error(`missing seed for ${id}`);
      const row = await testEnv.DB.prepare('SELECT epss_score FROM cve_state WHERE cve_id = ?')
        .bind(id)
        .first<{ epss_score: number }>();
      expect(row?.epss_score).toBeCloseTo(base.epssScore, 6);
    }

    // Successful run emits exactly one OK analytics point.
    expect(spies.analyticsWrite).toHaveBeenCalledTimes(1);
    const point = spies.analyticsWrite.mock.calls[0]?.[0] as { blobs: string[] } | undefined;
    expect(point?.blobs?.[0]).toBe('EPSS_QUEUE');
    expect(point?.blobs?.[1]).toBe('OK');
  }, 60_000);

  it("on a D1 failure mid-batch: rethrows (so index.ts's queue() handler retries the message) and emits a FAILED analytics point", async () => {
    const cveId = 'CVE-2026-59999';
    await seedCveRow({ cveId });

    const spies = spyOnBindings();
    spies.dbPrepare.mockImplementationOnce(() => {
      throw new Error('simulated D1 outage');
    });

    const message: EpssQueueMessage = {
      patches: [{ cveId, epssScore: 0.5, epssPercentile: 0.5, epssUpdatedAt: Date.now() }],
    };

    await expect(runEpssConsumer(message, testEnv, createExecutionContext())).rejects.toThrow(
      'simulated D1 outage',
    );

    expect(spies.analyticsWrite).toHaveBeenCalledTimes(1);
    const point = spies.analyticsWrite.mock.calls[0]?.[0] as { blobs: string[] } | undefined;
    expect(point?.blobs?.[0]).toBe('EPSS_QUEUE');
    expect(point?.blobs?.[1]).toBe('FAILED');
  });

  it('on a malformed message (missing/non-array patches, or a wrong-typed field): acks (does not throw/retry) and emits a MALFORMED_MESSAGE analytics point instead of touching D1', async () => {
    const spies = spyOnBindings();

    const missingPatches = {} as EpssQueueMessage;
    await expect(
      runEpssConsumer(missingPatches, testEnv, createExecutionContext()),
    ).resolves.toBeUndefined();

    const wrongTypedField = {
      patches: [
        {
          cveId: 'CVE-2026-50001',
          epssScore: 'not-a-number',
          epssPercentile: 0.5,
          epssUpdatedAt: Date.now(),
        },
      ],
    } as unknown as EpssQueueMessage;
    await expect(
      runEpssConsumer(wrongTypedField, testEnv, createExecutionContext()),
    ).resolves.toBeUndefined();

    expect(spies.dbPrepare).not.toHaveBeenCalled();
    expect(spies.cacheDelete).not.toHaveBeenCalled();

    expect(spies.analyticsWrite).toHaveBeenCalledTimes(2);
    for (const call of spies.analyticsWrite.mock.calls) {
      const point = call[0] as { blobs: string[] };
      expect(point.blobs[0]).toBe('EPSS_QUEUE');
      expect(point.blobs[1]).toBe('MALFORMED_MESSAGE');
    }
  });
});
