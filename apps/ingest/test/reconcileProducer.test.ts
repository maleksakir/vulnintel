import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import type { NvdQueueMessage } from '@threat-lens/contracts';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { runWeeklyReconciliation } from '../src/pipelines/reconcile';
import { spyOnBindings, testEnv, useCleanBindings } from './helpers';

// Weekly reconciliation PRODUCER coverage (pipelines/reconcile.ts). The fix:
// reconcile must no longer call processRecord() inline per record (the
// inline-per-record D1 bug — see docs/EXECUTION_PLAN.md's reconcile row). It
// now fetches the 30-day NVD window and enqueues onto the EXISTING nvd-ingest
// queue (shared with daily.ts), doing zero D1 patch work of its own.
//
// Same global-`fetch` stub approach as nvdProducer.test.ts (vi.mock doesn't
// work under @cloudflare/vitest-plugin's workerd). Copied from nvdProducer.ts
// — will go stale if that file changes these without updating here too.
const NVD_QUEUE_MAX_RECORDS = 8;
const QUEUES_HARD_CAP_BYTES = 131_072;

function requestUrl(input: RequestInfo | URL): string {
  if (typeof input === 'string') return input;
  if (input instanceof URL) return input.href;
  return input.url;
}

function nvdVuln(id: string, cpeCount = 4, refCount = 5) {
  return {
    cve: {
      id,
      published: '2026-01-01T00:00:00.000',
      lastModified: '2026-01-02T00:00:00.000',
      vulnStatus: 'Analyzed',
      descriptions: [{ lang: 'en', value: 'Example vulnerability.' }],
      weaknesses: [
        { source: 'nvd@nist.gov', type: 'Primary', description: [{ lang: 'en', value: 'CWE-79' }] },
      ],
      configurations: [
        {
          nodes: [
            {
              operator: 'OR',
              negate: false,
              cpeMatch: Array.from({ length: cpeCount }, (_, i) => ({
                vulnerable: true,
                criteria: `cpe:2.3:a:vendor-${i}:product-${i}:1.0.${i}:*:*:*:*:*:*:*`,
              })),
            },
          ],
        },
      ],
      references: Array.from({ length: refCount }, (_, i) => ({
        url: `https://example.com/advisory/${i}`,
        tags: ['x_refsource_misc'],
      })),
    },
  };
}

function stubNvd(vulns: ReturnType<typeof nvdVuln>[]): void {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      const url = requestUrl(input);
      if (url.startsWith('https://services.nvd.nist.gov/')) {
        return new Response(
          JSON.stringify({
            resultsPerPage: vulns.length,
            startIndex: 0,
            totalResults: vulns.length,
            vulnerabilities: vulns,
          }),
          { status: 200 },
        );
      }
      // Reconcile touches NVD only — no EPSS/MITRE/OSV fetches in this path.
      throw new Error(`unexpected fetch() call in reconcile test: ${url}`);
    }),
  );
}

describe('Weekly reconciliation producer (reconcile.ts)', () => {
  useCleanBindings();

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('enqueues the whole 30-day NVD window onto nvd-ingest (batched), makes zero D1 patch calls, and records an OK RECONCILE run', async () => {
    const vulns = Array.from({ length: 19 }, (_, i) =>
      nvdVuln(`CVE-2026-5${String(i).padStart(4, '0')}`),
    );
    stubNvd(vulns);

    const spies = spyOnBindings();
    const sendSpy = vi.spyOn(testEnv.NVD_QUEUE, 'send');

    const ctx = createExecutionContext();
    await runWeeklyReconciliation(testEnv, ctx);
    await waitOnExecutionContext(ctx);

    const sent = sendSpy.mock.calls.map(([msg]) => msg as NvdQueueMessage);

    // (a) every record enqueued exactly once, batched at NVD_QUEUE_MAX_RECORDS.
    const sentIds = sent.flatMap((m) => m.records.map((r) => r.cveId));
    expect(sentIds).toHaveLength(19);
    expect(new Set(sentIds)).toEqual(new Set(vulns.map((v) => v.cve.id)));
    for (const msg of sent.slice(0, -1)) {
      expect(msg.records.length).toBe(NVD_QUEUE_MAX_RECORDS);
    }

    // (b) under the Queues hard cap.
    for (const msg of sent) {
      const bytes = new TextEncoder().encode(JSON.stringify(msg)).length;
      expect(bytes).toBeLessThanOrEqual(QUEUES_HARD_CAP_BYTES);
    }

    // (c) NO inline processRecord() D1 work — the entire point of the fix.
    // Only ingest_run bookkeeping for RECONCILE is allowed. In particular,
    // no cve/cve_state/cpe/cve_reference writes and no db.batch() calls.
    const nonBookkeepingSql = spies.preparedSql().filter((sql) => !/\bingest_run\b/i.test(sql));
    expect(nonBookkeepingSql).toEqual([]);
    expect(spies.dbBatch).not.toHaveBeenCalled();
    expect(spies.aiRun).not.toHaveBeenCalled(); // no embedding — that's the consumer's job now
    expect(spies.vectorizeUpsert).not.toHaveBeenCalled();

    const ingestRow = await testEnv.DB.prepare(
      'SELECT last_status, records_processed, records_failed FROM ingest_run WHERE source = ?',
    )
      .bind('RECONCILE')
      .first<{ last_status: string; records_processed: number; records_failed: number }>();
    expect(ingestRow).toEqual({
      last_status: 'OK',
      records_processed: 19,
      records_failed: 0,
    });
  }, 30_000);

  it('an empty 30-day window: enqueues nothing and still records an OK run', async () => {
    stubNvd([]);

    const sendSpy = vi.spyOn(testEnv.NVD_QUEUE, 'send');
    const ctx = createExecutionContext();
    await runWeeklyReconciliation(testEnv, ctx);
    await waitOnExecutionContext(ctx);

    expect(sendSpy).not.toHaveBeenCalled();
    const ingestRow = await testEnv.DB.prepare(
      'SELECT last_status, records_processed FROM ingest_run WHERE source = ?',
    )
      .bind('RECONCILE')
      .first<{ last_status: string; records_processed: number }>();
    expect(ingestRow).toEqual({ last_status: 'OK', records_processed: 0 });
  }, 30_000);
});
