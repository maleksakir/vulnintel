import { applyD1Migrations, reset } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import type { NormalizedCveRecord } from '@threat-lens/contracts';
import { afterEach, beforeEach, vi } from 'vitest';
import type { Env } from '../src/types';

/** The `env` binding, cast to this Worker's real `Env` shape for call sites. */
export const testEnv = env as unknown as Env;

/**
 * Registers `beforeEach`/`afterEach` hooks that give every test a clean,
 * freshly-migrated D1 + KV + Queue state and restore any `vi.spyOn` mocks.
 *
 * `reset()` (from `cloudflare:test`) wipes the whole simulated D1 instance,
 * schema included — so the migrations applied once in `setupFiles` (which
 * runs a single time per test file) don't survive a mid-file `reset()`.
 * `applyD1Migrations` is idempotent, so re-running it here after every reset
 * is safe and keeps each test's schema intact without re-seeding any data.
 */
export function useCleanBindings(): void {
  beforeEach(async () => {
    await applyD1Migrations(testEnv.DB, testEnv.TEST_MIGRATIONS);
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await reset();
  });
}

/**
 * Builds a minimal but schema-valid `NormalizedCveRecord`. `cwes`/`cpes`
 * default to exactly one entry each so `writeD1`'s batch-call count
 * (main row + one CWE batch + one CPE batch, no references batch) stays a
 * fixed, assertable number across tests.
 */
export function makeRecord(overrides: Partial<NormalizedCveRecord> = {}): NormalizedCveRecord {
  return {
    cveId: 'CVE-2026-00001',
    publishedAt: Date.UTC(2026, 0, 1),
    lastModifiedAt: Date.UTC(2026, 0, 1),
    description: 'Example vulnerability in a widget factory.',
    cvss: {
      version: '3.1',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      base: 9.8,
      exploitability: 3.9,
      impact: 5.9,
    },
    severity: 'CRITICAL',
    source: 'NVD',
    cwes: ['CWE-79'],
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
    ],
    references: [],
    ...overrides,
  };
}

/**
 * Spies on every binding `processRecord`/`applyKevPatch`/`applyEpssPatchBatch`
 * touch. D1/KV/Queues spies pass through to the real workerd binding
 * (call-count assertions on genuine behaviour); AI/Vectorize spies replace
 * the implementation outright since those bindings have no local simulator
 * and would otherwise try to reach the real Cloudflare API.
 */
export function spyOnBindings() {
  const aiRun = vi.spyOn(testEnv.AI, 'run').mockResolvedValue({ data: [[0.1, 0.2, 0.3]] } as never);
  const vectorizeUpsert = vi
    .spyOn(testEnv.VECTORIZE, 'upsert')
    .mockImplementation(async (vectors) => ({
      mutationId: 'test-mutation',
      count: vectors.length,
      ids: vectors.map((v) => v.id),
    }));
  const vectorizeGetByIds = vi.spyOn(testEnv.VECTORIZE, 'getByIds').mockResolvedValue([]);
  const dbBatch = vi.spyOn(testEnv.DB, 'batch');
  const cacheDelete = vi.spyOn(testEnv.CACHE, 'delete');
  const retryQueueSend = vi.spyOn(testEnv.RETRY_QUEUE, 'send');
  const analyticsWrite = vi.spyOn(testEnv.ANALYTICS, 'writeDataPoint');

  // `boundCalls` records, per `db.prepare(sql).bind(...args)` call, the SQL
  // text and how many params were bound to it — the regression signal for
  // D1's 100-bound-param-per-query cap (see test/epssPatchBatch.test.ts).
  // Implemented by wrapping `prepare`'s return value rather than just
  // spying on `prepare` itself, since the param count lives on the
  // chained `.bind(...)` call, not on `prepare(sql)`.
  const boundCalls: { sql: string; paramCount: number }[] = [];
  const originalPrepare = testEnv.DB.prepare.bind(testEnv.DB);
  const dbPrepare = vi.spyOn(testEnv.DB, 'prepare').mockImplementation((sql: string) => {
    const stmt = originalPrepare(sql);
    const originalBind = stmt.bind.bind(stmt);
    vi.spyOn(stmt, 'bind').mockImplementation((...args: unknown[]) => {
      boundCalls.push({ sql, paramCount: args.length });
      return originalBind(...(args as never[]));
    });
    return stmt;
  });

  const spies = {
    aiRun,
    vectorizeUpsert,
    vectorizeGetByIds,
    dbBatch,
    dbPrepare,
    cacheDelete,
    retryQueueSend,
    analyticsWrite,
  };

  return {
    ...spies,
    boundCalls,
    /** Clears call history on every spy without discarding their mock implementations. */
    clearAll() {
      for (const spy of Object.values(spies)) spy.mockClear();
      boundCalls.length = 0;
    },
    /** SQL strings passed to `db.prepare`, in call order. */
    preparedSql(): string[] {
      return dbPrepare.mock.calls.map(([sql]) => sql);
    },
  };
}

/** Inserts a minimal, schema-valid `cve` row directly (bypassing processRecord). */
export async function seedCveRow(opts: {
  cveId: string;
  severity?: string;
  cvssBase?: number | null;
  textHash?: string;
  stateHash?: string;
}): Promise<void> {
  const now = Date.now();
  await testEnv.DB.prepare(
    `INSERT INTO cve
       (cve_id, published_at, last_modified_at, description, cvss_base,
        severity, source, text_hash, state_hash, ingested_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      opts.cveId,
      now,
      now,
      'seed description',
      opts.cvssBase ?? null,
      opts.severity ?? 'HIGH',
      'NVD',
      opts.textHash ?? 'seed-text-hash',
      opts.stateHash ?? 'seed-state-hash',
      now,
    )
    .run();
}

/** Inserts/replaces an `osv_record_state` row directly (bypassing applyOsvPatchBatch),
 *  for discovery-path tests that need to seed prior state without going through
 *  the fetch-batch write path. */
export async function seedOsvState(opts: {
  osvId: string;
  ecosystemDir?: string;
  modifiedAt: string;
  status?: 'LINKED' | 'NO_CVE_ALIAS' | 'CVE_NOT_INGESTED' | 'WITHDRAWN';
  cveIds?: string;
  contentHash?: string | null;
  firstSeenAt?: number;
  checkedAt?: number;
}): Promise<void> {
  const now = Date.now();
  await testEnv.DB.prepare(
    `INSERT INTO osv_record_state
       (osv_id, ecosystem_dir, modified_at, content_hash, status, cve_ids, first_seen_at, checked_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      opts.osvId,
      opts.ecosystemDir ?? 'npm',
      opts.modifiedAt,
      opts.contentHash ?? null,
      opts.status ?? 'CVE_NOT_INGESTED',
      opts.cveIds ?? '',
      opts.firstSeenAt ?? now,
      opts.checkedAt ?? now,
    )
    .run();
}

/** Inserts/replaces a `cve_state` row directly (bypassing applyKevPatch/applyEpssPatchBatch). */
export async function seedCveState(opts: {
  cveId: string;
  kevListed?: 0 | 1;
  kevDateAdded?: number | null;
  kevDueDate?: number | null;
  kevRequiredAction?: string | null;
  epssScore?: number | null;
  epssPercentile?: number | null;
}): Promise<void> {
  await testEnv.DB.prepare(
    `INSERT INTO cve_state
       (cve_id, kev_listed, kev_date_added, kev_due_date, kev_required_action,
        epss_score, epss_percentile, state_updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      opts.cveId,
      opts.kevListed ?? 0,
      opts.kevDateAdded ?? null,
      opts.kevDueDate ?? null,
      opts.kevRequiredAction ?? null,
      opts.epssScore ?? null,
      opts.epssPercentile ?? null,
      Date.now(),
    )
    .run();
}
