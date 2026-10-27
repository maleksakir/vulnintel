import type { HealthResponse, IngestSource, IngestSourceStatus } from '@threat-lens/contracts';

const CF_API = 'https://api.cloudflare.com/client/v4';

interface IngestRow {
  source: string;
  last_started_at: number | null;
  last_finished_at: number | null;
  last_status: 'OK' | 'PARTIAL' | 'FAILED' | null;
  records_processed: number | null;
  records_failed: number | null;
}

interface CountsRow {
  cve: number;
  cpe: number;
  cve_state: number;
  cve_quarantine: number;
  audit_log: number;
}

interface RateLimitRow {
  client_ip: string;
  blocks: number;
}

const INGEST_SOURCES: IngestSource[] = ['NVD', 'MITRE', 'KEV', 'EPSS', 'AGING'];

export async function getAdminHealth(
  db: D1Database,
  accountId: string,
  cfToken: string,
): Promise<HealthResponse> {
  const now = Date.now();
  const oneDayAgo = now - 86_400_000;

  const [ingestRows, countsRow, rateLimitRows] = await Promise.all([
    db.prepare(
      `SELECT source, last_started_at, last_finished_at, last_status,
              records_processed, records_failed
       FROM ingest_run
       WHERE source IN ('NVD','MITRE','KEV','EPSS','AGING')`,
    ).all<IngestRow>(),

    db.prepare(
      `SELECT
         (SELECT COUNT(*) FROM cve)              AS cve,
         (SELECT COUNT(*) FROM cpe)              AS cpe,
         (SELECT COUNT(*) FROM cve_state)        AS cve_state,
         (SELECT COUNT(*) FROM cve_quarantine)   AS cve_quarantine,
         (SELECT COUNT(*) FROM audit_log)        AS audit_log`,
    ).first<CountsRow>(),

    db.prepare(
      `SELECT client_ip, COUNT(*) AS blocks
       FROM audit_log
       WHERE occurred_at > ? AND action LIKE 'RATE_LIMITED%'
       GROUP BY client_ip
       ORDER BY blocks DESC
       LIMIT 10`,
    ).bind(oneDayAgo).all<RateLimitRow>(),
  ]);

  // Build ingest status map
  const ingestMap = new Map<string, IngestRow>();
  for (const row of ingestRows.results) ingestMap.set(row.source, row);

  const ingest = {} as Record<IngestSource, IngestSourceStatus>;
  for (const src of INGEST_SOURCES) {
    const row = ingestMap.get(src);
    ingest[src] = {
      lastStartedAt: row?.last_started_at != null ? new Date(row.last_started_at).toISOString() : null,
      lastFinishedAt: row?.last_finished_at != null ? new Date(row.last_finished_at).toISOString() : null,
      lastStatus: row?.last_status ?? null,
      recordsProcessed: row?.records_processed ?? null,
      recordsFailed: row?.records_failed ?? null,
      staleness: computeStaleness(row?.last_finished_at ?? null, row?.last_status ?? null, now),
    };
  }

  // Queue depths via Cloudflare API (best-effort).
  const [retryDepth, dlqDepth] = await Promise.all([
    getQueueDepth(accountId, cfToken, 'cve-ingest-retry'),
    getQueueDepth(accountId, cfToken, 'cve-ingest-dlq'),
  ]);

  const lastHourAgo = now - 3_600_000;
  const lastHourBlocksRes = await db.prepare(
    `SELECT COUNT(*) AS cnt FROM audit_log WHERE occurred_at > ? AND action LIKE 'RATE_LIMITED%'`,
  ).bind(lastHourAgo).first<{ cnt: number }>();

  return {
    generatedAt: new Date(now).toISOString(),
    ingest,
    counts: {
      cve: countsRow?.cve ?? 0,
      cpe: countsRow?.cpe ?? 0,
      cveState: countsRow?.cve_state ?? 0,
      cveQuarantine: countsRow?.cve_quarantine ?? 0,
      auditLog: countsRow?.audit_log ?? 0,
    },
    queues: { retryDepth, dlqDepth },
    rateLimits: {
      lastHourBlocks: lastHourBlocksRes?.cnt ?? 0,
      topIps: (rateLimitRows.results ?? []).map(r => ({ ip: r.client_ip, blocks: r.blocks })),
    },
  };
}

function computeStaleness(
  lastFinishedAt: number | null,
  lastStatus: string | null,
  now: number,
): 'green' | 'amber' | 'red' {
  if (!lastFinishedAt || lastStatus !== 'OK') return 'red';
  const hoursAgo = (now - lastFinishedAt) / 3_600_000;
  if (hoursAgo < 26) return 'green';
  if (hoursAgo < 48) return 'amber';
  return 'red';
}

async function getQueueDepth(
  accountId: string,
  token: string,
  name: string,
): Promise<number> {
  try {
    const res = await fetch(`${CF_API}/accounts/${accountId}/queues?name=${encodeURIComponent(name)}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) return -1;
    const data = await res.json<{ result?: Array<{ consumers_total_count?: number }> }>();
    return data.result?.[0]?.consumers_total_count ?? -1;
  } catch {
    return -1;
  }
}
