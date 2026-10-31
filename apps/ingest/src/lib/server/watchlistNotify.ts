import type { Env } from '../../types';

// Watchlist notifications. After reconciliation materializes new matches, fire
// a one-time digest per watchlist that has an enabled webhook, to the
// still-NEW, not-yet-notified matches. Runs inside the watchlist-ingest
// consumer invocation (pipelines/watchlistQueue.ts), so it shares that
// invocation's budget — hence the bounds below.

// Cap digest size per webhook (keeps the POST body and the UPDATE set bounded).
const MAX_MATCHES_PER_DIGEST = 50;
// Cap total webhooks dispatched per run (shared subrequest budget with the
// rest of the consumer invocation — one fetch per webhook).
const MAX_WEBHOOKS_PER_RUN = 20;
const FETCH_TIMEOUT_MS = 5000;

interface WebhookRow {
  webhook_id: number;
  watchlist_id: number;
  kind: 'generic' | 'slack';
  url: string;
  watchlist_name: string;
}

interface PendingMatchRow {
  cve_id: string;
  severity: string | null;
  cvss_base: number | null;
  kev_listed: number | null;
}

export interface NotifyResult {
  webhooksDispatched: number;
  matchesNotified: number;
}

/**
 * Dispatch new-match digests. Idempotent via watchlist_match.notified_at: a
 * CVE is included in at most one digest ever (the stamp is written only after
 * a successful POST, so a failed dispatch is retried on the next run rather
 * than silently dropped).
 *
 * Budget: 1 read for enabled webhooks, then per webhook (capped at
 * MAX_WEBHOOKS_PER_RUN): 1 read for pending matches + 1 fetch + 1 batched
 * UPDATE. Bounded well under the per-invocation D1 + subrequest budgets.
 */
export async function dispatchWatchlistNotifications(env: Env): Promise<NotifyResult> {
  const webhooksRes = await env.DB.prepare(
    `SELECT w.webhook_id, w.watchlist_id, w.kind, w.url, wl.name AS watchlist_name
     FROM watchlist_webhook w
     JOIN watchlist wl ON wl.watchlist_id = w.watchlist_id
     WHERE w.enabled = 1
     LIMIT ?`,
  )
    .bind(MAX_WEBHOOKS_PER_RUN)
    .all<WebhookRow>();

  let webhooksDispatched = 0;
  let matchesNotified = 0;

  for (const wh of webhooksRes.results) {
    // Still-NEW, not-yet-notified matches for this watchlist, joined to CVE
    // data for a useful digest. idx_wl_match_unnotified covers the filter.
    const pending = await env.DB.prepare(
      `SELECT m.cve_id, c.severity, c.cvss_base, s.kev_listed
       FROM watchlist_match m
       LEFT JOIN cve c ON c.cve_id = m.cve_id
       LEFT JOIN cve_state s ON s.cve_id = m.cve_id
       WHERE m.watchlist_id = ? AND m.notified_at IS NULL AND m.status = 'NEW'
       ORDER BY m.first_matched_at ASC
       LIMIT ?`,
    )
      .bind(wh.watchlist_id, MAX_MATCHES_PER_DIGEST)
      .all<PendingMatchRow>();

    if (pending.results.length === 0) continue;

    const ok = await postWebhook(wh, pending.results, env);
    if (!ok) {
      // Leave notified_at NULL so the next run retries; record the attempt.
      env.ANALYTICS.writeDataPoint({
        blobs: ['WATCHLIST_NOTIFY', 'DISPATCH_FAILED', String(wh.webhook_id), '', '', '', ''],
        doubles: [wh.watchlist_id, pending.results.length, 0, 0, 0],
        indexes: ['watchlist_consumer_processed'],
      });
      continue;
    }

    const now = Date.now();
    await env.DB.batch(
      pending.results.map((m) =>
        env.DB.prepare(
          `UPDATE watchlist_match SET notified_at = ? WHERE watchlist_id = ? AND cve_id = ?`,
        ).bind(now, wh.watchlist_id, m.cve_id),
      ),
    );
    // Best-effort webhook dispatch marker (ignore failure — not critical).
    env.DB.prepare(
      `UPDATE watchlist_webhook SET last_dispatch_at = ?, last_dispatch_status = 'OK' WHERE webhook_id = ?`,
    )
      .bind(now, wh.webhook_id)
      .run()
      .catch(() => {});

    webhooksDispatched++;
    matchesNotified += pending.results.length;
  }

  return { webhooksDispatched, matchesNotified };
}

async function postWebhook(wh: WebhookRow, matches: PendingMatchRow[], env: Env): Promise<boolean> {
  const lines = matches.map((m) => {
    const sev = m.severity ?? 'UNKNOWN';
    const cvss = m.cvss_base !== null ? ` CVSS ${m.cvss_base}` : '';
    const kev = m.kev_listed === 1 ? ' [KEV]' : '';
    return `• ${m.cve_id} (${sev}${cvss})${kev}`;
  });
  const summary = `Threat-Lens watchlist "${wh.watchlist_name}": ${matches.length} new matching CVE${
    matches.length === 1 ? '' : 's'
  }`;
  const text = `${summary}\n${lines.join('\n')}`;

  // Slack expects { text }; generic endpoints get a structured payload.
  const payload =
    wh.kind === 'slack'
      ? { text }
      : {
          watchlistId: wh.watchlist_id,
          watchlist: wh.watchlist_name,
          summary,
          matches: matches.map((m) => ({
            cveId: m.cve_id,
            severity: m.severity,
            cvssBase: m.cvss_base,
            kevListed: m.kev_listed === 1,
          })),
        };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(wh.url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    return res.ok;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}
