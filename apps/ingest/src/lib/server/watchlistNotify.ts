import type { Env } from '../../types';

// Watchlist notifications. After reconciliation materializes new matches, fire
// a one-time digest per watchlist to every enabled webhook on it, covering the
// still-NEW, not-yet-notified matches. Runs inside the watchlist-ingest
// consumer invocation (pipelines/watchlistQueue.ts), so it shares that
// invocation's budget — hence the bounds below.

// Cap digest size per watchlist (keeps the POST body and the UPDATE set bounded).
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
 * Dispatch new-match digests.
 *
 * Grouped BY WATCHLIST, not by webhook. `watchlist_match.notified_at` is keyed
 * (watchlist_id, cve_id) — there is no per-webhook notification state — so
 * stamping it after the first webhook's POST made every other webhook on that
 * watchlist read an empty pending set and never receive anything. A second
 * Slack channel or a generic endpoint added alongside it was silently dead.
 * The pending set is now snapshotted once per watchlist and posted to all of
 * its enabled webhooks before the stamp is written.
 *
 * Delivery semantics: stamp if AT LEAST ONE webhook accepted the digest. The
 * alternative (stamp only on unanimous success) means one permanently-broken
 * endpoint re-sends the same digest to the healthy ones on every run, forever
 * — alert fatigue that trains operators to ignore the channel. A webhook that
 * missed a digest is visible instead through its `last_dispatch_status` in the
 * watchlist UI. Within a single webhook, delivery is still at-least-once: a
 * run where every endpoint fails leaves notified_at NULL and retries.
 *
 * Budget: 1 read for enabled webhooks, then per watchlist 1 read for pending
 * matches + 1 batched UPDATE, and one fetch per webhook (capped at
 * MAX_WEBHOOKS_PER_RUN). Bounded well under the per-invocation D1 +
 * subrequest budgets.
 */
export async function dispatchWatchlistNotifications(env: Env): Promise<NotifyResult> {
  const webhooksRes = await env.DB.prepare(
    `SELECT w.webhook_id, w.watchlist_id, w.kind, w.url, wl.name AS watchlist_name
     FROM watchlist_webhook w
     JOIN watchlist wl ON wl.watchlist_id = w.watchlist_id
     WHERE w.enabled = 1
     ORDER BY w.watchlist_id ASC, w.webhook_id ASC
     LIMIT ?`,
  )
    .bind(MAX_WEBHOOKS_PER_RUN)
    .all<WebhookRow>();

  const byWatchlist = new Map<number, WebhookRow[]>();
  for (const wh of webhooksRes.results) {
    const list = byWatchlist.get(wh.watchlist_id);
    if (list) list.push(wh);
    else byWatchlist.set(wh.watchlist_id, [wh]);
  }

  let webhooksDispatched = 0;
  let matchesNotified = 0;

  for (const [watchlistId, webhooks] of byWatchlist) {
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
      .bind(watchlistId, MAX_MATCHES_PER_DIGEST)
      .all<PendingMatchRow>();

    if (pending.results.length === 0) continue;

    const now = Date.now();
    let anyDelivered = false;

    for (const wh of webhooks) {
      const ok = await postWebhook(wh, pending.results, env);
      if (ok) {
        anyDelivered = true;
        webhooksDispatched++;
      } else {
        env.ANALYTICS.writeDataPoint({
          blobs: ['WATCHLIST_NOTIFY', 'DISPATCH_FAILED', String(wh.webhook_id), '', '', '', ''],
          doubles: [watchlistId, pending.results.length, 0, 0, 0],
          indexes: ['watchlist_consumer_processed'],
        });
      }
      // Per-webhook outcome, so an endpoint that keeps failing is visible in
      // the UI rather than just silently missing digests. Best-effort.
      env.DB.prepare(
        `UPDATE watchlist_webhook SET last_dispatch_at = ?, last_dispatch_status = ?
         WHERE webhook_id = ?`,
      )
        .bind(now, ok ? 'OK' : 'FAILED', wh.webhook_id)
        .run()
        .catch(() => {});
    }

    // Every endpoint failed → leave notified_at NULL so the next run retries.
    if (!anyDelivered) continue;

    await env.DB.batch(
      pending.results.map((m) =>
        env.DB.prepare(
          `UPDATE watchlist_match SET notified_at = ? WHERE watchlist_id = ? AND cve_id = ?`,
        ).bind(now, watchlistId, m.cve_id),
      ),
    );
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

  const body = JSON.stringify(payload);
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };

  // Optional HMAC-SHA256 over the exact body, so a receiver can verify the
  // digest came from us and wasn't replayed or forged. Only set when the
  // secret is configured (`wrangler secret put WEBHOOK_SIGNING_SECRET`);
  // unsigned delivery stays the default so an unconfigured deploy still
  // notifies.
  if (env.WEBHOOK_SIGNING_SECRET) {
    try {
      headers['X-ThreatLens-Signature'] = `sha256=${await hmacHex(
        env.WEBHOOK_SIGNING_SECRET,
        body,
      )}`;
    } catch {
      // Signing failure must not block the alert.
    }
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(wh.url, {
      method: 'POST',
      headers,
      body,
      // Do NOT follow redirects. The URL is validated as https: at creation
      // time, but with default redirect handling a receiver could answer 302
      // with a plaintext http:// or internal-address Location and the runtime
      // would re-POST the digest there, defeating the scheme check entirely.
      // A 3xx is treated as a delivery failure and surfaced to the operator.
      redirect: 'manual',
      signal: controller.signal,
    });
    // `res.ok` is false for 3xx already; being explicit documents the intent.
    if (res.status >= 300 && res.status < 400) return false;
    return res.ok;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

/** HMAC-SHA256 of `body` under `secret`, lowercase hex. */
async function hmacHex(secret: string, body: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(body));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
