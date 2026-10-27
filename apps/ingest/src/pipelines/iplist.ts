import { markIngestFinished, markIngestStarted } from '../lib/server/ingestRun';
import type { Env } from '../types';

const CF_API_BASE = 'https://api.cloudflare.com/client/v4';
const LIST_NAME = 'corp_authorized_sources';

interface CfListItem {
  id: string;
  ip: string;
  comment?: string;
}

interface CfListsResponse {
  success: boolean;
  result: Array<{ id: string; name: string }>;
  errors: Array<{ message: string }>;
}

interface CfListItemsResponse {
  success: boolean;
  result: CfListItem[];
  result_info?: { cursor?: string };
  errors: Array<{ message: string }>;
}

interface CfDeleteResponse {
  success: boolean;
  errors: Array<{ message: string }>;
}

/**
 * IP allowlist prune (cron: 0 4 * * *).
 * Removes expired entries from the corp_authorized_sources Cloudflare IP List.
 * Expiry is encoded in the item comment as "expires:<unix-ms>".
 * Entries without an expiry tag are treated as permanent.
 */
export async function runIpListPrune(env: Env, ctx: ExecutionContext): Promise<void> {
  const startedAt = Date.now();
  await markIngestStarted(env, 'IPLIST_PRUNE');

  let pruned = 0;
  let lastError: string | undefined;

  try {
    const listId = await resolveListId(env);

    if (listId) {
      const items = await fetchAllListItems(env, listId);
      const expiredIds = items
        .filter((item) => {
          const m = /expires:(\d+)/.exec(item.comment ?? '');
          return m && parseInt(m[1]!, 10) < startedAt;
        })
        .map((item) => item.id);

      if (expiredIds.length > 0) {
        const delRes = await cfFetch<CfDeleteResponse>(
          env,
          `POST /accounts/${env.CLOUDFLARE_ACCOUNT_ID}/rules/lists/${listId}/items/delete`,
          { items: expiredIds.map((id) => ({ id })) },
        );
        if (!delRes.success) {
          throw new Error(`CF list delete failed: ${JSON.stringify(delRes.errors)}`);
        }
        pruned = expiredIds.length;
      }
    }
  } catch (err) {
    lastError = String(err);
  }

  await markIngestFinished(env, 'IPLIST_PRUNE', lastError ? 'FAILED' : 'OK', pruned, 0, lastError);

  ctx.waitUntil(
    Promise.resolve(
      env.ANALYTICS.writeDataPoint({
        blobs: ['IPLIST_PRUNE', lastError ? 'FAILED' : 'OK', 'IPLIST_PRUNE', '', '', '', ''],
        doubles: [startedAt, Date.now(), pruned, 0, Date.now() - startedAt],
        indexes: ['ingest_run'],
      }),
    ),
  );
}

async function resolveListId(env: Env): Promise<string | null> {
  const data = await cfFetch<CfListsResponse>(
    env,
    `GET /accounts/${env.CLOUDFLARE_ACCOUNT_ID}/rules/lists`,
  );
  return data.result.find((l) => l.name === LIST_NAME)?.id ?? null;
}

async function fetchAllListItems(env: Env, listId: string): Promise<CfListItem[]> {
  const items: CfListItem[] = [];
  let cursor: string | undefined;

  do {
    const qs = cursor ? `?cursor=${encodeURIComponent(cursor)}` : '';
    const data = await cfFetch<CfListItemsResponse>(
      env,
      `GET /accounts/${env.CLOUDFLARE_ACCOUNT_ID}/rules/lists/${listId}/items${qs}`,
    );
    items.push(...data.result);
    cursor = data.result_info?.cursor;
  } while (cursor);

  return items;
}

async function cfFetch<T extends { success: boolean; errors: Array<{ message: string }> }>(
  env: Env,
  pathAndMethod: string,
  body?: unknown,
): Promise<T> {
  const spaceIdx = pathAndMethod.indexOf(' ');
  const method = pathAndMethod.slice(0, spaceIdx);
  const path = pathAndMethod.slice(spaceIdx + 1);

  const res = await fetch(`${CF_API_BASE}${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${env.CLOUDFLARE_API_TOKEN}`,
      'Content-Type': 'application/json',
    },
    ...(body !== undefined && { body: JSON.stringify(body) }),
  });

  if (!res.ok) throw new Error(`Cloudflare API ${res.status}: ${path}`);
  return res.json<T>();
}
