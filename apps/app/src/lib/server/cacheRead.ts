/**
 * KV read-through helper. Fetches cached JSON on hit; calls fallback on miss
 * and stores the result with the given TTL (seconds).
 */
export async function cacheReadJson<T>(
  cache: KVNamespace,
  key: string,
  ttlSeconds: number,
  fallback: () => Promise<T>,
): Promise<T> {
  const cached = await cache.get(key, 'json');
  if (cached !== null) return cached as T;

  const value = await fallback();
  await cache.put(key, JSON.stringify(value), { expirationTtl: ttlSeconds });
  return value;
}
