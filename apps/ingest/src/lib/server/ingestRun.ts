import type { Env } from '../../types';

export async function markIngestStarted(env: Env, source: string): Promise<void> {
  await env.DB.prepare('UPDATE ingest_run SET last_started_at = ? WHERE source = ?')
    .bind(Date.now(), source)
    .run();
}

export async function markIngestFinished(
  env: Env,
  source: string,
  status: 'OK' | 'PARTIAL' | 'FAILED',
  processed: number,
  failed: number,
  error?: string,
): Promise<void> {
  await env.DB.prepare(
    `UPDATE ingest_run SET
       last_finished_at = ?,
       last_status      = ?,
       records_processed = ?,
       records_failed   = ?,
       last_error       = ?
     WHERE source = ?`,
  )
    .bind(Date.now(), status, processed, failed, error ?? null, source)
    .run();
}
