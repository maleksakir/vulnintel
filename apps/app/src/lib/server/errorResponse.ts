import type { ErrorCode, ErrorEnvelope } from '@threat-lens/contracts';

export function errorResponse(
  code: ErrorCode,
  message: string,
  requestId: string,
  status: number,
  opts: {
    retryAfterSeconds?: number;
    details?: Record<string, unknown>;
  } = {},
): Response {
  const envelope: ErrorEnvelope = {
    error: {
      code,
      message,
      retryAfterSeconds: opts.retryAfterSeconds ?? null,
      requestId,
      ...(opts.details ? { details: opts.details } : {}),
    },
  };

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };

  if (status === 429 && opts.retryAfterSeconds) {
    headers['Retry-After'] = String(opts.retryAfterSeconds);
  }

  return new Response(JSON.stringify(envelope), { status, headers });
}
