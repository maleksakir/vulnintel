/**
 * Constant-time string comparison. Use for any secret/token check — a plain
 * `===` leaks comparison length via early-exit timing.
 */
export function timingSafeEqual(a: string, b: string): boolean {
  const encoder = new TextEncoder();
  const aBytes = encoder.encode(a);
  const bBytes = encoder.encode(b);

  // Compare against a fixed-length buffer so the loop length itself doesn't
  // leak which input is longer/shorter.
  const len = Math.max(aBytes.length, bBytes.length, 32);
  let diff = aBytes.length ^ bBytes.length;

  for (let i = 0; i < len; i++) {
    diff |= (aBytes[i] ?? 0) ^ (bBytes[i] ?? 0);
  }

  return diff === 0;
}
