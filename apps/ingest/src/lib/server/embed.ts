import type { EmbedFn } from '@threat-lens/contracts';
import { EMBED_MAX_CHARS, EMBED_MODEL } from '@threat-lens/contracts';

/**
 * Concrete embed implementation for the ingest worker.
 * Byte-for-byte identical behaviour to apps/app/src/lib/server/embed.ts.
 */
export const embed: EmbedFn = async (ai, text) => {
  const truncated = text.slice(0, EMBED_MAX_CHARS);
  const result = await ai.run(EMBED_MODEL, { text: truncated });
  const vec = result.data[0];
  if (!vec || vec.length === 0) throw new Error('Workers AI returned empty embedding vector');
  return vec;
};

/** Builds the text passed to the embedding model from a CVE record. */
export function buildEmbedText(record: {
  description: string;
  cwes: ReadonlyArray<string>;
  cpes: ReadonlyArray<{ vendor: string; product: string }>;
}): string {
  const vendors = [...new Set(record.cpes.map((c) => c.vendor))].slice(0, 5).join(' ');
  const products = [...new Set(record.cpes.map((c) => c.product))].slice(0, 5).join(' ');
  const cwes = record.cwes.join(' ');
  return `${record.description} ${cwes} ${vendors} ${products}`.trim();
}
