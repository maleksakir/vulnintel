import { EMBED_MAX_CHARS, EMBED_MODEL } from '@threat-lens/contracts';

type AiLike = {
  run: (model: string, input: { text: string }) => Promise<{ data: number[][] }>;
};

/**
 * Concrete embed implementation for the app worker.
 * Byte-for-byte identical behaviour to apps/ingest/src/lib/server/embed.ts.
 */
export async function embed(ai: Ai, text: string): Promise<number[]> {
  const truncated = text.slice(0, EMBED_MAX_CHARS);
  const result = await (ai as AiLike).run(EMBED_MODEL, { text: truncated });
  const vec = result.data[0];
  if (!vec || vec.length === 0) throw new Error('Workers AI returned empty embedding vector');
  return vec;
}

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
