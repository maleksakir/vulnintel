/**
 * Shared embedding contract (Section 5.4).
 *
 * Both workers have their own concrete implementation of EmbedFn at
 * apps/<worker>/src/lib/server/embed.ts. This file is TYPE-ONLY.
 *
 * Keeping contracts type-only prevents any runtime coupling between workers;
 * the two implementations must be byte-identical in behaviour (same model,
 * same truncation rule, same retry policy). Conformance is verified by the
 * Phase 3 snapshot test.
 */

export type EmbedFn = (
  /** The Workers AI binding from the worker's Env. */
  ai: { run: (model: string, input: { text: string }) => Promise<{ data: number[][] }> },
  /** Input text — caller must pre-truncate to ≤ 1500 chars. */
  text: string,
) => Promise<number[]>;

/** Model identifier pinned across both workers. */
export const EMBED_MODEL = '@cf/baai/bge-base-en-v1.5' as const;

/** Maximum character length fed to the embedding model. */
export const EMBED_MAX_CHARS = 1500 as const;

/** Dimensionality of the embedding vector produced by EMBED_MODEL. */
export const EMBED_DIMENSIONS = 768 as const;
