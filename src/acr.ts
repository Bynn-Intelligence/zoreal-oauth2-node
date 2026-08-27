import type { AcrValue } from './types';

/**
 * The assurance vocabulary, weakest to strongest. Verification accepts equal
 * or stronger: an RP requiring zoreal.device is satisfied by a zoreal.live
 * token, never the reverse.
 */
export const ACR_ORDER: Readonly<Record<AcrValue, number>> = Object.freeze({
  'zoreal.session': 0,
  'zoreal.device': 1,
  'zoreal.live': 2,
});

const RANKS = new Map<string, number>(Object.entries(ACR_ORDER));

/** The rank of a value in the vocabulary; undefined for anything outside it. */
export function acrRank(value: unknown): number | undefined {
  return typeof value === 'string' ? RANKS.get(value) : undefined;
}
