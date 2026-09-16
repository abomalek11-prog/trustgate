import { describe, expect, it } from 'vitest';
import { THESIS, THESIS_WORD_COUNT } from '@/lib/thesis';

describe('two-year thesis', () => {
  it('is at most 300 words and never frames trust as a score', () => {
    expect(THESIS_WORD_COUNT).toBeLessThanOrEqual(300);
    expect(THESIS_WORD_COUNT).toBeGreaterThan(150);
    expect(THESIS).toMatch(/not .*a global score/);
  });
});
