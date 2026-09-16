/** Writes docs/thesis.md from the single source of truth in lib/thesis.ts. */
import { writeFileSync } from 'node:fs';
import { THESIS, THESIS_WORD_COUNT } from '../lib/thesis';

writeFileSync(
  'docs/thesis.md',
  '# Two-year thesis on agent identity and reputation\n\n_' + THESIS_WORD_COUNT + ' words. Source of truth: `lib/thesis.ts` (also rendered at `/architecture`)._\n\n' + THESIS + '\n',
);
console.log('docs/thesis.md written (' + THESIS_WORD_COUNT + ' words)');
