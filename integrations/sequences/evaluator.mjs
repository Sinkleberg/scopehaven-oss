// The sequence evaluator identity. Every module that decides or recomputes a sequence verdict is listed here
// (paths from the scopehaven folder), and SEQUENCE_EVALUATOR_HASH digests exactly those sources:
//   - sequence.mjs decides effect rows (decideAssertion) and response-status rows (decideStatusAssertion);
//   - run-validator.mjs recomputes both from a saved run;
//   - src/effect-events.mjs (with src/body-fields.mjs, the declared body-field rules it applies; sequences refuse
//     field selectors), src/custody.mjs and src/effect-lineage.mjs are the effect rules and custody they apply.
// A scopehaven-sequence-run/3 record seals this hash, the saved run the regression gate reads carries it, and the
// gate compares only runs of one evaluator: changing how sequence runs are judged changes the identity.
import { readFile } from 'node:fs/promises';
import { digest } from '../../src/domain.mjs';

export const SEQUENCE_EVALUATOR_FILES = Object.freeze(['integrations/sequences/sequence.mjs', 'integrations/sequences/run-validator.mjs', 'src/effect-events.mjs', 'src/body-fields.mjs', 'src/idempotency.mjs', 'src/custody.mjs', 'src/effect-lineage.mjs']);
export const SEQUENCE_EVALUATOR_HASH = digest({ files: await Promise.all(SEQUENCE_EVALUATOR_FILES.map(async name => [name, await readFile(new URL(`../../${name}`, import.meta.url), 'utf8')])) });
