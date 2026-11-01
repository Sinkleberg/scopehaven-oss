// The ledger as EVID-SUBJECT's operator-held, unwitnessed anchor. EVID-SUBJECT (integrations/evid-subject/custody.mjs)
// verifies an evidence chain against an anchor { count, head } the observer kept outside the
// subject's reach; without one, a subject that drops the tail and reseals the chain is caught only by
// custody. This returns that anchor from a verified ledger, from entries a signed checkpoint covers,
// in the shape verifyChain(entries, anchor) takes. It is an operator-held, unwitnessed anchor: held
// outside the application under test only while the operator's folder and key are.
import { LEDGER_VERSION } from './verify.mjs';

export function anchorFor(verified, { runId, source }) {
  if (!verified || verified.ledger !== LEDGER_VERSION || verified.verdict !== 'verified' || !Array.isArray(verified.entries)) throw new Error('Anchors are read only from a verified ledger.');
  // A verified ledger records each run id once, so there is at most one anchor per run and source.
  // Should two ever appear, nothing is returned rather than choosing between them.
  const found = verified.entries.flatMap(entry => entry.runs.filter(run => run.id === runId).flatMap(run => run.anchors.filter(a => a.source === source).map(anchor => ({ entry, anchor }))));
  if (found.length > 1) throw new Error(`Two anchors are recorded for run ${runId} and ${source}; refusing to choose.`);
  if (!found.length) return null;
  const [{ entry, anchor }] = found;
  return Object.freeze({ count: anchor.count, head: anchor.head, custody: anchor.custody, source, runId, entry: entry.index, coveredBy: verified.covered, witness: 'none', heldBy: 'operator' });
}
