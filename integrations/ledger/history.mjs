// Permission history: for each check, when its verdict changed, read only from a verified ledger
// (verifyLedger's result) and only between runs with the same comparable identity. A change of
// suite, policy, fixture, evaluator, application or evidence origin starts a new segment that is
// never compared with the one before it. A payments-pack run's rows compare only with runs of the
// same target and pack (comparePaymentsRuns' rule), never with a run export's. This is a view of
// recorded verdicts, not a re-grading, and it applies only the identity fields the entries carry,
// not every rule compareRuns or comparePaymentsRuns applies.
import { LEDGER_VERSION, isPaymentsRun } from './verify.mjs';

// The fields that must match for two runs' verdicts to be compared (compareRuns' stable keys).
export const COMPARABLE = Object.freeze(['schemaVersion', 'applicationId', 'suiteId', 'suiteHash', 'policyHash', 'fixtureHash', 'fixtureVersion', 'adapterVersion',
  'evaluatorHash', 'runtimeMode', 'evidenceOrigin', 'profileHash', 'assertionSchemaVersion', 'contextId']);
export const PAYMENTS_COMPARABLE = Object.freeze(['schema', 'targetId', 'packSha256']);
const comparableOf = run => isPaymentsRun(run) ? PAYMENTS_COMPARABLE : COMPARABLE;
const identityKey = run => JSON.stringify(comparableOf(run).map(field => [field, Object.hasOwn(run, field) ? run[field] : null]));
// A payments run whose target or pack is not text (the pack's reader puts no type on them) is compared with no other run.
const uncomparable = run => isPaymentsRun(run) && (typeof run.targetId !== 'string' || typeof run.packSha256 !== 'string');

export function permissionHistory(verified) {
  if (!verified || verified.ledger !== LEDGER_VERSION || verified.verdict !== 'verified' || !Array.isArray(verified.entries)) throw new Error('History is read only from a verified ledger.');
  // One current segment per kind, so a payments run (which entries never held before) does not cut a run export's history.
  const segments = [], currentOf = new Map();
  for (const entry of verified.entries) for (const run of entry.runs) {
    const key = uncomparable(run) ? `uncomparable ${entry.index} ${run.subject}` : identityKey(run), kind = isPaymentsRun(run) ? 'payments' : 'run';
    let current = currentOf.get(kind);
    if (!current || current.key !== key) {
      current = { key, identity: Object.fromEntries(comparableOf(run).filter(field => Object.hasOwn(run, field)).map(field => [field, run[field]])), runs: [], changes: [], last: new Map() };
      segments.push(current); currentOf.set(kind, current);
    }
    const at = { entry: entry.index, recordedAt: entry.recordedAt, runId: run.id ?? null, build: run.build ?? null };
    current.runs.push(at);
    for (const [check, status] of run.verdicts) {
      const before = current.last.get(check);
      if (before !== undefined && before !== status) current.changes.push({ check, from: before, to: status, ...at });
      current.last.set(check, status);
    }
  }
  return {
    ledger: LEDGER_VERSION, log: verified.log, entries: verified.covered, witness: 'none',
    meaning: 'Verdict changes between runs with the same comparable identity, as recorded in a verified ledger. Not a re-grading, and not externally witnessed.',
    segments: segments.map(({ identity, runs, changes, last }) => ({ identity, runs, changes, current: Object.fromEntries(last) })),
  };
}
