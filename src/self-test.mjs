// --self-test (scopehaven assess, check-config and gate): the known-negative self-test (src/known-negative.mjs) over a
// target's validated profile, run before anything is authorized, started or sent. It plants violations through the pure
// evaluators a run uses and contacts nothing. A check with a predicate that cannot fail (its violation still reads pass, or
// is never decided) or that always fails (its best observation fails too) is broken: its pass, or its fail, shows nothing.
// The run is still made and its verdicts are unchanged, but it never reads clean: assess and check-config exit 1, and the
// gate adds the reason (check-cannot-fail, check-always-fails) and exits 1. Unprovable, partial and errored checks are
// reported, never refused: they say what was not shown, not that a check is broken. The report names check ids,
// positions, kinds, outcomes and reason codes only, never an expected, planted or declared value.
import { knownNegativeTarget } from './known-negative.mjs';

// The refusal each broken predicate outcome gives, in this order.
export const SELF_TEST_REASONS = Object.freeze([['cannot-fail', 'check-cannot-fail'], ['always-fails', 'check-always-fails']]);
export const SELF_TEST_UNSUPPORTED = 'self-test-unsupported-target';

export class SelfTestError extends Error {
  constructor(code) { super('--self-test applies to an HTTP contract target from --config.'); this.name = 'SelfTestError'; this.code = code; }
}

/** The self-test of one registered target (a registry.list() entry) and its validated profile. Only an HTTP contract
 * target has checks this mode plants; any other target is refused, never reported as having nothing to prove. */
export function selfTestFor(entry, profile) {
  if (entry?.kind !== 'http-contract' || profile?.id !== entry.id) throw new SelfTestError(SELF_TEST_UNSUPPORTED);
  return knownNegativeTarget(profile);
}

/** The reasons a self-test report refuses a clean result for: one per broken predicate outcome it has. */
export function selfTestReasons(report) {
  const outcomes = new Set((Array.isArray(report?.checks) ? report.checks : []).flatMap(c => (Array.isArray(c?.predicates) ? c.predicates : []).map(p => p?.outcome)));
  return SELF_TEST_REASONS.filter(([outcome]) => outcomes.has(outcome)).map(([, reason]) => reason);
}

/** The broken checks' ids, in profile order. */
export const brokenChecks = report => (Array.isArray(report?.checks) ? report.checks : []).filter(c => c?.outcome === 'broken').map(c => c.id);
