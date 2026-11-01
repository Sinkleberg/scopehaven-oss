// Live operator collection only. Importing/serializing facts never mints trust.
import { performance } from 'node:perf_hooks';
import { canonical, freezeEvidence, bindTemporalFacts, sameBinding } from './binding.mjs';
import { isAuthenticPaymentsWindow } from '../observers/payments-double.mjs';

export const TEMPORAL_EVIDENCE_SCHEMA = 'scopehaven-refund-evidence/1';
const BUNDLES = new WeakMap();
const FIXTURES = new WeakSet();
const copy = value => JSON.parse(JSON.stringify(value));
function expectedIdentity(contract) { return { runId: contract.runId, targetId: contract.targetId, buildHash: contract.buildHash }; }
function snapshotProblems(snapshot, contract, closed) {
  const problems = [];
  if (snapshot?.schema !== 'scopehaven-refund-app-evidence/1') problems.push('application-schema-invalid');
  if (canonical(expectedIdentity(snapshot ?? {})) !== canonical(expectedIdentity(contract))) problems.push('application-identity-mismatch');
  if (typeof snapshot?.sourceId !== 'string' || !snapshot.sourceId || snapshot.sourceId.length > 128) problems.push('application-source-missing');
  if (!Array.isArray(snapshot?.events) || !Array.isArray(snapshot?.instructions)) problems.push('application-records-missing');
  if (snapshot?.horizon?.id !== contract.horizon.id) problems.push('application-horizon-mismatch');
  if (snapshot?.horizon?.deadlineMs !== contract.horizon.deadlineMs) problems.push('application-deadline-mismatch');
  const timing = snapshot?.timing;
  if (typeof timing?.clockId !== 'string' || !timing.clockId || !Number.isFinite(timing?.startedAtMs) || timing.startedAtMs < 0) problems.push('application-timing-missing');
  const coverage = snapshot?.coverage;
  const complete = coverage?.source === 'application' && coverage.complete === true && coverage.ordered === true
    && coverage.lateEvents === 0 && Array.isArray(coverage.problems) && coverage.problems.length === 0
    && coverage.fromSeq === 1 && coverage.toSeq === snapshot?.horizon?.watermark;
  if (closed && (!complete || snapshot.horizon?.closed !== true || snapshot.horizon?.sealed !== true || snapshot.horizon?.pending !== 0
    || !Number.isSafeInteger(snapshot.horizon?.watermark) || snapshot.horizon.watermark < 0)) problems.push('application-horizon-not-closed');
  if (closed && Array.isArray(snapshot?.events) && snapshot.horizon?.watermark !== Math.max(0, ...snapshot.events.map(row => row.seq))) problems.push('application-watermark-mismatch');
  if (closed && (!Number.isFinite(timing?.closedAtMs) || timing.closedAtMs < timing.startedAtMs)) problems.push('application-closed-timing-missing');
  if (closed && Array.isArray(snapshot?.events)) {
    let previous = timing?.startedAtMs;
    for (const event of snapshot.events) {
      if (!Number.isFinite(event.atMs) || event.atMs < timing?.startedAtMs || event.atMs > timing?.closedAtMs || event.atMs < previous) problems.push('application-event-timing-invalid');
      previous = event.atMs;
    }
  }
  return problems;
}
export function createTemporalCollector({ fixture, payments, contract }) {
  if (!fixture || typeof fixture.snapshot !== 'function' || !payments || typeof payments.mark !== 'function' || typeof payments.collectPayments !== 'function'
    || typeof payments.registerTemporalRun !== 'function' || typeof payments.dispatchWitness !== 'function') throw new Error('Temporal collection requires live fixture and payment source capabilities.');
  const expected = freezeEvidence(copy(contract));
  if (expected?.schema !== 'scopehaven-refund-contract/1' || !expected.horizon?.id || !Number.isSafeInteger(expected.horizon.deadlineMs)
    || expected.horizon.deadlineMs <= 0 || !Array.isArray(expected.authorities) || !expected.authorities.length) throw new Error('Temporal collection requires a bounded, nonempty expected contract.');
  const contractSnapshot = canonical(expected), identity = freezeEvidence(expectedIdentity(expected));
  let state = 'new', from, initial, startedAt, observing = false;
  const operations = [];
  // This capability stays with the operator. Neither app records nor headers
  // can create a window, move its bounds, or choose its instruction.
  async function observeOperation(metadata, action) {
    if (state !== 'active' || observing) throw new Error('refund-operator-window-state');
    if (!['invoke', 'release', 'revoke'].includes(metadata?.kind) || typeof action !== 'function') throw new Error('refund-operator-operation-invalid');
    const operation = copy(metadata);
    observing = true;
    try {
      const lower = await payments.mark(), startMs = performance.now() - startedAt;
      let result, error;
      try { result = await action(); } catch (caught) { error = caught; }
      const endMs = performance.now() - startedAt, upper = await payments.mark();
      const response = result?.json ?? result;
      operations.push(freezeEvidence({ ...operation, index: operations.length + 1,
        fromSeq: lower.seq, toSeq: upper.seq, epoch: lower.epoch, startMs, endMs,
        complete: !error && lower.ok && upper.ok && lower.epoch === upper.epoch,
        response: { status: result?.status ?? null, complete: result?.complete ?? !error,
          state: response?.state ?? null, effectId: response?.effectId ?? null } }));
      if (error) throw error;
      return result;
    } finally { observing = false; }
  }
  async function begin() {
    if (state !== 'new') throw new Error('A temporal collector is single-use.');
    state = 'starting';
    if (FIXTURES.has(fixture)) { state = 'failed'; throw new Error('The application source already belongs to a temporal collector.'); }
    FIXTURES.add(fixture);
    try {
      payments.registerTemporalRun({ ...identity, horizonId: expected.horizon.id });
      startedAt = performance.now();
      from = await payments.mark();
      initial = freezeEvidence(copy(await fixture.snapshot({ horizonId: expected.horizon.id, deadlineMs: expected.horizon.deadlineMs, close: false })));
      state = 'active';
    } catch (error) { state = 'failed'; throw error; }
  }
  async function finish() {
    if (state !== 'active' || observing) throw new Error('An active temporal collector can finish exactly once.');
    state = 'finishing';
    const problems = new Set(snapshotProblems(initial, expected, false));
    let application = null, paymentBundle = null;
    try { application = freezeEvidence(copy(await fixture.snapshot({ horizonId: expected.horizon.id, deadlineMs: expected.horizon.deadlineMs, close: true }))); }
    catch { problems.add('application-closure-failed'); }
    for (const problem of snapshotProblems(application, expected, true)) problems.add(problem);
    if (application?.sourceId !== initial?.sourceId) problems.add('application-source-changed');
    if (application?.timing?.clockId !== initial?.timing?.clockId || application?.timing?.startedAtMs !== initial?.timing?.startedAtMs) problems.add('application-clock-or-start-changed');
    if (canonical(initial?.events) !== canonical(application?.events?.slice(0, initial?.events?.length))) problems.add('application-initial-event-prefix-changed');
    for (const original of initial?.instructions ?? []) {
      const current = application?.instructions?.find(row => row.instructionId === original.instructionId);
      if (!sameBinding(original, current)) problems.add('application-initial-instruction-binding-changed');
    }
    if (initial?.events?.some(row => ['accepted', 'attempt', 'terminal'].includes(row.type))) problems.add('application-work-before-provider-window');
    // A registered live-source closure, not elapsed silence, establishes the app
    // boundary. The witness separately closes this provider collection window.
    try {
      await payments.dispatchWitness(from);
      paymentBundle = await payments.collectPayments(from, await payments.mark());
    } catch { problems.add('payments-collection-failed'); }
    if (!isAuthenticPaymentsWindow(paymentBundle)) problems.add('payments-custody-untrusted');
    if (paymentBundle?.coverage !== 'complete' || paymentBundle?.scope?.evidence !== 'authoritative') problems.add('payments-coverage-incomplete');
    if (canonical(paymentBundle?.temporalRun) !== canonical({ ...identity, horizonId: expected.horizon.id })) problems.add('payments-run-identity-mismatch');
    // Read the same live source once more after provider delivery. A fixture that
    // reports late in-scope events cannot hide them behind its first watermark.
    try {
      const finalApplication = freezeEvidence(copy(await fixture.snapshot({ horizonId: expected.horizon.id, deadlineMs: expected.horizon.deadlineMs, close: true })));
      if (finalApplication.sourceId !== application?.sourceId || canonical(finalApplication.events) !== canonical(application?.events)
        || canonical(finalApplication.instructions) !== canonical(application?.instructions) || canonical(finalApplication.timing) !== canonical(application?.timing)) problems.add('application-evidence-after-closure');
      application = finalApplication;
      for (const problem of snapshotProblems(application, expected, true)) problems.add(problem);
    } catch { problems.add('application-final-read-failed'); }
    // Independent of recorder delivery: the registered operator-supplied live
    // source must close consistently on both reads. This is a synthetic source
    // capability boundary, not authentication of arbitrary application records.
    const independentClosure = isAuthenticPaymentsWindow(paymentBundle)
      && canonical(paymentBundle.temporalRun) === canonical({ ...identity, horizonId: expected.horizon.id })
      && application !== null && ![...problems].some(problem => problem.startsWith('application-'));
    if (!['external', 'none', 'observer-dispatched'].includes(paymentBundle?.witnessSource)) problems.add('payments-witness-source-unknown');
    if (paymentBundle?.witnessSource === 'observer-dispatched' && !independentClosure) problems.add('observer-witness-independent-closure-missing');
    const elapsedMs = performance.now() - startedAt;
    const operator = freezeEvidence({ clockId: 'operator-monotonic', startedAtMs: 0, closedAtMs: elapsedMs, operations: [...operations] });
    const facts = bindTemporalFacts({ application, payments: paymentBundle, contract: expected, operator });
    for (const problem of facts.problems) problems.add(problem);
    const horizon = { id: expected.horizon.id, deadlineMs: expected.horizon.deadlineMs, closed: application?.horizon?.closed === true, sealed: application?.horizon?.sealed === true,
      watermark: application?.horizon?.watermark ?? null, pending: application?.horizon?.pending ?? null, elapsedMs,
      timing: application?.timing ?? null,
      boundary: 'explicit-application-drain-and-original-provider-witness', effectsAfterClosure: 'outside-declared-claim' };
    const bundle = freezeEvidence({ schema: TEMPORAL_EVIDENCE_SCHEMA, identity, application, payments: paymentBundle, operator, horizon,
      coverage: problems.size ? 'incomplete' : 'complete', problems: [...problems].sort() });
    BUNDLES.set(bundle, { contractSnapshot, facts, paymentCustody: isAuthenticPaymentsWindow(paymentBundle), independentClosure });
    state = 'finished';
    return bundle;
  }
  return Object.freeze({ begin, observeOperation, finish });
}
export function inspectTemporalEvidence(bundle, contract) {
  const minted = BUNDLES.get(bundle);
  if (!minted || !Object.isFrozen(bundle)) return freezeEvidence({ trusted: false, coverage: 'failed', problems: ['temporal-custody-untrusted'] });
  if (!minted.paymentCustody) return freezeEvidence({ trusted: false, coverage: 'failed', problems: ['payments-custody-untrusted'] });
  if (canonical(contract) !== minted.contractSnapshot) return freezeEvidence({ trusted: false, coverage: 'failed', problems: ['expected-contract-mismatch'] });
  return freezeEvidence({ trusted: true, coverage: bundle.coverage, problems: bundle.problems, facts: minted.facts,
    independentClosure: minted.independentClosure });
}
