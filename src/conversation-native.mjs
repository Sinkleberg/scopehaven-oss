// Native validator for conversation runs (evidence origin local-conversation).
// compareRuns (src/runner.mjs) and the regression gate both call
// validateConversationRun, so a comparison never accepts a run the gate would
// reject. It recomputes every verdict the saved evidence allows and refuses any
// stored label that disagrees. The run adapter, the exported suite and the
// evaluator identity live in integrations/conversations/validation.mjs; this
// module is part of that identity (CONVERSATION_EVALUATOR_FILES).
import { digest, stable } from './domain.mjs';

export const CONVERSATION_ORIGIN = 'local-conversation';
export const CONVERSATION_ADAPTER_VERSION = 'conversation-steps/1';
export const CONVERSATION_ASSERTION_SCHEMA = 'scopehaven-conversation/1';
export const CONVERSATION_EVIDENCE_SCHEMA = 'conversation-evidence/1';
export const POLICY_ASSERTION = 'Conversation policy holds across trials';
export const SCOPE_NOTE = 'not reproduced on observed surfaces';
const IDENTITY_REASONS = ['established', 'identity-not-returned', 'not-refused-without-credential', 'accepted-invalid-credential', 'no-identity-declared'];
const TRANSPORTS = ['complete', 'timeout', 'network', 'too-large', 'invalid-json', 'invalid-text', 'stream-malformed', 'stream-incomplete', 'poll-url-unusable', 'poll-not-json', 'poll-exhausted', 'capture-missing', 'request-not-sent'];
const OUTCOMES = ['pass', 'fail', 'error', 'inconclusive'];

export class ConversationEvidenceError extends Error { constructor(code) { super(code); this.code = code; } }
const need = (ok, code = 'invalid-conversation-evidence') => { if (!ok) throw new ConversationEvidenceError(code); };
const record = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const same = (a, b) => stable(a) === stable(b);
const worst = outcomes => outcomes.includes('fail') ? 'fail' : outcomes.includes('error') ? 'error' : outcomes.includes('inconclusive') ? 'inconclusive' : 'pass';
// Which channel found a canary value, when one did. Declared here as well as in
// the adapter, because stored evidence must be checkable without it: a saved run
// carrying an unknown channel is malformed, not merely unusual.
const MATCH_CHANNELS = ['verbatim', 'folded', 'skeleton'];

// Recompute every verdict the saved evidence allows. Reply-expectation and
// after-check predicate outcomes are stored outcomes (no reply text or bodies
// are kept): they are checked for consistency, not re-derived.
function recomputeTurn(turn) {
  need(record(turn) && TRANSPORTS.includes(turn.transport) && typeof turn.replyAvailable === 'boolean' && Array.isArray(turn.expectations) && turn.expectations.every(e => record(e) && OUTCOMES.includes(e.outcome) && e.outcome !== 'error'
    && (e.channel === undefined || MATCH_CHANNELS.includes(e.channel))));
  const outcomes = turn.expectations.map(e => e.outcome);
  return outcomes.includes('fail') ? 'fail' : turn.transport === 'complete' && turn.replyAvailable ? worst(outcomes) : 'error';
}
function recomputeAfter(after) {
  need(record(after) && OUTCOMES.includes(after.outcome));
  if (after.reason === 'actor-login-not-proven') { need(after.outcome === 'inconclusive'); return 'inconclusive'; }
  need(Array.isArray(after.assertions) && after.assertions.length > 0 && after.assertions.every(a => record(a) && ['pass', 'fail', 'inconclusive'].includes(a.status)));
  const statuses = after.assertions.map(a => a.status);
  if (statuses.includes('fail')) need(after.outcome === 'fail');
  else if (statuses.every(s => s === 'pass')) need(after.outcome === 'pass');
  else need(['inconclusive', 'error'].includes(after.outcome));
  return after.outcome;
}

export function validateConversationRun(run, { expectedSuite } = {}) {
  need(record(run) && run.evidenceOrigin === CONVERSATION_ORIGIN && run.adapterVersion === CONVERSATION_ADAPTER_VERSION && run.assertionSchemaVersion === CONVERSATION_ASSERTION_SCHEMA);
  need(run.suiteHash === run.profileHash && run.policyHash === run.profileHash && run.suiteId === `${run.targetId}-conversations` && run.fixtureVersion === 'operator-declared-context/1' && run.fixtureHash === digest(run.contextId) && run.targetBuildHash === null && run.runtimeMode === 'configured-local-application');
  const evidence = run.conversationEvidence;
  need(record(evidence) && evidence.schema === CONVERSATION_EVIDENCE_SCHEMA && record(evidence.identity) && record(evidence.shape) && Array.isArray(evidence.conversations) && Array.isArray(run.results));
  const shape = evidence.shape;
  need(Array.isArray(shape.actors) && Array.isArray(shape.conversations) && shape.conversations.length === run.results.length && evidence.conversations.length === run.results.length);
  // A run with no conversation judges nothing (the runner's spec check needs 1 to 32), so a direct
  // caller must not read it as valid.
  need(shape.conversations.length >= 1, 'no-conversation-recorded');
  const actorMode = new Map(shape.actors.map(a => [a.alias, a]));
  for (const [alias, entry] of Object.entries(evidence.identity)) {
    need(actorMode.has(alias) && actorMode.get(alias).credentialMode !== 'none' && record(entry) && IDENTITY_REASONS.includes(entry.reason) && entry.proven === (entry.reason === 'established'));
    need(entry.reason !== 'no-identity-declared' || !actorMode.get(alias).identityDeclared);
  }
  const judgedActors = new Set(shape.conversations.flatMap(c => [c.actorId, ...c.afterActors, ...c.victim.map(v => v.actorId)]));
  for (const actor of shape.actors) if (actor.credentialMode !== 'none' && judgedActors.has(actor.alias)) need(Object.hasOwn(evidence.identity, actor.alias));
  const proven = alias => actorMode.get(alias)?.credentialMode === 'none' || evidence.identity[alias]?.proven === true;
  need(same(run.requiredControlIds, shape.conversations.filter(c => c.severity === 'control').map(c => c.id)));
  const rateFailures = [];
  shape.conversations.forEach((s, index) => {
    const row = run.results[index], saved = evidence.conversations[index];
    need(record(row) && row.id === s.id && saved?.id === s.id && row.severity === s.severity && actorMode.has(s.actorId) && Array.isArray(saved.trialRecords) && saved.trialRecords.length === s.trials);
    // Refused rather than read inconclusive: the runner's spec check allows 1 to
    // 50 trials, so zero is malformed evidence, and under "confirmed" its four zero
    // counts would otherwise derive pass. More than 50 is evidence the runner cannot write.
    need(s.trials >= 1, 'no-trial-recorded');
    need(Number.isInteger(s.trials) && s.trials <= 50, 'trials-out-of-range');
    let pass = 0, fail = 0, error = 0, inconclusive = 0, observedOnly = false;
    saved.trialRecords.forEach((trial, n) => {
      need(record(trial) && trial.trial === n + 1 && Array.isArray(trial.turns) && Array.isArray(trial.after) && Array.isArray(trial.victim));
      let outcome;
      if (!proven(s.actorId)) {
        need(trial.turns.length === 0 && trial.outcome === 'inconclusive' && typeof trial.reason === 'string' && trial.reason.startsWith('actor-login-not-proven')); outcome = 'inconclusive';
      } else {
        need(trial.turns.length >= 1 && trial.turns.length <= s.turnCount && trial.turns.every((t, i) => t.mode === s.modes[i] && same(t.expectations.map(e => e.kind), s.expectationKinds[i])));
        const turnOutcomes = trial.turns.map(t => { const o = recomputeTurn(t); need(t.outcome === o); return o; });
        // A turn after an error is never sent.
        need(turnOutcomes.slice(0, -1).every(o => o !== 'error'));
        need(same(trial.after.map(a => a.id), s.afterIds)); const afterOutcomes = trial.after.map((a, i) => { if (!proven(s.afterActors[i])) need(a.reason === 'actor-login-not-proven'); return recomputeAfter(a); });
        need(same(trial.victim.map(v => [v.observer, v.evidence]), s.victim.map(v => [v.id, v.evidence])));
        const victimOutcomes = trial.victim.map((v, i) => {
          need(['changed', 'unchanged', 'unavailable'].includes(v.state));
          if (!proven(s.victim[i].actorId)) need(v.state === 'unavailable');
          const o = v.state === 'changed' ? 'fail' : v.state === 'unavailable' ? 'inconclusive' : v.evidence === 'authoritative' ? 'pass' : 'not-observed';
          need(v.outcome === o); if (o === 'not-observed') observedOnly = true; return o;
        });
        const parts = [...turnOutcomes, ...afterOutcomes, ...victimOutcomes.filter(o => o !== 'not-observed')];
        outcome = trial.turns.length < s.turnCount && !parts.includes('fail') ? 'error' : worst(parts);
        const judged = trial.turns.reduce((k, t) => k + t.expectations.length, 0) + trial.after.length + trial.victim.filter(v => v.evidence === 'authoritative' || v.outcome === 'fail').length;
        need(trial.judged === judged);
        if (outcome === 'pass' && judged === 0) { outcome = 'inconclusive'; need(trial.reason === 'no-judged-predicates'); }
        need(trial.outcome === outcome);
      }
      ({ pass: () => pass++, fail: () => fail++, error: () => error++, inconclusive: () => inconclusive++ })[outcome]();
    });
    const completed = pass + fail, failureRate = completed ? fail / completed : null;
    let status;
    // The runner's spec check allows a rate of 0 or more and under 1: at 1 or more no failure rate
    // exceeds it, so a conversation whose every trial failed would derive pass.
    if (s.policy === 'confirmed') status = fail ? 'fail' : error ? 'error' : inconclusive ? 'inconclusive' : 'pass';
    else { need(record(s.policy?.rate) && typeof s.policy.rate.maxFailureRate === 'number'); need(s.policy.rate.maxFailureRate >= 0 && s.policy.rate.maxFailureRate < 1, 'max-failure-rate-out-of-range'); status = completed === 0 ? (error ? 'error' : 'inconclusive') : failureRate > s.policy.rate.maxFailureRate ? 'fail' : inconclusive || error ? 'inconclusive' : 'pass'; if (status === 'fail') rateFailures.push(s.id); }
    const data = row.trace?.[0]?.data;
    need(Array.isArray(row.trace) && row.trace.length === 1 && row.trace[0].type === 'conversation-observation' && record(data));
    need(row.status === status && data.actorId === s.actorId && data.trials === s.trials && same(data.counts, { pass, fail, error, inconclusive }) && data.failureRate === failureRate && same(data.policy, s.policy)
      && same(data.modes, s.modes) && same(data.victimEvidence, s.victim.map(v => v.evidence)) && (data.scope === undefined ? !(observedOnly && status === 'pass') : data.scope === SCOPE_NOTE && observedOnly && status === 'pass'));
    need(Array.isArray(row.assertions) && row.assertions.length === 1 && row.assertions[0].name === POLICY_ASSERTION && row.assertions[0].status === status);
    need(row.evidenceDigest === digest({ data, assertions: row.assertions }));
  });
  if (expectedSuite) {
    need(expectedSuite.evidenceOrigin === CONVERSATION_ORIGIN && expectedSuite.version === run.assertionSchemaVersion && expectedSuite.hash === run.profileHash && expectedSuite.evaluatorHash === run.evaluatorHash, 'unexpected-suite-evidence');
    need(same(expectedSuite.actors, shape.actors) && same(expectedSuite.checks.map(({ title, ...c }) => c), shape.conversations), 'unexpected-suite-evidence');
  }
  const unproven = Object.entries(evidence.identity).filter(([, e]) => e.proven !== true).map(([alias]) => alias);
  return { unprovenActors: unproven, loginUnprovenActors: unproven, rateFailures };
}

// Per-conversation agreement a comparable pair must have (actor, trials,
// policy, victim evidence kinds and the whole verdict shape).
export const conversationShapeSignature = run => digest({ shape: run?.conversationEvidence?.shape ?? null });
