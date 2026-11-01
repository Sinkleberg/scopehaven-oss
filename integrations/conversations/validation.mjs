// Conversation reports as native saved runs: the report-to-run adapter, the
// exported suite (for gate binding) and the evaluator identity. The native
// validator that recomputes every verdict is src/conversation-native.mjs,
// which compareRuns and the regression gate import directly.
//
// Evaluator identity: every module that computes or recomputes a conversation
// verdict is in CONVERSATION_EVALUATOR_FILES (paths from the scopehaven root),
// and CONVERSATION_EVALUATOR_HASH digests exactly those sources. Changing how
// runs are judged changes the identity, so old and new runs never compare.
import { readFile } from 'node:fs/promises';
import { digest } from '../../src/domain.mjs';
import { CONVERSATION_ORIGIN, CONVERSATION_ADAPTER_VERSION, CONVERSATION_ASSERTION_SCHEMA, CONVERSATION_EVIDENCE_SCHEMA, POLICY_ASSERTION, validateConversationRun, conversationShapeSignature, ConversationEvidenceError } from '../../src/conversation-native.mjs';
export { CONVERSATION_ORIGIN, validateConversationRun, conversationShapeSignature, ConversationEvidenceError };

export const CONVERSATION_EVALUATOR_FILES = Object.freeze(['integrations/conversations/conversation.mjs', 'src/conversation-native.mjs', 'src/lookalike.mjs']);
export const CONVERSATION_EVALUATOR_HASH = digest({ files: await Promise.all(CONVERSATION_EVALUATOR_FILES.map(async name => [name, await readFile(new URL(`../../${name}`, import.meta.url), 'utf8')])) });
const ID = /^[A-Za-z0-9_-]{1,80}$/;

// The contract shape a run is bound to: everything that decides a verdict,
// never values, paths, patterns or canaries.
function shapeOf(spec) {
  const observers = new Map((spec.observers || []).map(o => [o.id, o]));
  return {
    actors: Object.entries(spec.actors).map(([alias, a]) => ({ alias, credentialMode: !a.credentialEnv ? 'none' : a.credentialCookie ? 'cookie' : 'bearer', identityDeclared: Boolean(a.identity) })),
    conversations: spec.conversations.map(c => ({ id: c.id, severity: c.severity, actorId: c.actorId, trials: c.trials ?? 1, policy: c.policy ?? 'confirmed', turnCount: c.turns.length,
      modes: c.turns.map(t => t.mode), expectationKinds: c.turns.map(t => t.expect.map(e => e.kind)), afterIds: (c.after || []).map(a => a.id),
      afterActors: (c.after || []).map(a => a.actorId), victim: (c.victimUnchanged || []).map(id => ({ id, evidence: observers.get(id).evidence, actorId: observers.get(id).actorId })) })),
  };
}

// A spec can feed comparisons and the gate only with these identity fields;
// without them its runs stay report-only.
export function runReady(spec) {
  const text = v => typeof v === 'string' && v.length > 0 && v.length <= 200;
  return ID.test(spec?.applicationId || '') && text(spec?.build) && ID.test(spec?.contextId || '');
}

export function exportConversationSuite(spec, specDigest) {
  const shape = shapeOf(spec);
  return { id: `${spec.id}-conversations`, targetId: spec.id, applicationId: spec.applicationId, version: CONVERSATION_ASSERTION_SCHEMA, evidenceOrigin: CONVERSATION_ORIGIN, hash: specDigest,
    evaluatorHash: CONVERSATION_EVALUATOR_HASH, requiredControlIds: spec.conversations.filter(c => c.severity === 'control').map(c => c.id),
    checks: shape.conversations.map(c => ({ ...c, title: spec.conversations.find(x => x.id === c.id).title })), actors: shape.actors,
    scope: 'Definition summary only: no paths, bodies, values, patterns or canaries.' };
}

export function conversationRunFromReport(spec, report) {
  if (!runReady(spec)) throw new Error('This spec is report-only: add applicationId, build and contextId to save runs for comparison and the gate.');
  const shape = shapeOf(spec);
  const results = report.conversations.map(c => {
    const s = shape.conversations.find(x => x.id === c.id);
    const data = { actorId: c.actorId, trials: c.trials, counts: c.counts, failureRate: c.failureRate, policy: c.policy, modes: s.modes, victimEvidence: s.victim.map(v => v.evidence), ...(c.scope ? { scope: c.scope } : {}) };
    const assertions = [{ name: POLICY_ASSERTION, status: c.status, expected: c.policy === 'confirmed' ? 'No trial fails' : `Failure rate at most ${c.policy.rate.maxFailureRate}`, actual: `${c.counts.fail} of ${c.trials} trials failed` }];
    return { id: c.id, title: c.title, category: 'Conversation checks', severity: c.severity, status: c.status, summary: `${c.counts.pass} pass, ${c.counts.fail} fail, ${c.counts.error} error, ${c.counts.inconclusive} inconclusive over ${c.trials} trials.`,
      evidenceRequirement: 'response', backendEvidence: 'unavailable', expected: 'Configured conversation predicates and declared surfaces only.', assertions,
      trace: [{ type: 'conversation-observation', label: 'Statuses and outcomes only; reply text is not kept', data }], evidenceDigest: digest({ data, assertions }) };
  });
  const counts = { pass: 0, fail: 0, inconclusive: 0, error: 0, not_applicable: 0 }; for (const r of results) counts[r.status]++;
  return { schemaVersion: 1, id: report.id, createdAt: report.createdAt, targetId: spec.id, targetName: spec.id, build: spec.build, applicationId: spec.applicationId, contextId: spec.contextId,
    suiteId: `${spec.id}-conversations`, suiteHash: report.specDigest, policyHash: report.specDigest, profileHash: report.specDigest,
    fixtureVersion: 'operator-declared-context/1', fixtureHash: digest(spec.contextId), targetConfigHash: digest({ build: spec.build }), targetBuildHash: null,
    adapterVersion: CONVERSATION_ADAPTER_VERSION, assertionSchemaVersion: CONVERSATION_ASSERTION_SCHEMA, evaluatorHash: CONVERSATION_EVALUATOR_HASH,
    runtimeMode: 'configured-local-application', evidenceOrigin: CONVERSATION_ORIGIN, scopeLabel: report.scope,
    requiredControlIds: shape.conversations.filter(c => c.severity === 'control').map(c => c.id), checksTotal: results.length, counts, durationMs: report.durationMs, results,
    conversationEvidence: { schema: CONVERSATION_EVIDENCE_SCHEMA, identity: report.identity, shape,
      conversations: report.conversations.map(c => ({ id: c.id, trialRecords: c.trialRecords })) } };
}
