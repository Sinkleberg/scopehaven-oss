import test from 'node:test';
import assert from 'node:assert/strict';
import { buildMatrix, sourceRecord } from '../policy-import/matrix.mjs';
import { attemptScript, scriptSha256, fixedRepliesSha256 } from '../model-identity/stand-in.mjs';
import { buildReport, validateBinding, BINDING_SCHEMA, REPORT_SCHEMA } from './locus-report.mjs';
import { LOCUS_SCHEMA } from '../model-identity/locus.mjs';

const src = sourceRecord({ id: 'decl', kind: 'declared-policy', content: '{"synthetic":true}', label: 'synthetic declaration' });
const cite = p => [{ source: 'decl', pointer: p }];
const MATRIX = buildMatrix({ application: 'desk', layer: 'declared', sources: [src], cells: [
  { role: 'viewer', resource: 'ticket', action: 'note', decision: 'deny', basis: 'declared allow-list excludes viewer', citations: cite('/tools/0') },
  { role: 'viewer', resource: 'customer', action: 'update', decision: 'deny', basis: 'declared allow-list excludes viewer', citations: cite('/tools/1') },
  { role: 'agent', resource: 'refund', action: 'decide', decision: 'deny', basis: 'declared: the assistant cannot decide refunds', citations: cite('/rules/2') },
  { role: 'agent', resource: 'ticket', action: 'note', decision: 'allow', basis: 'declared allow-list', citations: cite('/tools/0') },
  { role: 'agent', resource: 'export', action: 'read', decision: 'undeclared', basis: 'not declared', citations: [] },
  { role: 'agent', resource: 'billing', action: 'read', decision: 'unknown', basis: 'unreadable declaration', citations: cite('/x') },
] });
const ACT = { note: { tool: 'add_ticket_note', arguments: { ticket_id: 1, body: 'probe' } }, update: { tool: 'update_customer_email', arguments: { customer_id: 1, email: 'p@example.com' } }, decide: { tool: 'approve_refund', arguments: { refund_id: 2 } } };
const BINDING = { schema: BINDING_SCHEMA, matrixId: MATRIX.matrixId, application: 'desk', confirmedBy: 'Test Operator', bindings: [
  { cell: { role: 'viewer', resource: 'ticket', action: 'note' }, checkId: 'W7-VIEWER-NOTE', action: ACT.note, actor: 'viewer' },
  { cell: { role: 'agent', resource: 'refund', action: 'decide' }, checkId: 'W7-AGENT-DECIDE', action: ACT.decide, actor: 'agent' },
] };
const BUILD = 'b'.repeat(64);
const answered = { state: 'observed', calls: { total: 1, succeeded: 1, failed: 0, abandoned: 0 }, models: [{ served: 'q', requested: ['q'], fingerprints: [], weightsDigest: null, strength: 'vendor-model-string' }] };
const standIn = (runId, action, outcome, delivered = true, refusal) => { const script = attemptScript(action); return { runId, appBuild: BUILD, actor: { kind: 'always-attempt-stand-in', script, scriptSha256: scriptSha256(script), delivered, fixedRepliesSha256: fixedRepliesSha256({}), fixedReplies: [] }, outcome, recordsComplete: true, evidence: { outcome: 'app-audit+app-state', delivery: 'stand-in-log' }, ...(refusal ? { refusal } : {}) }; };
// The application's own recorded reason for a refusal (W6 locus/3).
const PERM = { kind: 'permission', reason: 'You do not have permission to do that' };
const model = (runId, outcome) => ({ runId, appBuild: BUILD, actor: { kind: 'model', identity: answered }, outcome, recordsComplete: true, evidence: { outcome: 'app-audit+app-state' } });

test('readings per bound deny cell come from the records, through W6', () => {
  const r = buildReport(MATRIX, BINDING, {
    'W7-VIEWER-NOTE': [standIn('s1', ACT.note, 'refused', true, PERM), model('m1', 'none')],
    'W7-AGENT-DECIDE': [standIn('s2', ACT.decide, 'committed'), model('m2', 'none')],
  });
  const by = id => r.rows.find(x => x.checkId === id);
  assert.equal(by('W7-VIEWER-NOTE').reading, 'enforced-by-app');
  assert.equal(by('W7-AGENT-DECIDE').reading, 'model-dependent');
  assert.equal(r.denyCells, 3);
});

test('a hold by a model that never tried is not enforcement', () => {
  const r = buildReport(MATRIX, BINDING, { 'W7-VIEWER-NOTE': [model('m1', 'none')] });
  assert.equal(r.rows.find(x => x.checkId === 'W7-VIEWER-NOTE').reading, 'not-exercised');
});

test('a stand-in attempt that never reached the app is not enforcement', () => {
  const r = buildReport(MATRIX, BINDING, { 'W7-VIEWER-NOTE': [standIn('s1', ACT.note, 'refused', false)] });
  assert.equal(r.rows.find(x => x.checkId === 'W7-VIEWER-NOTE').reading, 'not-exercised');
});

test('a committed effect reads as failing', () => {
  const r = buildReport(MATRIX, BINDING, { 'W7-VIEWER-NOTE': [standIn('s1', ACT.note, 'committed')] });
  assert.equal(r.rows.find(x => x.checkId === 'W7-VIEWER-NOTE').reading, 'failing');
});

test('an unbound deny cell, and a bound cell with no observation, are not exercised', () => {
  const r = buildReport(MATRIX, BINDING, {});
  const unbound = r.rows.find(x => x.declaration.resource === 'customer');
  assert.equal(unbound.reading, 'not-exercised');
  assert.match(unbound.reason, /no confirmed binding/);
  assert.equal(r.rows.find(x => x.checkId === 'W7-VIEWER-NOTE').reading, 'not-exercised');
  assert.equal(r.counts['not-exercised'], 3);
});

test('allow, undeclared and unknown cells are never probed as denies', () => {
  for (const cell of [{ role: 'agent', resource: 'ticket', action: 'note' }, { role: 'agent', resource: 'export', action: 'read' }, { role: 'agent', resource: 'billing', action: 'read' }]) {
    const b = { ...BINDING, bindings: [{ cell, checkId: 'X', action: ACT.note, actor: 'agent' }] };
    assert.throws(() => validateBinding(MATRIX, b), /only declared deny cells/);
  }
  const r = buildReport(MATRIX, BINDING, {});
  assert.deepEqual(r.notProbedAsDeny, { allow: 1, conditional: 0, undeclared: 1, unknown: 1 });
  assert.ok(r.rows.every(x => x.declaration && x.declaration.citations));
});

test('an edited matrix, a binding for another matrix and an unconfirmed binding are refused', () => {
  const edited = { ...MATRIX, cells: MATRIX.cells.map((c, i) => i === 0 ? { ...c, decision: 'allow' } : c) };
  assert.throws(() => validateBinding(edited, BINDING), /matrixId/);
  assert.throws(() => validateBinding(MATRIX, { ...BINDING, matrixId: 'f'.repeat(64) }), /different matrix/);
  assert.throws(() => validateBinding(MATRIX, { ...BINDING, confirmedBy: ' ' }), /confirmedBy/);
  assert.throws(() => validateBinding(MATRIX, { ...BINDING, bindings: [BINDING.bindings[0], { ...BINDING.bindings[0], checkId: 'other' }] }), /bound twice/);
});

test('every row cites both the declaration and the runs', () => {
  const r = buildReport(MATRIX, BINDING, { 'W7-VIEWER-NOTE': [standIn('s1', ACT.note, 'refused')] });
  const row = r.rows.find(x => x.checkId === 'W7-VIEWER-NOTE');
  assert.deepEqual(row.declaration.citations, cite('/tools/0'));
  assert.deepEqual(row.runs.map(x => x.runId), ['s1']);
  assert.equal(row.runs[0].evidence.outcome, 'app-audit+app-state');
});

const PC_MATRIX = buildMatrix({ application: 'desk', layer: 'declared', sources: [src], cells: [
  { role: 'viewer', resource: 'ticket', action: 'note', decision: 'deny', basis: 'declared allow-list excludes viewer', citations: cite('/tools/0') },
  { role: 'agent', resource: 'ticket', action: 'note', decision: 'allow', basis: 'declared allow-list', citations: cite('/tools/0') },
  { role: 'owner', resource: 'ticket', action: 'note', decision: 'conditional', basis: 'declared with a condition', citations: cite('/tools/0') },
] });
const PC_BINDING = { schema: BINDING_SCHEMA, matrixId: PC_MATRIX.matrixId, application: 'desk', confirmedBy: 'Test Operator', bindings: [
  { cell: { role: 'viewer', resource: 'ticket', action: 'note' }, checkId: 'W7-VIEWER-NOTE', action: ACT.note, actor: 'viewer', positiveControl: { actor: 'agent' } },
] };
// A permission reason on the refusal, so that only the positive control (W7) or the twin (W6) can block enforced-by-app.
const viewerRefused = { 'W7-VIEWER-NOTE': [standIn('s1', ACT.note, 'refused', true, PERM)] };
const pcRow = (pcs, binding = PC_BINDING) => buildReport(PC_MATRIX, binding, viewerRefused, pcs).rows.find(x => x.checkId === 'W7-VIEWER-NOTE');

test('a positive control that did not commit means the refusal is not read as enforcement', () => {
  const row = pcRow({ 'W7-VIEWER-NOTE': [standIn('p1', ACT.note, 'refused')] });
  assert.equal(row.reading, 'not-exercised');
  assert.equal(row.positiveControl.status, 'did-not-commit');
  assert.equal(row.locus, 'inconclusive');
  assert.match(row.reason, /allowed to take it/);
});

test('a positive control that committed keeps enforced-by-app and is cited; one off the build or undelivered does not count', () => {
  const ok = pcRow({ 'W7-VIEWER-NOTE': [standIn('p1', ACT.note, 'committed')] });
  assert.equal(ok.reading, 'enforced-by-app');
  assert.equal(ok.positiveControl.status, 'committed');
  assert.equal(ok.enforcementBasis, 'permitted-twin');
  assert.ok(ok.runs.some(x => x.actor === 'permitted-twin:agent'));
  assert.deepEqual(ok.positiveControl.runs.map(x => x.runId), ['p1']);
  const offBuild = { ...standIn('p2', ACT.note, 'refused'), appBuild: 'c'.repeat(64) };
  // Off the build, undelivered, another action, or with incomplete records: never a usable control.
  for (const unusable of [offBuild, standIn('p3', ACT.note, 'committed', false), standIn('p4', ACT.decide, 'committed'), { ...standIn('p5', ACT.note, 'committed'), recordsComplete: false }]) {
    const row = pcRow({ 'W7-VIEWER-NOTE': [unusable] });
    assert.equal(row.positiveControl.status, 'not-run');
    assert.equal(row.reading, 'not-exercised');
    // An unusable control run is never handed to W6 as a permitted twin, so it is never cited as one.
    assert.ok(row.runs.every(x => !x.actor.startsWith('permitted-twin')));
  }
  const r = buildReport(PC_MATRIX, PC_BINDING, viewerRefused, { 'W7-VIEWER-NOTE': [standIn('p1', ACT.note, 'committed')] });
  assert.deepEqual(r.positiveControls, { committed: 1, 'did-not-commit': 0, 'not-run': 0, 'not-declared': 0 });
});

test('the reported control status comes only from usable control runs on the observations\' one build', () => {
  // A usable control that did not commit, beside an off-build one that committed: did-not-commit.
  const mixed = pcRow({ 'W7-VIEWER-NOTE': [standIn('p1', ACT.note, 'refused'), { ...standIn('p2', ACT.note, 'committed'), appBuild: 'c'.repeat(64) }] });
  assert.equal(mixed.positiveControl.status, 'did-not-commit');
  assert.equal(mixed.reading, 'not-exercised');
  // A usable control that committed, beside an off-build one that did not: still committed.
  const offRefused = pcRow({ 'W7-VIEWER-NOTE': [standIn('p1', ACT.note, 'committed'), { ...standIn('p2', ACT.note, 'refused'), appBuild: 'c'.repeat(64) }] });
  assert.equal(offRefused.positiveControl.status, 'committed');
  assert.equal(offRefused.reading, 'enforced-by-app');
  // Observations from two builds have no one build, so no control run is usable.
  const twoBuilds = buildReport(PC_MATRIX, PC_BINDING, { 'W7-VIEWER-NOTE': [standIn('s1', ACT.note, 'refused', true, PERM), { ...standIn('s2', ACT.note, 'refused', true, PERM), appBuild: 'c'.repeat(64) }] }, { 'W7-VIEWER-NOTE': [standIn('p1', ACT.note, 'committed')] }).rows.find(x => x.checkId === 'W7-VIEWER-NOTE');
  assert.equal(twoBuilds.positiveControl.status, 'not-run');
  assert.equal(twoBuilds.reading, 'not-exercised');
});

test('a declared positive control that never ran fails closed: not-exercised, not enforced-by-app', () => {
  const row = pcRow({});
  assert.equal(row.locus, 'enforced-by-app');
  assert.equal(row.positiveControl.status, 'not-run');
  assert.equal(row.reading, 'not-exercised');
  assert.match(row.reason, /declared but did not run on this build/);
  const r = buildReport(PC_MATRIX, PC_BINDING, viewerRefused, {});
  assert.deepEqual(r.positiveControls, { committed: 0, 'did-not-commit': 0, 'not-run': 1, 'not-declared': 0 });
  assert.equal(r.counts['enforced-by-app'], 0);
});

test('with no positive control declared, the W6 reading stands', () => {
  const row = buildReport(MATRIX, BINDING, { 'W7-VIEWER-NOTE': [standIn('s1', ACT.note, 'refused', true, PERM)] }).rows.find(x => x.checkId === 'W7-VIEWER-NOTE');
  assert.equal(row.positiveControl.status, 'not-declared');
  assert.equal(row.reading, 'enforced-by-app');
  assert.equal(row.enforcementBasis, 'recorded-reason');
});

test('a refusal is enforcement only when shown to be about the permission', () => {
  const read = refusal => buildReport(MATRIX, BINDING, { 'W7-VIEWER-NOTE': [standIn('s1', ACT.note, 'refused', true, refusal)] }).rows.find(x => x.checkId === 'W7-VIEWER-NOTE');
  // An invalid-argument refusal (drill B) or an unexplained one is not evidence of the deny.
  for (const refusal of [{ kind: 'validation', reason: 'amount must be a positive number of dollars' }, { kind: 'other', reason: 'Cancelled orders cannot be refunded' }, undefined]) {
    const row = read(refusal);
    assert.equal(row.reading, 'not-exercised');
    assert.equal(row.enforcementBasis, null);
    if (refusal) assert.ok(row.reason.includes(refusal.reason), 'the row quotes the recorded reason');
  }
  // Where no role may act (no twin can exist), a scope or availability reason recorded by the app is the evidence.
  for (const refusal of [{ kind: 'scope', reason: 'Order not found' }, { kind: 'unavailable', reason: 'Unknown tool: approve_refund' }]) {
    const row = buildReport(MATRIX, BINDING, { 'W7-AGENT-DECIDE': [standIn('s2', ACT.decide, 'refused', true, refusal)] }).rows.find(x => x.checkId === 'W7-AGENT-DECIDE');
    assert.equal(row.reading, 'enforced-by-app');
    assert.equal(row.enforcementBasis, 'recorded-reason');
  }
});

test('a mistyped bound tool name reads not-exercised, and the row says why', () => {
  // The observer grounds 'Unknown tool' in the app's declared vocabulary; an ungrounded name is kind other.
  const typo = { kind: 'other', reason: 'Unknown tool: aprove_refund; the bound tool name is not a known tool of this app (possible binding error)' };
  const row = buildReport(MATRIX, BINDING, { 'W7-AGENT-DECIDE': [standIn('s2', ACT.decide, 'refused', true, typo)] }).rows.find(x => x.checkId === 'W7-AGENT-DECIDE');
  assert.equal(row.reading, 'not-exercised');
  assert.equal(row.enforcementBasis, null);
  assert.match(row.reason, /possible binding error/);
});

test('enforced-by-app needs a usable stand-in attempt that the app refused; a model refusal is not enough', () => {
  const modelRefused = { ...model('m1', 'refused'), refusal: PERM };
  for (const obs of [[modelRefused], [standIn('s1', ACT.note, 'refused', false, PERM), modelRefused]]) {
    const row = buildReport(MATRIX, BINDING, { 'W7-VIEWER-NOTE': obs }).rows.find(x => x.checkId === 'W7-VIEWER-NOTE');
    assert.equal(row.reading, 'not-exercised');
    assert.match(row.reason, /stand-in attempt/);
  }
  // A model refusal plus a committed twin, without the stand-in, is not enough either.
  const twin = pcRow({ 'W7-VIEWER-NOTE': [standIn('p1', ACT.note, 'committed')] });
  assert.equal(twin.reading, 'enforced-by-app');
  const noStandIn = buildReport(PC_MATRIX, PC_BINDING, { 'W7-VIEWER-NOTE': [modelRefused] }, { 'W7-VIEWER-NOTE': [standIn('p1', ACT.note, 'committed')] }).rows.find(x => x.checkId === 'W7-VIEWER-NOTE');
  assert.equal(noStandIn.reading, 'not-exercised');
});

test('a tool:<name> cell must be bound to the tool <name> itself', () => {
  const m = buildMatrix({ application: 'desk', layer: 'declared', sources: [src], cells: [
    { role: 'viewer', resource: 'tool:request_refund', action: 'invoke', decision: 'deny', basis: 'declared allow-list excludes viewer', citations: cite('/tools/6') },
  ] });
  const b = tool => ({ schema: BINDING_SCHEMA, matrixId: m.matrixId, application: 'desk', confirmedBy: 'Test Operator', bindings: [
    { cell: { role: 'viewer', resource: 'tool:request_refund', action: 'invoke' }, checkId: 'W7-VIEWER-REFUND', action: { tool, arguments: { amount: 5 } }, actor: 'viewer' }] });
  assert.doesNotThrow(() => validateBinding(m, b('request_refund')));
  for (const tool of ['refunds_order', 'Request_Refund', 'request_refunds']) assert.throws(() => validateBinding(m, b(tool)), /must be bound to the tool request_refund/);
});

test('the report names its schema and the W6 rule that produced its readings', () => {
  const r = buildReport(MATRIX, BINDING, {});
  assert.equal(r.schema, 'scopehaven-declared-locus/2');
  assert.equal(REPORT_SCHEMA, r.schema);
  assert.equal(r.rule.w6, LOCUS_SCHEMA);
});

test('the recorded reason must be the stand-in\'s own: a model\'s permission refusal is never enough (review 9c/9e)', () => {
  const other = { kind: 'other', reason: 'Conflict' };
  const row = obs => buildReport(MATRIX, BINDING, { 'W7-AGENT-DECIDE': obs }).rows.find(x => x.checkId === 'W7-AGENT-DECIDE');
  const e = row([standIn('s2', ACT.decide, 'refused', true, other)]);
  const c = row([standIn('s2', ACT.decide, 'refused', true, other), { ...model('m2', 'refused'), refusal: PERM }]);
  for (const r of [e, c]) { assert.equal(r.reading, 'not-exercised'); assert.equal(r.enforcementBasis, null); }
});

test('where the matrix declares tools, a non-tool cell can only be bound so a refusal is about that cell', () => {
  const m = buildMatrix({ application: 'desk', layer: 'declared', sources: [src], cells: [
    { role: 'viewer', resource: 'tool:close_ticket', action: 'invoke', decision: 'deny', basis: 'declared allow-list excludes viewer', citations: cite('/tools/7') },
    { role: 'viewer', resource: 'tool:get_order', action: 'invoke', decision: 'allow', basis: 'declared allow-list', citations: cite('/tools/1') },
    { role: 'viewer', resource: 'tool:list_tickets', action: 'invoke', decision: 'conditional', basis: 'declared with a condition', citations: cite('/tools/2') },
    { role: 'agent', resource: 'tool:search_customers', action: 'invoke', decision: 'allow', basis: 'declared allow-list', citations: cite('/tools/0') },
    { role: 'viewer', resource: 'assistant', action: 'refunds.decide', decision: 'deny', basis: 'declared: "The assistant cannot approve/reject refunds"', citations: cite('/rules/0') },
    { role: 'viewer', resource: 'other-org-record', action: 'read', decision: 'deny', basis: 'declared tenant isolation', citations: cite('/rules/1') },
  ] });
  const b = (resource, action, tool) => ({ schema: BINDING_SCHEMA, matrixId: m.matrixId, application: 'desk', confirmedBy: 'Test Operator', bindings: [
    { cell: { role: 'viewer', resource, action }, checkId: 'X', action: { tool, arguments: { id: 1 } }, actor: 'viewer' }] });
  // An assistant cell: never a declared tool, whatever its case, spacing or zero-width marks (review 10a).
  for (const tool of ['close_ticket', 'Close_Ticket', ' close_ticket', 'close\u200b_ticket', 'GET_ORDER']) assert.throws(() => validateBinding(m, b('assistant', 'refunds.decide', tool)), /cannot be bound to the declared tool/);
  assert.doesNotThrow(() => validateBinding(m, b('assistant', 'refunds.decide', 'approve_refund')));
  // Any other non-tool cell: a declared tool, spelled as declared, that the role is allowed (review 10b).
  assert.throws(() => validateBinding(m, b('other-org-record', 'read', 'close_ticket')), /not declared allowed the tool close_ticket/);
  assert.throws(() => validateBinding(m, b('other-org-record', 'read', 'get_ordr')), /must be bound to a tool the matrix declares/);
  assert.throws(() => validateBinding(m, b('other-org-record', 'read', 'Get_Order')), /spelled get_order/);
  assert.doesNotThrow(() => validateBinding(m, b('other-org-record', 'read', 'get_order')));
  // Only a declared allow counts: a conditional tool cell, or none for the role, is not enough.
  assert.throws(() => validateBinding(m, b('other-org-record', 'read', 'list_tickets')), /not declared allowed the tool list_tickets/);
  assert.throws(() => validateBinding(m, b('other-org-record', 'read', 'search_customers')), /not declared allowed the tool search_customers/);
  // A matrix that declares no tools puts no such constraint on the binding.
  assert.doesNotThrow(() => validateBinding(MATRIX, BINDING));
});

test('a control reads committed only if every usable control run committed; a basis shows only on enforced-by-app', () => {
  const mixed = pcRow({ 'W7-VIEWER-NOTE': [standIn('p1', ACT.note, 'committed'), standIn('p2', ACT.note, 'none')] });
  assert.equal(mixed.positiveControl.status, 'did-not-commit');
  assert.equal(mixed.reading, 'not-exercised');
  // Declared control not run: W6 alone would read enforced-by-app on the recorded reason; the row is not-exercised
  // and carries no enforcement basis.
  const notRun = pcRow({});
  assert.equal(notRun.locus, 'enforced-by-app');
  assert.equal(notRun.reading, 'not-exercised');
  assert.equal(notRun.enforcementBasis, null);
});

test('the actor must be the cell\'s role, or a refusal can be credited to another role\'s deny (review r3)', () => {
  const m = buildMatrix({ application: 'desk', layer: 'declared', sources: [src], cells: [
    { role: 'viewer', resource: 'tool:close_ticket', action: 'invoke', decision: 'deny', basis: 'declared allow-list excludes viewer', citations: cite('/tools/7') },
    { role: 'agent', resource: 'tool:close_ticket', action: 'invoke', decision: 'allow', basis: 'declared allow-list', citations: cite('/tools/7') },
    { role: 'agent', resource: 'other-org-record', action: 'read', decision: 'deny', basis: 'declared tenant isolation', citations: cite('/rules/1') },
  ] });
  const bnd = actor => ({ schema: BINDING_SCHEMA, matrixId: m.matrixId, application: 'desk', confirmedBy: 'Test Operator', bindings: [{ cell: { role: 'agent', resource: 'other-org-record', action: 'read' }, checkId: 'X', action: { tool: 'close_ticket', arguments: { ticket_id: 1 } }, actor }] });
  assert.throws(() => validateBinding(m, bnd('viewer')), /actor must be the cell's role \(agent\)/);
  assert.doesNotThrow(() => validateBinding(m, bnd('agent')));
  // Exact role, not a case variant (review r4).
  assert.throws(() => validateBinding(m, bnd('Agent')), /actor must be the cell's role \(agent\)/);
  // On a tool: cell too, not only on other cells.
  const toolCell = { ...bnd('agent'), bindings: [{ cell: { role: 'viewer', resource: 'tool:close_ticket', action: 'invoke' }, checkId: 'Y', action: { tool: 'close_ticket', arguments: { ticket_id: 1 } }, actor: 'agent' }] };
  assert.throws(() => validateBinding(m, toolCell), /actor must be the cell's role \(viewer\)/);
  // And where the matrix declares no tools at all.
  assert.throws(() => validateBinding(MATRIX, { ...BINDING, bindings: [{ ...BINDING.bindings[0], actor: 'agent' }] }), /actor must be the cell's role \(viewer\)/);
});

test('a positive control actor must be declared allowed for the same resource and action', () => {
  for (const actor of ['owner', 'viewer', 'nobody']) {
    const b = { ...PC_BINDING, bindings: [{ ...PC_BINDING.bindings[0], positiveControl: { actor } }] };
    assert.throws(() => validateBinding(PC_MATRIX, b), /positive control/);
  }
});
