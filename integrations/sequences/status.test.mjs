// Judged response-status rows (assertStatus) and the scopehaven-sequence-run/3 record. Every run here is made by
// the real runner with a scripted transport and scripted observers (no network), saved as JSON and read back.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { runSequence, validateSequence, decideStatusAssertion, statusAssertionsOf, countsOf, sequenceHashOf, SEQUENCE_SCHEMA, SEQUENCE_RUN_SCHEMA, SEQUENCE_RUN_SCHEMA_V2 } from './sequence.mjs';
import { validateSequenceRun } from './run-validator.mjs';
import { SEQUENCE_EVALUATOR_FILES, SEQUENCE_EVALUATOR_HASH } from './evaluator.mjs';
import { main } from './cli.mjs';
import { digest } from '../../src/domain.mjs';

const saved = run => JSON.parse(JSON.stringify(run));
const reseal = r => { const { timeline: _t, gateTimeline: _g, createdAt: _c, durationMs: _d, runDigest: _r, ...sealed } = r; r.runDigest = digest(sealed); return r; };
const refuse = (r, code, detail, options) => assert.throws(() => validateSequenceRun(r, options), e => e.code === code && (detail === undefined || e.detail === detail), `${code} ${detail ?? ''}`);
// A request-path gate observer: its absence can pass (custody independent).
const gated = () => { let at = 0; return { kind: 'hold-gate', instanceId: 'gate-1', source: 'hold-proxy', scope: Object.freeze({ operations: ['tool-call'], names: ['refund', 'ungated'], actorAttribution: 'none', evidence: 'authoritative' }),
  async start() {}, async stop() {}, async mark() { return { at: ++at }; }, async collect() { return { events: [], coverage: 'complete', reason: null }; } }; };
const statusSequence = (extra = {}) => ({ schema: SEQUENCE_SCHEMA, id: 'STATUS', actors: { amy: { principalId: 'agent-amy' }, ben: { principalId: 'agent-ben' } },
  // Amy is accepted first: a refusal row passes only after an earlier 2xx for the same actor.
  steps: [{ request: { id: 'amy-login', actorId: 'amy', method: 'GET', path: '/whoami' } }, { mark: 'before' },
    { request: { id: 'amy-refund', actorId: 'amy', method: 'POST', path: '/refund' }, assertStatus: { id: 'AMY-REFUSED', title: 'Amy is refused', severity: 'high', in: [401, 403] } },
    { request: { id: 'ben-refund', actorId: 'ben', method: 'POST', path: '/refund' }, assertStatus: { id: 'BEN-ACCEPTED', title: 'Ben is accepted', severity: 'control', in: [200] } },
    ...(extra.steps ?? []), { mark: 'after' }],
  assertions: [{ id: 'NO-REFUND', title: 'No refund', severity: 'critical', from: 'before', to: 'after', effect: { kind: 'effect.none', select: { source: 'hold-proxy', operation: 'tool-call', name: 'refund' } } }] });
// The scripted application answers by request path and actor: status only, a JSON body nobody reads.
const answering = statuses => async (_origin, check) => ({ status: statuses[`${check.method} ${check.path}`] ?? 200, complete: true, jsonParsed: true, json: { reply: 'Refund issued. Everything worked.' }, bytes: 10 });
const run = async (seq, statuses = {}, transport = answering(statuses)) => saved(await runSequence(seq, { origin: 'http://127.0.0.1:1', observers: [gated()], transport }));

test('assertStatus is declared on a request step, judged from the status alone and sealed in a /3 run', async () => {
  const seq = statusSequence();
  // Amy answered 403 and Ben 200: both rows pass; a reply text claiming success is never read.
  const refused = await run(seq, { 'POST /refund': 403 });
  assert.equal(refused.schema, SEQUENCE_RUN_SCHEMA);
  assert.equal(refused.evaluatorHash, SEQUENCE_EVALUATOR_HASH);
  assert.deepEqual(refused.statusAssertions, statusAssertionsOf(seq));
  assert.deepEqual(refused.results.map(r => [r.id, r.kind ?? 'effect', r.status]), [['NO-REFUND', 'effect', 'pass'], ['AMY-REFUSED', 'response-status', 'pass'], ['BEN-ACCEPTED', 'response-status', 'fail']]);
  assert.deepEqual(refused.responses, { 'amy-login': { status: 200, complete: true, transport: 'complete' }, 'amy-refund': { status: 403, complete: true, transport: 'complete' }, 'ben-refund': { status: 403, complete: true, transport: 'complete' } });
  assert.equal(refused.results.find(r => r.id === 'AMY-REFUSED').acceptedBy, 'amy-login');
  assert.deepEqual(refused.counts, { pass: 2, fail: 1, inconclusive: 0, error: 0 });
  assert.ok(!JSON.stringify(refused).includes('Refund issued'), 'reply text is never kept');
  validateSequenceRun(refused, { expectedSequence: seq });
  // The judge itself: in the set passes, outside it fails, a stopped sequence, a request never sent or one without a complete response is inconclusive.
  const [s] = statusAssertionsOf(seq);
  assert.deepEqual(['pass', 'fail'].map((_, i) => decideStatusAssertion(s, { status: [403, 200][i], complete: true }, null, 'amy-login').status), ['pass', 'fail']);
  // A refusal without an earlier same-actor acceptance is inconclusive; a served request still fails.
  assert.deepEqual([decideStatusAssertion(s, { status: 403, complete: true }, null).verdict, decideStatusAssertion(s, { status: 200, complete: true }, null).verdict], ['identity-not-established', 'fail']);
  assert.deepEqual(decideStatusAssertion(s, null, null).verdict, 'not-sent');
  assert.deepEqual(decideStatusAssertion(s, { status: 403, complete: false }, null).verdict, 'no-response');
  assert.deepEqual(decideStatusAssertion(s, { status: null, complete: false }, null).status, 'inconclusive');
  for (const status of [403, 200]) assert.deepEqual([decideStatusAssertion(s, { status, complete: true }, 'run-budget').verdict, decideStatusAssertion(s, { status, complete: true }, 'run-budget').status], ['missing', 'inconclusive']);
});

test('a stopped sequence decides no status row: a background answer can depend on steps that never ran', async () => {
  const seq = statusSequence({ steps: [{ expectStatus: { request: 'ben-refund', in: [201] } }] });
  const stopped = await run(seq, { 'POST /refund': 403 });
  assert.equal(stopped.aborted, 'precondition-failed:ben-refund');
  // Without the stop Amy's row would pass and Ben's fail; stopped, neither is decided.
  assert.deepEqual(stopped.results.filter(r => r.kind === 'response-status').map(r => [r.id, r.verdict, r.status]), [['AMY-REFUSED', 'missing', 'inconclusive'], ['BEN-ACCEPTED', 'missing', 'inconclusive']]);
  validateSequenceRun(stopped, { expectedSequence: seq });
  // A transport failure stops the run too, so an unanswered request never decides its row.
  const failing = await run(statusSequence(), {}, async (_o, check) => check.path === '/refund' ? { status: null, complete: false, error: 'network' } : { status: 200, complete: true });
  assert.match(failing.aborted, /^transport-failed:/);
  assert.deepEqual(failing.results.filter(r => r.kind === 'response-status').map(r => r.status), ['inconclusive', 'inconclusive']);
  assert.ok(failing.results.every(r => r.status !== 'pass'));
});

// Review F1 (key-order probe): a step's JSON key order never changes what runs. Alphabetical serialization puts
// assertStatus before request; the request must still be sent and its row decided.
test('a request step runs the same whatever the order of its keys', async () => {
  const status = { id: 'ANSWER', title: 'The fixture answers 200', severity: 'control', in: [200] }, request = { id: 'r', actorId: 'amy', method: 'GET', path: '/example' };
  const normal = statusSequence({ steps: [{ request, assertStatus: status }] }), reordered = statusSequence({ steps: [{ assertStatus: status, request }] });
  const background = statusSequence({ steps: [{ assertStatus: status, background: true, request }, { awaitResponse: { request: 'r' } }] });
  assert.equal(sequenceHashOf(normal), sequenceHashOf(reordered));
  const observed = [];
  for (const seq of [normal, reordered, background]) {
    let calls = 0;
    const r = await run(seq, {}, async () => { calls++; return { status: 200, complete: true }; });
    validateSequenceRun(r, { expectedSequence: seq });
    const row = r.results.find(x => x.id === 'ANSWER');
    observed.push([calls, r.aborted, row.status, row.verdict]);
  }
  // Four requests each: Amy's login, Amy, Ben and the step under test.
  assert.deepEqual(observed, [[4, null, 'pass', 'pass'], [4, null, 'pass', 'pass'], [4, null, 'pass', 'pass']]);
});

// Review F2 (aborted-request-id probe): the validator accepts every unedited stopped run its runner writes,
// whatever valid id the unsent request has, including names an object inherits.
test('a stopped run round-trips for every valid id of an unsent status request', async () => {
  const outcomes = [];
  for (const id of ['ordinary', 'constructor', 'toString', '__proto__', 'hasOwnProperty', 'valueOf']) {
    const seq = { ...statusSequence(), steps: [{ mark: 'before' }, { request: { id: 'first', actorId: 'amy', method: 'GET', path: '/a' } },
      { request: { id, actorId: 'amy', method: 'GET', path: '/b' }, assertStatus: { id: 'ANSWER', title: 'answers', severity: 'control', in: [200] } }, { mark: 'after' }] };
    let calls = 0;
    const r = await run(seq, {}, async () => { calls++; return { status: null, complete: false, error: 'network' }; });
    let validation = 'accepted';
    try { validateSequenceRun(r, { expectedSequence: seq }); } catch (error) { validation = `${error.code}:${error.detail}`; }
    const row = r.results.find(x => x.id === 'ANSWER');
    outcomes.push([id, calls, validation, row.observed, row.status]);
  }
  assert.deepEqual(outcomes, ['ordinary', 'constructor', 'toString', '__proto__', 'hasOwnProperty', 'valueOf'].map(id => [id, 1, 'accepted', null, 'inconclusive']));
});

test('the sequence rules for assertStatus', () => {
  const bad = (edit, pattern) => { const seq = statusSequence(); edit(seq); assert.throws(() => validateSequence(seq), pattern); };
  bad(s => { s.steps[1].assertStatus = { id: 'X', title: 't', severity: 'high', in: [200] }; }, /assertStatus belongs on a request step/);
  bad(s => { s.steps[3].assertStatus.id = 'AMY-REFUSED'; }, /AMY-REFUSED is declared twice/);
  bad(s => { s.steps[2].assertStatus.id = 'NO-REFUND'; }, /NO-REFUND is declared twice/);
  for (const codes of [[], [99], [600], [200, 200], ['200'], [1.5], Array.from({ length: 17 }, (_, i) => 200 + i)]) bad(s => { s.steps[2].assertStatus.in = codes; }, /distinct status codes/);
  bad(s => { s.steps[2].assertStatus.severity = 'urgent'; }, /severity/);
  bad(s => { s.steps[2].assertStatus.text = 'Refund refused'; }, /needs an id and a title/);
  bad(s => { delete s.steps[2].assertStatus.title; }, /needs an id and a title/);
  bad(s => { s.applicationId = 'has space'; }, /applicationId/);
  bad(s => { s.contextId = ''; }, /contextId/);
  // expectStatus still stops the run, and is not a judged row.
  const seq = statusSequence({ steps: [{ expectStatus: { request: 'amy-refund', in: [403] } }] });
  assert.equal(statusAssertionsOf(validateSequence(seq)).length, 2);
});

test('the run validator recomputes every status row from the sealed responses and binds them to the sequence', async () => {
  const seq = statusSequence();
  const r = await run(seq, { 'POST /refund': 403 });
  // A stored status verdict edited to pass is refused, by the row's sealed id; unsealed, the digest breaks first.
  const flipped = structuredClone(r); Object.assign(flipped.results[2], { status: 'pass', verdict: 'pass' }); flipped.counts = { pass: 3, fail: 0, inconclusive: 0, error: 0 };
  refuse(flipped, 'invalid-sequence-run', 'run-digest');
  refuse(reseal(flipped), 'sequence-verdict', 'BEN-ACCEPTED');
  // A response edited without its row, or a response dropped (the row would now read not sent), is refused.
  const answered = structuredClone(r); answered.responses['ben-refund'].status = 200;
  refuse(reseal(answered), 'sequence-verdict', 'BEN-ACCEPTED');
  const dropped = structuredClone(r); delete dropped.responses['amy-refund'];
  refuse(reseal(dropped), 'sequence-verdict', 'AMY-REFUSED');
  // Responses: only for named requests, in the runner's shape.
  for (const [label, edit] of [['unnamed request', x => { x.responses.other = { status: 200, complete: true, transport: 'complete' }; }], ['complete without status', x => { x.responses['amy-refund'] = { status: null, complete: true, transport: 'complete' }; }],
    ['status out of range', x => { x.responses['amy-refund'].status = 99; }], ['extra field', x => { x.responses['amy-refund'].body = 'Refund issued'; }], ['not an object', x => { x.responses = []; }]]) {
    const x = structuredClone(r); edit(x); assert.throws(() => validateSequenceRun(reseal(x)), e => e.code === 'invalid-sequence-run' && e.detail === 'responses', label);
  }
  // Status assertions: the sequence's rules, one per request, ids unique across every row.
  for (const [label, edit, detail] of [['bad codes', x => { x.statusAssertions[0].in = [42]; }, 'status-assertions'], ['extra key', x => { x.statusAssertions[0].note = 'n'; }, 'status-assertions'],
    ['same request twice', x => { x.statusAssertions[1].request = 'amy-refund'; }, 'status-assertions'], ['id of the effect row', x => { x.statusAssertions[0].id = 'NO-REFUND'; }, 'assertions'],
    ['a row too many', x => { x.results.push(structuredClone(x.results[2])); }, 'assertions'], ['missing', x => { delete x.statusAssertions; }, 'status-assertions']]) {
    const x = structuredClone(r); edit(x); assert.throws(() => validateSequenceRun(reseal(x)), e => e.code === 'invalid-sequence-run' && e.detail === detail, label);
  }
  // The evaluator identity is sealed in a /3 run.
  const noEvaluator = structuredClone(r); delete noEvaluator.evaluatorHash;
  refuse(reseal(noEvaluator), 'invalid-sequence-run', 'identity');
  // A rewritten status assertion re-derived consistently validates alone, but not against the sequence.
  const rewritten = structuredClone(r); rewritten.statusAssertions[1].in = [403];
  rewritten.results[2] = saved(decideStatusAssertion(rewritten.statusAssertions[1], rewritten.responses['ben-refund'], null)); rewritten.counts = countsOf(rewritten.results);
  validateSequenceRun(reseal(rewritten));
  refuse(rewritten, 'unexpected-sequence', undefined, { expectedSequence: seq });
});

test('/2 records still validate as /2; a /3 run relabelled /2 is refused or loses its binding', async () => {
  const plain = { ...statusSequence(), steps: statusSequence().steps.map(({ assertStatus: _a, ...step }) => step) };
  const r3 = await run(plain);
  assert.deepEqual([r3.schema, r3.statusAssertions, Object.keys(r3.responses)], [SEQUENCE_RUN_SCHEMA, [], ['amy-login', 'amy-refund', 'ben-refund']]);
  // A record the /2 runner wrote: no evaluator, status assertions or responses.
  const r2 = structuredClone(r3); r2.schema = SEQUENCE_RUN_SCHEMA_V2; delete r2.evaluatorHash; delete r2.statusAssertions; delete r2.requests; delete r2.responses;
  validateSequenceRun(reseal(r2), { expectedSequence: plain });
  // A /2 record carrying any /3 field is not one the /2 runner wrote.
  for (const key of ['evaluatorHash', 'statusAssertions', 'requests', 'responses']) { const x = structuredClone(r2); x[key] = r3[key]; refuse(reseal(x), 'invalid-sequence-run', 'schema'); }
  // Downgrading a run with status rows to /2 drops them; bound to its sequence, that is refused.
  const seq = statusSequence(), withStatus = await run(seq, { 'POST /refund': 403 });
  const downgraded = structuredClone(withStatus); downgraded.schema = SEQUENCE_RUN_SCHEMA_V2; delete downgraded.evaluatorHash; delete downgraded.statusAssertions; delete downgraded.requests; delete downgraded.responses;
  downgraded.results = downgraded.results.slice(0, 1); downgraded.counts = countsOf(downgraded.results);
  validateSequenceRun(reseal(downgraded));
  refuse(downgraded, 'unexpected-sequence', undefined, { expectedSequence: seq });
});

test('the evaluator identity covers exactly the modules that decide or recompute a sequence verdict', async () => {
  assert.deepEqual(SEQUENCE_EVALUATOR_FILES, ['integrations/sequences/sequence.mjs', 'integrations/sequences/run-validator.mjs', 'src/effect-events.mjs', 'src/body-fields.mjs', 'src/idempotency.mjs', 'src/custody.mjs', 'src/effect-lineage.mjs']);
  const sources = await Promise.all(SEQUENCE_EVALUATOR_FILES.map(async name => [name, await readFile(new URL(`../../${name}`, import.meta.url), 'utf8')]));
  assert.equal(SEQUENCE_EVALUATOR_HASH, digest({ files: sources }));
  for (const outside of ['./cli.mjs', './native.mjs', '../regression-gate/gate.mjs']) assert.doesNotMatch(await readFile(new URL(outside, import.meta.url), 'utf8'), /function decide|evaluateEffectAssertion\(|clauseCustody\(|\.in\.includes\(/, `Verdict logic must not live outside the identity set (${outside}).`);
});

test('the CLI prints each status row with the status answered and refuses save flags with --validate', async () => {
  const lines = [];
  assert.equal(await main(['--validate', '/nonexistent.json', '--save', '/tmp/x'], { log: s => lines.push(s) }), 2);
  assert.deepEqual(lines, ['Configuration error: --save, --build, --regression-gate and --baseline apply to a new run, not to --validate.']);
  for (const [args, message] of [[['--regression-gate'], /need --save DATA_DIR/], [['--build', 'b1'], /need --save DATA_DIR/], [['--save', '/tmp/x', '--baseline', 'id'], /--baseline needs --regression-gate/],
    [['--save', '/tmp/x'], /--save needs --build LABEL/], [['--save', '/tmp/x', '--build', 'bad\nlabel'], /--save needs --build LABEL/], [['--save', '--build', 'b'], /--save needs a value/], [['--save', '/tmp/x', '--build'], /--build needs a value/]]) {
    const out = [];
    assert.equal(await main(['--sequence', '/nonexistent.json', '--origin', 'http://127.0.0.1:1', '--observers', '/nonexistent.json', ...args], { log: s => out.push(s) }), 2, args.join(' '));
    assert.match(out.join('\n'), message, args.join(' '));
  }
});
