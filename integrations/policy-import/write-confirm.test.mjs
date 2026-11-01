// Goal 03 M2: write-plan confirmation and its forgery surface. Synthetic inputs in memory; the CLI writes only into a
// temporary directory with a space in its name. Nothing is sent to any application.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { canonical, sha256 } from './matrix.mjs';
import { buildWritePlan } from './write-plan.mjs';
import { WRITE_CONFIRMATION_SCHEMA, checkPlanCases, confirmWritePlan, verifyWriteConfirmation } from './write-confirm.mjs';
import { main } from './cli.mjs';

// The same synthetic statement, binding and matrix as write-plan.test.mjs (its definitions, without its tests).
const here = fileURLToPath(new URL('.', import.meta.url));
const source = readFileSync(join(here, 'write-plan.test.mjs'), 'utf8');
const fixtureURL = pathToFileURL(join(here, 'write-plan.test.mjs')).href;
const prefix = source.split("\ntest('")[0].replace(/from '(\.\.?\/[^']+)'/g, (_m, p) => `from '${new URL(p, fixtureURL).href}'`);
const { statementOf, BINDING, MATRIX } = await import('data:text/javascript;base64,' + Buffer.from(`${prefix}\nexport { statementOf, BINDING, MATRIX };`).toString('base64'));
const NOW = new Date('2026-10-08T13:00:00.000Z');
const inputs = () => ({ statement: statementOf(), binding: BINDING, matrices: [MATRIX] });
const reseal = (plan, edit) => { const { planId: _p, ...body } = structuredClone(plan); edit(body); return { ...body, planId: sha256(canonical(body)) }; };

test('confirm: re-derives the plan, accepts only an identical planId, and seals a record', () => {
  const plan = buildWritePlan(inputs());
  const record = confirmWritePlan(plan, { ...inputs(), confirmedBy: ' Operator Label ', now: NOW });
  assert.equal(record.schema, WRITE_CONFIRMATION_SCHEMA);
  assert.deepEqual([record.planId, record.confirmedBy, record.confirmedAt, record.cases.length], [plan.planId, 'Operator Label', NOW.toISOString(), plan.cases.length]);
  assert.ok(record.cases.every(c => /^[a-f0-9]{64}$/.test(c.caseDigest)));
  assert.ok(verifyWriteConfirmation(record));
  assert.equal(verifyWriteConfirmation({ ...record, confirmedBy: 'someone else' }), false);
  assert.throws(() => confirmWritePlan(plan, { ...inputs(), confirmedBy: '  ', now: NOW }), /confirmedBy is a label/);
  assert.throws(() => confirmWritePlan({ ...plan, cases: [] }, { ...inputs(), confirmedBy: 'x' }), /planId no longer matches/);
  assert.throws(() => confirmWritePlan(reseal(plan, b => { b.confirmed = true; }), { ...inputs(), confirmedBy: 'x' }), /already marked confirmed/);
});

test('forgery: a recomputed planId over an edited plan is refused by re-derivation, and every case property is re-checked', () => {
  const plan = buildWritePlan(inputs());
  const edits = {
    'a 500 counted as a refusal': b => { b.cases[0].turns.find(t => t.part === 'attempt').expect = [403, 500]; },
    'a json predicate': b => { b.cases[0].assertions.push({ id: 'J', kind: 'json.equals', severity: 'high', window: [1, 1], select: b.cases[0].assertions[0].select }); },
    'the paired control removed': b => { b.cases[0].assertions = b.cases[0].assertions.filter(a => a.kind === 'effect.none'); },
    'a control on another effect': b => { const c = b.cases[0].assertions.find(a => a.id === 'C'); c.select = { ...c.select, name: 'other' }; },
    'padding removed': b => { b.cases[0].turns = b.cases[0].turns.filter(t => t.part !== 'padding'); b.cases[0].assertions.forEach(a => { a.window = [1, 1]; }); },
    'padding with a write': b => { const t = b.cases[0].turns.find(x => x.part === 'padding'); t.method = 'PUT'; },
    'a path that is not the route\'s': b => { b.cases[0].turns[0].pathTemplate = '/api/admin/{{id}}'; },
    'a GET with a body': b => { const t = b.cases[0].turns.find(x => x.part === 'padding'); t.body = { a: 1 }; },
    'a control expecting a 404': b => { b.cases[0].turns.find(t => t.part === 'pair').expect = [404]; },
    'a window past the turns': b => { b.cases[0].assertions[0].window = [1, 99]; },
    'a vehicle its template does not allow': b => { b.cases.find(c => c.template === 'T5').vehicle = 'P'; },
    'a case marked confirmed': b => { b.cases[0].confirmed = true; },
    'a repeated case id': b => { b.cases[1].caseId = b.cases[0].caseId; },
  };
  for (const [label, edit] of Object.entries(edits)) {
    const forged = reseal(plan, edit);
    assert.throws(() => confirmWritePlan(forged, { ...inputs(), confirmedBy: 'x' }), /not what this statement, binding and matrices produce/, label);
    // The second line on its own: each property is refused on the case itself.
    assert.throws(() => checkPlanCases(forged, BINDING), /was not drafted from the statement as recorded/, label);
  }
  checkPlanCases(plan, BINDING);
  // One property per edit, so each check is shown on its own (an edit that trips two checks shows neither).
  const alone = {
    'an attempt expecting other 4xx statuses': b => { b.cases[0].turns.find(t => t.part === 'attempt').expect = [401, 403]; },
    'a padding turn expecting a 5xx': b => { b.cases[0].turns.find(t => t.part === 'padding').expect = [503]; },
    'a json predicate filed as a control': b => { b.cases[0].assertions.push({ id: 'J', kind: 'json.equals', severity: 'control', window: [1, 1], select: b.cases[0].assertions[0].select }); },
    'padding with a bound write route': b => { const t = b.cases[0].turns.find(x => x.part === 'padding'); const w = b.cases[0].turns.find(x => x.part === 'attempt');
      Object.assign(t, { resource: w.resource, action: w.action, method: w.method, pathTemplate: w.pathTemplate }); },
  };
  for (const [label, edit] of Object.entries(alone)) assert.throws(() => checkPlanCases(reseal(plan, edit), BINDING), /was not drafted from the statement as recorded/, label);
  // A case whose shape contradicts its decision is refused on the case alone, whatever path drafted it: a deny drafted
  // as a control only, and an allow carrying a prohibition.
  const flip = (template, decision) => reseal(plan, b => { b.cases.find(c => c.template === template).decision = decision; });
  assert.throws(() => checkPlanCases(flip('T6', 'deny'), BINDING), /contradicts its stated decision/);
  assert.throws(() => checkPlanCases(flip('T1', 'allow'), BINDING), /contradicts its stated decision/);
  // Another binding or statement than the plan's is refused too.
  const otherBinding = structuredClone(BINDING); otherBinding.observers.settleMs = 300;
  assert.throws(() => confirmWritePlan(plan, { ...inputs(), binding: otherBinding, confirmedBy: 'x' }), /not what this statement/);
});

test('CLI: write-plan and write-confirm in a path with spaces; new files, mode 0600', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven write plan ')); t.after(() => rm(dir, { recursive: true, force: true }));
  const at = n => join(dir, n), quiet = { out: () => {} };
  await writeFile(at('statement.json'), JSON.stringify(statementOf())); await writeFile(at('binding.json'), JSON.stringify(BINDING)); await writeFile(at('matrix.json'), JSON.stringify(MATRIX));
  assert.equal(await main(['write-plan', at('statement.json'), at('matrix.json'), '--binding', at('binding.json'), '--out', at('plan.json')], quiet), 0);
  const plan = JSON.parse(await readFile(at('plan.json'), 'utf8'));
  assert.equal(plan.planId, buildWritePlan(inputs()).planId);
  assert.equal((await stat(at('plan.json'))).mode & 0o777, 0o600);
  assert.equal(await main(['write-confirm', at('plan.json'), at('matrix.json'), '--statement', at('statement.json'), '--binding', at('binding.json'), '--confirmed-by', 'Operator Label', '--out', at('record.json')], quiet), 0);
  assert.ok(verifyWriteConfirmation(JSON.parse(await readFile(at('record.json'), 'utf8'))));
  await assert.rejects(main(['write-confirm', at('plan.json'), at('matrix.json'), '--statement', at('statement.json'), '--binding', at('binding.json'), '--confirmed-by', 'x', '--out', at('record.json')], quiet), /EEXIST/);
  await assert.rejects(main(['write-confirm', at('plan.json'), '--statement', at('statement.json'), '--binding', at('binding.json'), '--confirmed-by', 'x', '--out', at('r2.json')], quiet), /not what this statement/, 'the matrix the plan came from is needed');
  await assert.rejects(main(['write-plan', at('statement.json'), '--out', at('p2.json')], quiet), /needs --binding/);
});
