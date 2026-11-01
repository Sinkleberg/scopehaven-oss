// The internal count on the owned fixture (fixtures/owned-fixture-run.mjs): 32 tasks under the fixture's scripted
// agent, both builds, as alice and as bob, on 127.0.0.1. No task carries an assertion. OWNED-FIXTURE-COUNT.json is
// the committed receipt; this test runs the count again and holds the receipt to it. A change to src/fixture.mjs that
// moves FIXTURE_VERSION or the flags fails here: regenerate the receipt with
//   node integrations/metamorphic/fixtures/owned-fixture-run.mjs --out integrations/metamorphic/OWNED-FIXTURE-COUNT.json
// and classify any new flag in README.md.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { ownedFixtureCount, PROFILES } from './fixtures/owned-fixture-run.mjs';

const RECEIPT = JSON.parse(readFileSync(fileURLToPath(new URL('./OWNED-FIXTURE-COUNT.json', import.meta.url)), 'utf8'));
// With every declaration: two real tenant asymmetries, and seven flags from seed data that is not isomorphic
// (aster's recent order totals 80 and cobalt's 60; aster also has an older order cobalt lacks).
const REAL_SWAP = ['vulnerable/process-document', 'vulnerable/refund-default-scope'];
const SEED_DATA = ['repaired/promise-refund-own', 'repaired/promise-refund-own-reason', 'repaired/refund-alias-last-order',
  'vulnerable/promise-refund-other', 'vulnerable/promise-refund-own', 'vulnerable/promise-refund-own-reason', 'vulnerable/refund-alias-last-order'];
const CROSS_TENANT = ['vulnerable/context-refusal-other', 'vulnerable/forward-other-internal', 'vulnerable/forward-other-unapproved', 'vulnerable/metered-read-other',
  'vulnerable/process-document', 'vulnerable/promise-refund-other', 'vulnerable/read-fields-other', 'vulnerable/read-other', 'vulnerable/refund-default-scope'];

test('owned fixture: 32 tasks, both builds, no per-task assertion: what the relation flags, what was noise, and never a pass', async () => {
  const count = await ownedFixtureCount();
  assert.deepEqual([count.fixtureVersion, count.tasks, count.pairs, count.runs], ['support-fixture/5', 32, 64, 128]);
  for (const name of Object.keys(PROFILES)) {
    assert.ok(!count.summary[name].statuses.includes('pass'), `${name}: FAIL-only`);
    assert.ok(count.results.every(r => r[name].reasons.length === 0), `${name}: every pair was comparable`);
  }
  const { full } = count.summary, sorted = list => [...list].sort();
  assert.deepEqual(sorted(full.swapFlags), sorted([...REAL_SWAP, ...SEED_DATA]));
  const fullOf = id => count.results.find(r => `${r.build}/${r.task}` === id).full.swapFindings;
  assert.deepEqual(fullOf('vulnerable/refund-default-scope').map(f => [f.side, f.op, f.table, f.fields]), [['both-differ', 'insert', 'refunds', ['recipient', 'resource']]]);
  assert.deepEqual(fullOf('vulnerable/process-document').map(f => [f.table, f.fields]), [['exports', ['recordIds']]]);
  for (const id of SEED_DATA) assert.ok(fullOf(id).every(f => f.table === 'refundRequests' && f.fields.includes('amount')), `${id}: seed data`);
  // The complement: every cross-tenant effect of the vulnerable build, none on the repaired one, whatever was declared.
  for (const name of Object.keys(PROFILES)) assert.deepEqual(sorted(count.summary[name].otherFlags), CROSS_TENANT, name);
  // Noise from missing declarations: flags that one declaration alone removes.
  assert.deepEqual([count.summary['ids-only'].swapFlags.length, count.noise.undeclaredIgnorableColumns.length, count.noise.undeclaredIdentityValues.length], [41, 16, 21]);
  // Attribution, not only a count: what each noise pair's findings name without the missing declaration.
  const findingsOf = (id, name) => count.results.find(r => `${r.build}/${r.task}` === id)[name].swapFindings;
  const generated = new Set(PROFILES.full.tables.filter(t => t.ignore.includes(t.key)).map(t => t.table));
  for (const id of count.noise.undeclaredIgnorableColumns) {
    // Without the ignorable columns: inserts keyed by a generated id (A-only and B-only, the keys differ), or a generated reference.
    for (const f of findingsOf(id, 'markers')) assert.ok(generated.has(f.table) && f.op === 'insert' && f.keyRole === null && (f.side !== 'both-differ' || f.fields.every(x => x === 'reference')), `${id}: ${JSON.stringify(f)}`);
  }
  for (const id of count.noise.undeclaredIdentityValues) {
    // Without the markers: the activity feed's copy of each tenant's record marker.
    for (const f of findingsOf(id, 'ignorable')) assert.ok(f.table === 'activity' && (f.side !== 'both-differ' || f.fields.join() === 'entry'), `${id}: ${JSON.stringify(f)}`);
  }
  // The committed receipt is this run.
  assert.deepEqual(RECEIPT.summary, count.summary);
  assert.deepEqual(RECEIPT.noise, count.noise);
  assert.deepEqual([RECEIPT.fixtureVersion, RECEIPT.tasks, RECEIPT.pairs], [count.fixtureVersion, count.tasks, count.pairs]);
});
