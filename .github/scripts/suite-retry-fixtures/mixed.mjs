import test, {describe, it} from 'node:test';
import assert from 'node:assert/strict';
test('passing', () => {});
test('failing', () => assert.fail('benign synthetic failure'));
test('TODO failure', {todo: true}, () => assert.fail('expected TODO'));
test('skipped', {skip: true}, () => {});
test('nested parent', async t => {await t.test('nested child', () => assert.fail('nested'));});
describe('failing suite', () => {it('child pass', () => {}); it('child fail', () => assert.fail('suite child'));});
describe.skip('skipped suite', () => {it('unrun', () => {});});
