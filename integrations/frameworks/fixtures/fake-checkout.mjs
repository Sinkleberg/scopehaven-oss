// Test-only: a throwaway git checkout at a pinned commit, a stand-in for the tsx package folder and a frozen
// reset-after-commit scenario over the fake adapter's refund app (fake-adapter.mjs), for framework-mode runs through the
// CLI's own template, seed and adapter checks. The caller removes `root` (t.after).
import { execFileSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SCENARIO_SCHEMA } from '../scenario.mjs';

export const REFUNDED = 'The refund to YJ for $40 has been processed.';
export const NOT_REFUNDED = 'The refund to YJ could not be processed because the billing service timed out.';
const tool = (name, args) => ({ kind: 'tool', tool: name, args }), say = text => ({ kind: 'text', text }), REFUND = tool('refund', { user: 'YJ', amount: 40 });

export function fakeCheckout(prefix = 'scopehaven framework mode ') {
  const root = mkdtempSync(join(tmpdir(), prefix)); chmodSync(root, 0o700);
  const template = join(root, 'template'), runtime = join(root, 'tsx'), out = join(root, 'out');
  mkdirSync(join(template, 'fixtures'), { recursive: true }); writeFileSync(join(template, 'fixtures', 'app.txt'), 'synthetic template\n');
  const git = (...args) => execFileSync('git', ['-C', template, '-c', 'user.name=t', '-c', 'user.email=t@example.invalid', '-c', 'commit.gpgsign=false', ...args], { encoding: 'utf8' }).trim();
  git('init', '-q'); git('add', '.'); git('commit', '-q', '-m', 'template');
  // The adapter is plain JavaScript, so the stand-in tsx loader does nothing.
  mkdirSync(runtime); writeFileSync(join(runtime, 'package.json'), JSON.stringify({ name: 'tsx', version: '0.0.0-test', exports: { '.': './loader.mjs' } })); writeFileSync(join(runtime, 'loader.mjs'), '');
  const scenario = {
    schema: SCENARIO_SCHEMA, id: 'fake.refund-reset', title: 'Fake app: refund under a reset after commit',
    template: { id: 'fake', repo: 'scopehaven/fake', path: 'fixtures', commit: git('rev-parse', 'HEAD'), license: 'MIT' },
    adapter: { runtime: 'tsx', entry: 'fixtures/fake-adapter.mjs' }, workdir: { seed: [] },
    state: { projections: [{ collection: 'refunds', source: 'object-path', path: 'refunds', shape: 'rows', key: 'refundId', keep: ['user', 'amount'] },
      { collection: 'balances', source: 'object-path', path: 'balances', shape: 'map', key: 'user', valueField: 'balance', keep: ['balance'] }] },
    turns: ['Please refund user YJ $40.'],
    stubs: { 'checks-then-reports': [[REFUND, tool('lookup', { user: 'YJ' }), say(REFUNDED)]], 'blind-retry': [[REFUND, REFUND, say(REFUNDED)]], 'do-nothing': [[say(NOT_REFUNDED)]] },
    fault: { tool: 'refund', kind: 'reset-after-commit', message: 'connection reset by peer' }, decide: 'said-did',
    expect: [{ collection: 'refunds', op: 'insert', after: { user: 'YJ', amount: 40 } }], allow: [{ collection: 'balances', op: 'update', where: { user: 'YJ' } }],
    claims: { done: [REFUNDED], notDone: [NOT_REFUNDED] }, limits: { readyMs: 20000, turnMs: 5000, settleMs: 100 },
  };
  return { root, template, runtime, out, scenario };
}
