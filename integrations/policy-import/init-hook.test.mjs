import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { validateTargetFile } from '../../src/contracts.mjs';
import { runHttpAssessment } from '../../src/http-connector.mjs';
import { createObservedSupportApp } from '../../examples/observed-support-app.mjs';
import { DRAFT_STATUS } from './write-draft.mjs';
import { matchTemplate, recordsFromProfile } from './init-hook.mjs';

// The inference hooks as `scopehaven init` loads them (integrations/init/hooks.mjs, an earlier review): each module that
// exists is imported and its draftForInit({ profile, openapi, root }) is called; the result must be { checks, notDrafted,
// warnings }. A module that does not exist reads as not available (session-import is held on its own branch, so init finds no
// session hook). This copy of the loader is the contract; it reads no init file.
const integrations = fileURLToPath(new URL('../', import.meta.url));
const MODULES = ['policy-import/init-hook.mjs', 'session-import/init-hook.mjs', 'model-standin/init-hook.mjs'];
async function laneDDrafts(args) {
  const results = [];
  for (const rel of MODULES) {
    const path = `${integrations}${rel}`;
    if (!existsSync(path)) { results.push({ module: rel, available: false }); continue; }
    const mod = await import(pathToFileURL(path).href);
    const out = await mod.draftForInit({ ...args, profile: structuredClone(args.profile), root: integrations });
    results.push({ module: rel, out });
  }
  return results;
}
const here = fileURLToPath(new URL('.', import.meta.url));
const OPENAPI = join(here, 'fixtures', 'support-app-openapi.json');

// The starter profile init's buildProfile writes for the owned support app (two identities, Bearer slot, /api/me).
const starter = (origin = 'http://127.0.0.1:4480') => {
  const actor = (principalId, tenantId, env, identityValue) => ({ principalId, tenantId, role: 'member', credentialEnv: env, identityValue });
  const get = (id, title, category, severity, actorId, path, assertions) => ({ id, title, category, severity, actorId, method: 'GET', path, evidenceRequirement: 'response', assertions });
  const eq = expected => ({ kind: 'status.equals', expected }), within = expected => ({ kind: 'status.in', expected });
  return { id: 'support', name: 'support (init starter)', applicationId: 'support', origin, buildLabel: 'local copy', contextId: 'synthetic-seed-1',
    actors: { a: actor('agent-a', 'tenant-a', 'SCOPEHAVEN_TARGET_EXAMPLE_AGENT_A', 'agent-a@acme.test'), b: actor('agent-b', 'tenant-b', 'SCOPEHAVEN_TARGET_EXAMPLE_AGENT_B', 'agent-b@globex.test'), anonymous: { principalId: 'anonymous' } },
    requiredControlIds: ['A-WHOAMI', 'B-WHOAMI', 'A-OWN-RECORD', 'B-OWN-RECORD'],
    checks: [
      get('A-WHOAMI', "Identity A's session names identity A", 'Identity', 'control', 'a', '/api/me', [eq(200), { kind: 'json.equals', pointer: '/email', expected: 'agent-a@acme.test' }]),
      get('B-WHOAMI', "Identity B's session names identity B", 'Identity', 'control', 'b', '/api/me', [eq(200), { kind: 'json.equals', pointer: '/email', expected: 'agent-b@globex.test' }]),
      get('A-OWN-RECORD', 'Identity A opens its own record (allowed use)', 'Access', 'control', 'a', '/api/orders/A-1', [eq(200)]),
      get('B-OWN-RECORD', 'Identity B opens its own record (allowed use)', 'Access', 'control', 'b', '/api/orders/B-1', [eq(200)]),
      get('B-READS-A-RECORD', "Identity B cannot open identity A's record", 'Access', 'high', 'b', '/api/orders/A-1', [within([403, 404])]),
      get('A-READS-B-RECORD', "Identity A cannot open identity B's record", 'Access', 'high', 'a', '/api/orders/B-1', [within([403, 404])]),
      get('ANON-READS-A-RECORD', "A signed-out request cannot open identity A's record", 'Access', 'high', 'anonymous', '/api/orders/A-1', [within([401, 403, 404])]),
    ] };
};
const shapeOk = out => Array.isArray(out.checks) && Array.isArray(out.notDrafted) && Array.isArray(out.warnings);
// What a person does after init: adds the proposed checks to the profile (as a confirmation would), requires the controls.
const withProposals = (profile, checks) => ({ ...profile, checks: [...profile.checks, ...checks], requiredControlIds: [...profile.requiredControlIds, ...checks.filter(c => c.severity === 'control').map(c => c.id)] });

test('init loads the hooks that exist and each returns { checks, notDrafted, warnings }; without inputs they draft nothing and say why', async () => {
  const results = await laneDDrafts({ profile: starter(), openapi: undefined });
  assert.deepEqual(results.map(r => [r.module, r.available !== false]), [[MODULES[0], true], [MODULES[1], false], [MODULES[2], true]]);
  const [policy, , standin] = results.map(r => r.out);
  for (const out of [policy, standin]) assert.ok(shapeOk(out));
  assert.equal(policy.checks.length, 0);
  assert.match(policy.notDrafted[0].reason, /--openapi/);
  assert.equal(standin.checks.length, 0);
  assert.deepEqual(standin.standIn.env, ['OPENAI_BASE_URL=http://127.0.0.1:4471/v1', 'OPENAI_API_BASE=http://127.0.0.1:4471/v1', 'OPENAI_API_KEY=standin-no-key']);
  assert.equal(standin.standIn.plan.schema, 'scopehaven-model-standin-plan/1');
});

test('policy-import hook: write checks from --openapi, the record parameter inferred from the starter profile\'s own-record paths', async () => {
  const profile = starter();
  assert.deepEqual(recordsFromProfile(profile), { aPath: '/api/orders/A-1', bPath: '/api/orders/B-1', index: 2, a: 'A-1', b: 'B-1' });
  assert.deepEqual(matchTemplate(['/orders/{orderId}', '/orders/{orderId}/refunds'], '/api/orders/A-1', 2, '/api'), { template: '/orders/{orderId}', parameter: 'orderId' });
  assert.equal(matchTemplate(['/tickets/{id}'], '/api/orders/A-1', 2, '/api'), null);
  const [{ out }] = await laneDDrafts({ profile, openapi: OPENAPI });
  assert.deepEqual(out.inferred, { records: { a: 'A-1', b: 'B-1' }, parameter: { name: 'orderId', read: '/orders/{orderId}' } });
  assert.deepEqual(out.binding.pairs, { 'requirement:bearer': { A: 'a', B: 'b' } });
  const refund = out.draft.provenance.filter(p => p.resource === '/orders/{orderId}/refunds').map(p => p.variant);
  assert.deepEqual(refund, ['owner-read-before', 'own-read', 'twin-before', 'foreign-owner', 'anonymous', 'twin-after']);
  const byVariant = (resource, variant) => out.checks.find(c => c.id === out.draft.provenance.find(p => p.resource === resource && p.variant === variant).checkId);
  assert.deepEqual([byVariant('/orders/{orderId}/refunds', 'twin-before').path, byVariant('/orders/{orderId}/refunds', 'twin-before').body, byVariant('/orders/{orderId}/refunds', 'twin-before').assertions],
    ['/api/orders/A-1/refunds', { reason: 'customer asked' }, [{ kind: 'status.equals', expected: 201 }]]);
  assert.equal(byVariant('/orders/{orderId}/refunds', 'foreign-owner').path, '/api/orders/B-1/refunds');
  assert.deepEqual(byVariant('/assistant/chat', 'twin-before').assertions, [{ kind: 'status.equals', expected: 200 }]);
  assert.ok(out.draft.provenance.every(p => p.status === DRAFT_STATUS));
  assert.ok(out.notDrafted.some(n => n.variant === 'read-back' && /unchanged/.test(n.reason)));
  assert.ok(!out.warnings.some(w => /no allowed-use GET control/.test(w)), 'the starter profile carries A-OWN-RECORD and B-OWN-RECORD');
  assert.ok(out.warnings.some(w => /inferred from A-OWN-RECORD/.test(w)));
  assert.match(out.confirm, /write-draft-confirm/);
  // One identity: no foreign side; the parameter still binds A.
  const single = structuredClone(profile); delete single.actors.b; single.checks = single.checks.filter(c => c.actorId !== 'b' && !c.id.startsWith('B-')); single.requiredControlIds = ['A-WHOAMI', 'A-OWN-RECORD'];
  const one = (await laneDDrafts({ profile: single, openapi: OPENAPI }))[0].out;
  assert.deepEqual(one.binding.pairs, { 'requirement:bearer': { A: 'a' } });
  assert.ok(one.notDrafted.some(n => n.variant === 'foreign-owner' && /no second actor/.test(n.reason)));
});

test('end to end over loopback: the write hook\'s proposals, added to the starter profile, run against the owned support app', async t => {
  const app = await createObservedSupportApp({ build: 'secure' });
  t.after(() => app.close());
  const results = await laneDDrafts({ profile: starter(app.origin), openapi: OPENAPI });
  // The review step: proposals a reviewer keeps. The assistant refuses in text with a 200, so its status refusals are left out.
  const keep = c => !(c.path === '/api/assistant/chat' && c.severity === 'high' && c.actorId !== 'anonymous') && !(c.path === '/api/assistant/chat' && c.actorId === 'b' && c.severity === 'high');
  const proposals = results[0].out.checks.filter(keep);
  const ids = new Set(); const unique = proposals.filter(c => !ids.has(c.id) && ids.add(c.id));
  const profile = withProposals(starter(app.origin), unique);
  validateTargetFile({ schemaVersion: 1, targets: [profile] });
  const run = await runHttpAssessment(profile, { env: app.env });
  assert.deepEqual(run.results.filter(r => r.status !== 'pass').map(r => [r.id, r.status, r.summary.slice(0, 120)]), []);
  assert.ok(run.results.length > profile.checks.length / 2);
  assert.equal(run.results.length, profile.checks.length);
  // The starter profile alone had 7 checks; the hooks proposed the rest.
  assert.ok(profile.checks.length - 7 >= 5, `${profile.checks.length - 7} proposed checks kept`);
  app.setBuild('refuse-b');
  const blocked = await runHttpAssessment(profile, { env: app.env });
  assert.ok(blocked.results.some(r => r.status === 'fail' && profile.checks.find(c => c.id === r.id).actorId === 'b'));
});
