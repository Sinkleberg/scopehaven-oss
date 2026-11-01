// Goal 03 M2, stage 1: the write binding and the variant inventory. Synthetic statement, binding and matrix in memory;
// nothing reads an application or sends a request.
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildMatrix, canonical, cellKey, sha256 } from './matrix.mjs';
import { proposeStatement, sealStatement } from './statement.mjs';
import { VALUES_SCHEMA, WRITE_BINDING_SCHEMA, missingValues, validateValues, validateWriteBinding, valuesNeeded } from './write-binding.mjs';
import { CASE_LIMITS, CLASSIFY_ORDER, DIMENSIONS, LIFECYCLE_PHASES, LIMIT_POINTS, PRIORITY, TEMPLATES, buildWritePlan, inventoryCells, inventoryDigest, planAccounting, variantKey, verifyPlanId, writeInventory } from './write-plan.mjs';
import { MULTITURN_SCHEMA, compileScenario } from '../multiturn/multiturn.mjs';

const NOW = new Date('2026-10-08T12:00:00.000Z');
const MATRIX = buildMatrix({ application: 'desk', layer: 'openapi-security', sources: [], cells: [
  { role: 'agent', resource: 'invoices', action: 'read', decision: 'unknown', basis: 'unreadable', citations: [{ source: 'openapi.json' }] },
  { role: 'manager', resource: 'invoices', action: 'read', decision: 'allow', basis: 'declared', citations: [{ source: 'openapi.json' }] },
] });
const rule = (ruleId, role, resource, action, decision, extra = {}) => ({ ruleId, role, resource, action, decision, source: { sourceId: 'policy', locator: ruleId }, confidence: 'stated', ...extra });
const RULES = [
  rule('upd-own', 'agent', 'orders', 'update', 'allow', { relation: 'own' }),
  rule('upd-peer', 'agent', 'orders', 'update', 'deny', { relation: 'other-same-role' }),
  rule('upd-other', 'agent', 'orders', 'update', 'deny', { relation: 'other-role' }),
  rule('upd-cross', 'agent', 'orders', 'update', 'deny', { relation: 'cross-tenant' }),
  rule('upd-mgr', 'manager', 'orders', 'update', 'allow'),
  rule('refund-cap', 'agent', 'refunds', 'create', 'allow', { limit: { pointer: '/amount', cap: 100, unit: 'USD' } }),
  rule('del-made-by-mgr', 'agent', 'orders', 'delete', 'deny', { creators: ['manager'], creatorRule: 'actor-must-differ' }),
  rule('del-own-made', 'agent', 'orders', 'delete', 'allow', { creators: ['agent'], creatorRule: 'actor-must-equal' }),
  rule('close', 'agent', 'tickets', 'close', 'allow', { lifecycle: { transition: 'suspend', subject: 'actor', after: 'deny' } }),
  rule('void', 'agent', 'invoices', 'void', 'allow'),
  rule('archive', 'agent', 'orders', 'archive', 'allow'),
  rule('hide', 'agent', 'invoices', 'hide', 'deny'), rule('hide-mgr', 'manager', 'invoices', 'hide', 'allow'),
  rule('audit', 'auditor', 'orders', 'update', 'deny'),
  rule('export', 'agent', 'reports', 'export', 'allow'),
  rule('share-own', 'agent', 'reports', 'share', 'allow', { relation: 'own' }),
  rule('void-paid', 'manager', 'invoices', 'void', 'deny', { state: 'paid' }),
  rule('refund-mgr', 'manager', 'refunds', 'create', 'deny'),
  rule('reopen-made', 'agent', 'tickets', 'reopen', 'allow', { creators: ['agent'], creatorRule: 'actor-must-equal' }),
  rule('reopen-mgr-made', 'agent', 'tickets', 'reopen', 'deny', { creators: ['manager'], creatorRule: 'actor-must-differ' }),
  rule('reopen-mgr', 'manager', 'tickets', 'reopen', 'allow'),
  rule('suspend-mgr', 'manager', 'users', 'suspend', 'allow'),
];
const statementOf = (rules = RULES, extra = {}) => {
  const proposal = proposeStatement({ application: 'desk', matrices: [MATRIX] });
  return sealStatement({ ...proposal, roles: ['agent', 'manager', 'auditor'], tenants: ['acme', 'globex'], sources: [{ sourceId: 'policy', label: 'Desk policy' }], rules, ...extra },
    { statedBy: 'Operator Name', now: NOW });
};
const route = (method, pathTemplate, object, extra = {}) => ({ method, pathTemplate, object, allowStatus: 200, refusal: { kind: 'status', statuses: [403, 409] }, ...extra });
const effect = (operation, name) => ({ source: 'sql-audit-table', operation, name, actorAttributed: true });
const BINDING = {
  schema: WRITE_BINDING_SCHEMA, application: 'desk', targetId: 'desk-local',
  actors: { a1: { role: 'agent', tenant: 'acme' }, a2: { role: 'agent', tenant: 'acme' }, a3: { role: 'agent', tenant: 'globex' }, m1: { role: 'manager', tenant: 'acme' } },
  routes: {
    orders: {
      create: route('POST', '/api/orders', null, { bodyTemplate: { note: 'synthetic' } }),
      read: route('GET', '/api/orders/{{id}}', 'order'),
      update: route('PUT', '/api/orders/{{id}}', 'order', { bodyTemplate: { note: 'changed' }, refusal: { kind: 'status', statuses: [403, 404], notFoundIsRefusal: true } }),
      delete: route('DELETE', '/api/orders/{{id}}', 'order'),
      archive: route('POST', '/api/orders/{{id}}/archive', 'order'),
    },
    refunds: { create: route('POST', '/api/refunds', null, { bodyTemplate: { amount: 1 } }), list: route('GET', '/api/refunds', null) },
    tickets: { close: route('POST', '/api/tickets/{{id}}/close', 'ticket'), reopen: route('POST', '/api/tickets/{{id}}/reopen', 'ticket'), read: route('GET', '/api/tickets/{{id}}', 'ticket') },
    users: { suspend: route('POST', '/api/users/{{id}}/suspend', 'user', { transition: 'suspend' }) },
    invoices: { void: route('POST', '/api/invoices/{{id}}/void', 'invoice'), hide: route('POST', '/api/invoices/{{id}}/hide', 'invoice', { refusal: { kind: 'silent', status: 200 } }) },
  },
  effects: {
    orders: { create: effect('insert', 'orders'), update: effect('update', 'orders'), delete: { ...effect('delete', 'orders'), name: { prefix: 'order' } } },
    refunds: { create: effect('insert', 'refunds') },
    tickets: { close: effect('update', 'tickets'), reopen: effect('update', 'tickets') },
    invoices: { void: effect('update', 'invoices') },
  },
  objects: {
    order: { create: { resource: 'orders', action: 'create', capture: '/id' }, precheck: { resource: 'orders', action: 'read' }, revert: { environmentReset: 'seed' } },
    ticket: { precheck: { resource: 'tickets', action: 'read' }, revert: { environmentReset: 'seed' } },
    user: { revert: { environmentReset: 'seed' } },
    invoice: {},
  },
  identityControls: { a1: 'ID-A1', a2: 'ID-A2', a3: 'ID-A3', m1: 'ID-M1' },
  observers: { path: 'observers.json', settleMs: 250 },
  budget: { maxCases: 50, inventoryLimit: 5000 },
};
const inv = (extra = {}) => writeInventory({ statement: statementOf(), binding: BINDING, matrices: [MATRIX], ...extra });
const variant = (i, where) => i.variants.find(v => Object.entries(where).every(([k, x]) => v[k] === x));

test('write binding: a valid binding normalizes with a digest; every malformed part is refused', () => {
  const b = validateWriteBinding(BINDING);
  assert.match(b.bindingDigest, /^[a-f0-9]{64}$/);
  assert.equal(b.routes.orders.delete.consumes, true, 'a DELETE consumes its object');
  assert.equal(b.routes.orders.update.consumes, false);
  assert.equal(validateWriteBinding({ ...BINDING, bindingDigest: b.bindingDigest }).bindingDigest, b.bindingDigest);
  const refuse = (edit, pattern) => { const x = structuredClone(BINDING); edit(x); assert.throws(() => validateWriteBinding(x), pattern); };
  refuse(x => { x.schema = 'scopehaven-policy-binding/1'; }, /needs schema "scopehaven-policy-write-binding\/1"/);
  refuse(x => { x.bindingDigest = '0'.repeat(64); }, /edited after it was computed/);
  refuse(x => { x.extra = 1; }, /unknown field extra/);
  refuse(x => { x.routes.orders.update.method = 'HEAD'; }, /method is GET, POST, PUT, PATCH, DELETE/);
  refuse(x => { x.routes.orders.read.bodyTemplate = { a: 1 }; }, /only a write method/);
  refuse(x => { x.routes.orders.read.pathTemplate = '/api/orders/{{oid}}'; }, /unknown placeholder \{\{oid\}\}/);
  refuse(x => { x.routes.orders.read.pathTemplate = '/api/orders/x{{id}}'; }, /a path segment is literal text or one whole \{\{placeholder\}\}/);
  refuse(x => { x.routes.orders.read.pathTemplate = '/api/orders/../{{id}}'; }, /a path segment is literal text/);
  refuse(x => { x.routes.orders.read.pathTemplate = '/api/orders'; }, /a request on an object puts \{\{id\}\}/);
  refuse(x => { x.routes.orders.create.pathTemplate = '/api/orders/{{id}}'; }, /\{\{id\}\} needs the object/);
  refuse(x => { x.routes.orders.create.bodyTemplate = { '{{actor}}': 1 }; }, /never goes in a body key/);
  refuse(x => { x.routes.orders.create.bodyTemplate = { owner: 'by {{actor}}' }; }, /a placeholder is a whole string value/);
  refuse(x => { x.routes.orders.update.refusal = { kind: 'status', statuses: [403, 500] }; }, /2 to 5 distinct 4xx statuses \(a 5xx is never a refusal\)/);
  refuse(x => { x.routes.orders.update.refusal = { kind: 'status', statuses: [403] }; }, /2 to 5 distinct 4xx/);
  refuse(x => { x.routes.orders.update.refusal = { kind: 'status', statuses: [403, 404] }; }, /404 is a refusal only with notFoundIsRefusal: true/);
  refuse(x => { x.routes.invoices.hide.refusal = { kind: 'silent', status: 403 }; }, /a silent refusal answers a 2xx status/);
  refuse(x => { x.routes.orders.update.allowStatus = 302; }, /allowStatus is a 2xx status/);
  refuse(x => { x.routes.orders.delete.consumes = false; }, /a DELETE consumes its object/);
  refuse(x => { x.routes.orders.update.object = 'ghost'; }, /object type ghost, which objects does not declare/);
  refuse(x => { x.effects.orders.update.source = 'logs'; }, /source is one of/);
  refuse(x => { x.effects.orders.update.operation = 'mutate'; }, /operation is one of/);
  refuse(x => { x.effects.orders.update.name = ''; }, /name is the exact effect name, or \{ prefix \}/);
  refuse(x => { delete x.effects.orders.update.actorAttributed; }, /actorAttributed/);
  refuse(x => { x.effects.reports = { export: effect('insert', 'reports') }; }, /effect reports export has no route/);
  refuse(x => { x.objects.order.create = { resource: 'orders', action: 'read', capture: '/id' }; }, /create names a bound write route on a collection/);
  refuse(x => { x.objects.order.create.capture = 'id'; }, /create.capture is the JSON pointer/);
  refuse(x => { x.objects.order.precheck = { resource: 'orders', action: 'update' }; }, /precheck names a bound GET route/);
  refuse(x => { x.objects.order.revert = { steps: [{ resource: 'orders', action: 'delete' }], environmentReset: 'seed' }; }, /one of them/);
  refuse(x => { x.objects.order.revert = { steps: [{ resource: 'orders', action: 'nope' }] }; }, /revert.steps name bound routes/);
  refuse(x => { x.identityControls.ghost = 'ID-G'; }, /identityControls maps a bound actor/);
  refuse(x => { x.observers = { path: 'observers.json' }; }, /declared settle/);
  refuse(x => { x.budget.maxCases = 0; }, /budget.maxCases is 1 to 500/);
  refuse(x => { x.budget.inventoryLimit = 1e6; }, /budget.inventoryLimit is 1 to 100000/);
  refuse(x => { x.actors.a1 = { role: 'agent' }; }, /tenant is a name or null/);
});

// A cell's variants: the product of relation, creators and states, each base variant times its own points and phases.
const checkCounts = i => {
  const byCell = new Map();
  for (const v of i.variants) byCell.set(v.cellKey, [...(byCell.get(v.cellKey) ?? []), v]);
  for (const [, list] of byCell) {
    const bases = new Map();
    for (const v of list) { const k = JSON.stringify([v.relation, v.creator, v.state]); bases.set(k, [...(bases.get(k) ?? []), v]); }
    const sizes = ['relation', 'creator', 'state'].map(d => new Set(list.map(v => JSON.stringify(v[d]))).size);
    assert.equal(bases.size, sizes.reduce((n, x) => n * x, 1), `${list[0].role} ${list[0].resource} ${list[0].action}`);
    for (const [, group] of bases) {
      const points = new Set(group.map(v => v.point)), phases = new Set(group.map(v => v.phase));
      assert.ok([1, 3].includes(points.size) && [1, 3].includes(phases.size) && group.length === points.size * phases.size, group[0].key);
    }
  }
  return byCell;
};

test('inventory: every cell is expanded over its dimensions, points and phases only where a rule has them, and nothing is dropped', () => {
  const i = inv();
  const byCell = checkCounts(i);
  assert.equal(i.total, i.variants.length);
  assert.equal(new Set(i.variants.map(v => v.key)).size, i.variants.length);
  // Relations on an object route, one "none" variant for a create, the limit's three points, the lifecycle's three phases.
  assert.deepEqual(byCell.get(cellKey({ role: 'agent', resource: 'orders', action: 'update' })).map(v => v.relation).sort(), ['cross-tenant', 'other-role', 'other-same-role', 'own']);
  assert.deepEqual(byCell.get(cellKey({ role: 'agent', resource: 'refunds', action: 'create' })).map(v => [v.relation, v.point]), LIMIT_POINTS.map(p => ['none', p]));
  assert.equal(byCell.get(cellKey({ role: 'agent', resource: 'tickets', action: 'close' })).length, 4 * LIFECYCLE_PHASES.length);
  assert.equal(byCell.get(cellKey({ role: 'agent', resource: 'orders', action: 'delete' })).length, 4 * 2, 'four relations times two creators');
  // A limit or a lifecycle rule beside a plain rule in one cell: only the variants the limited or lifecycle rule decides get
  // points or phases, the plain rule's get neither, and the plan builds.
  for (const extra of [{ limit: { pointer: '/note', cap: 50, unit: 'chars' } }, { lifecycle: { transition: 'suspend', subject: 'actor', after: 'deny' } }]) {
    const mixed = statementOf([rule('upd-own-x', 'agent', 'orders', 'update', 'allow', { relation: 'own', ...extra }), rule('upd-other', 'agent', 'orders', 'update', 'deny', { relation: 'other-role' }),
      rule('upd-mgr', 'manager', 'orders', 'update', 'allow'), rule('suspend-mgr', 'manager', 'users', 'suspend', 'allow')]);
    const m = writeInventory({ statement: mixed, binding: BINDING });
    checkCounts(m);
    const cell = m.variants.filter(v => v.role === 'agent' && v.resource === 'orders' && v.action === 'update');
    const dim = extra.limit ? 'point' : 'phase';
    assert.deepEqual(cell.filter(v => v[dim] !== null).map(v => v.relation), ['own', 'own', 'own'], JSON.stringify(extra));
    assert.deepEqual(cell.filter(v => v.relation === 'other-role').map(v => [v.point, v.phase, v.stated?.decision]), [[null, null, 'deny']]);
    const plan = buildWritePlan({ statement: mixed, binding: BINDING });
    assert.ok(plan.cases.some(c => c.ruleId === 'upd-other' && c.template === 'T1' && c.variant.point === null && c.variant.phase === null));
  }
  // A binding route alone adds variants for every statement role; a matrix cell alone adds its own.
  assert.ok(variant(i, { role: 'auditor', resource: 'refunds', action: 'create' }));
  assert.deepEqual(variant(i, { role: 'agent', resource: 'invoices', action: 'read' }).from, ['matrix']);
  // One tenant in the statement: no cross-tenant variant.
  const single = writeInventory({ statement: statementOf(RULES.filter(r => r.relation !== 'cross-tenant'), { tenants: ['acme'] }), binding: BINDING });
  assert.ok(!single.variants.some(v => v.relation === 'cross-tenant'));
  // Above the inventory limit generation refuses and names the dimension that multiplies it most; it never truncates.
  assert.throws(() => writeInventory({ statement: statementOf(), binding: { ...BINDING, budget: { inventoryLimit: 10 } }, matrices: [MATRIX] }), /above the inventory limit of 10; the "relation" dimension multiplies it most/);
});

test('classify: each variant gets its stated decision or exactly one reason, and every reason is reachable', () => {
  const i = inv();
  const at = (where, reason, decision) => { const v = variant(i, where); assert.ok(v, JSON.stringify(where)); assert.equal(v.reason, reason, JSON.stringify(where)); if (decision !== undefined) assert.equal(v.stated?.decision ?? null, decision, JSON.stringify(where)); return v; };
  for (const v of i.variants) assert.ok(v.reason === null ? v.stated && v.cast : CLASSIFY_ORDER.includes(v.reason), v.key);
  // Draftable, with the actors that play attacker and owner.
  assert.deepEqual(at({ role: 'agent', action: 'update', relation: 'own' }, null, 'allow').cast, { attacker: 'a1', owner: 'a1' });
  assert.deepEqual(at({ role: 'agent', action: 'update', relation: 'other-same-role' }, null, 'deny').cast, { attacker: 'a1', owner: 'a2' });
  assert.deepEqual(at({ role: 'agent', action: 'update', relation: 'other-role' }, null, 'deny').cast, { attacker: 'a1', owner: 'm1' });
  assert.deepEqual(at({ role: 'agent', action: 'update', relation: 'cross-tenant' }, null, 'deny').cast, { attacker: 'a1', owner: 'a3' });
  at({ role: 'manager', action: 'update', relation: 'cross-tenant' }, null, 'allow');
  // The limit's points: under allowed, over refused, at unstated without inclusivity.
  at({ role: 'agent', resource: 'refunds', point: 'under' }, null, 'allow');
  at({ role: 'agent', resource: 'refunds', point: 'over' }, null, 'deny');
  at({ role: 'agent', resource: 'refunds', point: 'at' }, 'not-stated', null);
  // The lifecycle's phases: before the rule's decision, after the stated one, in flight unexecuted.
  at({ role: 'agent', resource: 'tickets', relation: 'own', phase: 'before' }, null, 'allow');
  at({ role: 'agent', resource: 'tickets', relation: 'own', phase: 'after' }, null, 'deny');
  at({ role: 'agent', resource: 'tickets', relation: 'own', phase: 'in-flight' }, 'needs-hold-gate', 'allow');
  // Every reason, each on the variant built for it.
  at({ role: 'auditor', resource: 'refunds', action: 'create' }, 'not-stated', null);
  at({ role: 'manager', resource: 'invoices', action: 'read' }, 'candidate-only', null);
  at({ role: 'agent', resource: 'invoices', action: 'read' }, 'unknown-gap', null);
  at({ role: 'agent', resource: 'reports', action: 'export' }, 'no-route-bound', 'allow');
  at({ role: 'auditor', resource: 'orders', action: 'update', relation: 'own' }, 'role-not-mapped', 'deny');
  at({ role: 'manager', action: 'update', relation: 'other-same-role' }, 'needs-second-actor', 'allow');
  at({ role: 'agent', action: 'delete', creator: 'manager', relation: 'own' }, 'no-allowed-use-on-route', 'deny');
  at({ role: 'agent', resource: 'invoices', action: 'hide', relation: 'own' }, 'silent-refusal-without-observer', 'deny');
  at({ role: 'agent', action: 'delete', creator: 'agent', relation: 'own' }, 'prefix-effect-name', 'allow');
  at({ role: 'agent', action: 'archive', relation: 'own' }, 'insufficient-observation', 'allow');
  at({ role: 'agent', resource: 'invoices', action: 'void', relation: 'own' }, 'no-declared-revert', 'allow');
  // An unbound cell varies over the relations its rules name, so it reads unbound rather than unstated.
  at({ role: 'agent', resource: 'reports', action: 'share', relation: 'own' }, 'no-route-bound', 'allow');
  // A state named by a rule is a dimension of its cell.
  at({ role: 'manager', resource: 'invoices', action: 'void', relation: 'own', state: 'paid' }, 'no-declared-revert', 'deny');
  // Own means the attacker owns the object.
  assert.deepEqual(at({ role: 'manager', action: 'update', relation: 'own' }, null, 'allow').cast, { attacker: 'm1', owner: 'm1' });
  const seen = new Set(i.variants.map(v => v.reason).filter(Boolean));
  assert.deepEqual(CLASSIFY_ORDER.filter(r => !seen.has(r)), [], 'every reason is reachable');
  assert.equal(i.draftable, i.variants.filter(v => v.stated && v.reason === null).length);
});

test('R9: matrices and routes add variants, never intent; only the statement states a decision', () => {
  const plain = writeInventory({ statement: statementOf([]), binding: BINDING, matrices: [MATRIX] });
  assert.ok(plain.variants.length > 0);
  assert.ok(plain.variants.every(v => v.stated === null && ['not-stated', 'candidate-only', 'unknown-gap'].includes(v.reason)));
  const dflt = writeInventory({ statement: statementOf([], { defaults: { unlisted: 'deny' } }), binding: BINDING });
  assert.ok(dflt.variants.every(v => v.stated?.confidence === 'stated-default' && v.stated.decision === 'deny'));
  // A default deny with no allowed role on the route has no pair control: unexecuted, never a lone prohibition.
  assert.ok(dflt.variants.filter(v => v.resource === 'orders').every(v => v.reason !== null));
  assert.throws(() => writeInventory({ statement: { ...statementOf(), rules: [] }, binding: BINDING }), /sealed, unedited statement/);
  assert.throws(() => writeInventory({ statement: statementOf(), binding: { ...BINDING, application: 'other' } }), /the binding is for other, the statement for desk/);
  assert.throws(() => writeInventory({ statement: statementOf(), binding: BINDING, matrices: [{ ...MATRIX, cells: [] }] }), /edited after import/);
  // An id recomputed over an edited body is refused: a whole deny beside the whole allow it contradicts.
  const { statementId: _id, ...body } = structuredClone(statementOf());
  body.rules.push({ ...body.rules.find(r => r.ruleId === 'upd-mgr'), ruleId: 'upd-mgr-deny', decision: 'deny', relation: 'own' });
  assert.throws(() => writeInventory({ statement: { ...body, statementId: sha256(canonical(body)) }, binding: BINDING }), /overlap and disagree/);
});

test('the inventory is the same for shuffled inputs, and feeds the coverage accounting as it is', () => {
  const i = inv();
  const shuffledRules = statementOf([...RULES].reverse());
  const reordered = structuredClone(BINDING);
  reordered.routes = Object.fromEntries(Object.entries(reordered.routes).reverse().map(([k, v]) => [k, Object.fromEntries(Object.entries(v).reverse())]));
  reordered.actors = Object.fromEntries(Object.entries(reordered.actors).reverse());
  const again = writeInventory({ statement: shuffledRules, binding: reordered, matrices: [MATRIX] });
  assert.equal(inventoryDigest(again), inventoryDigest(i));
  assert.equal(again.bindingDigest, i.bindingDigest);
  assert.equal(variantKey(i.variants[0]), i.variants[0].key);
  // One accounting cell per variant, carrying its stated decision or its reason (write-plan-accounting.test.mjs runs
  // them through the coverage accounting itself).
  const invCells = inventoryCells(i);
  assert.equal(invCells.length, i.variants.length);
  assert.equal(invCells.filter(c => c.stated).length, i.variants.filter(v => v.stated).length);
  assert.equal(invCells.filter(c => c.reason === 'no-route-bound').length, i.reasons['no-route-bound']);
  assert.ok(invCells.every(c => (c.stated === null) === ['not-stated', 'candidate-only', 'unknown-gap'].includes(c.reason)));
  // An edited statement changes the digest; so does an edited binding.
  assert.notEqual(inventoryDigest(writeInventory({ statement: statementOf(RULES.slice(1)), binding: BINDING, matrices: [MATRIX] })), inventoryDigest(i));
  // A flipped decision that leaves every reason as it was still changes the digest; so does one edited by hand on the
  // inventory itself, with the statementId unchanged.
  const flipped = RULES.map(r => (r.ruleId === 'void-paid' ? { ...r, decision: 'allow' } : r));
  const flippedInv = writeInventory({ statement: statementOf(flipped), binding: BINDING, matrices: [MATRIX] });
  assert.deepEqual(flippedInv.variants.map(v => v.reason), i.variants.map(v => v.reason));
  assert.notEqual(inventoryDigest(flippedInv), inventoryDigest(i));
  const edited = structuredClone(i), ev = edited.variants.find(x => x.stated);
  ev.stated.decision = ev.stated.decision === 'allow' ? 'deny' : 'allow';
  assert.equal(edited.statementId, i.statementId);
  assert.notEqual(inventoryDigest(edited), inventoryDigest(i));
  // Each accounting cell takes its side from the stated decision.
  const cells = new Map(inventoryCells(i).map(c => [c.key, c]));
  assert.equal(cells.get(variant(i, { role: 'agent', action: 'update', relation: 'own' }).key).side, 'allowed');
  assert.equal(cells.get(variant(i, { role: 'agent', action: 'update', relation: 'cross-tenant' }).key).side, 'forbidden');
  const otherBinding = structuredClone(BINDING); otherBinding.observers.settleMs = 300;
  assert.notEqual(writeInventory({ statement: statementOf(), binding: otherBinding, matrices: [MATRIX] }).bindingDigest, i.bindingDigest);
  assert.equal(sha256(canonical(null)).length, 64);
});

test('actors: a peer shares role and tenant, another role shares the tenant, a cross-tenant owner is elsewhere', () => {
  const spread = { ...BINDING, actors: { a1: { role: 'agent', tenant: 'acme' }, a3: { role: 'agent', tenant: 'globex' }, m2: { role: 'manager', tenant: 'globex' } }, identityControls: {} };
  const i = writeInventory({ statement: statementOf(), binding: spread });
  const reason = where => variant(i, where).reason;
  assert.equal(reason({ role: 'agent', action: 'update', relation: 'other-same-role' }), 'needs-second-actor', 'the only other agent is in another tenant');
  assert.deepEqual(variant(i, { role: 'agent', action: 'update', relation: 'other-role' }).cast, { attacker: 'a3', owner: 'm2' }, 'the manager is in globex, so the globex agent attacks');
  const apart = writeInventory({ statement: statementOf(), binding: { ...spread, actors: { a1: { role: 'agent', tenant: 'acme' }, m2: { role: 'manager', tenant: 'globex' } } } });
  assert.equal(variant(apart, { role: 'agent', action: 'update', relation: 'other-role' }).reason, 'needs-second-actor', 'no manager shares the agent\'s tenant');
  assert.deepEqual(variant(apart, { role: 'agent', action: 'update', relation: 'cross-tenant' }).cast, { attacker: 'a1', owner: 'm2' });
});

test('the inventory limit names the dimension that multiplies most, whichever it is', () => {
  const states = ['s1', 's2', 's3', 's4', 's5', 's6'].map((st, n) => rule(`refund-${st}`, 'agent', 'refunds', 'create', n % 2 ? 'deny' : 'allow', { state: st }));
  const only = { ...BINDING, routes: { refunds: BINDING.routes.refunds }, effects: { refunds: BINDING.effects.refunds }, objects: {}, budget: { inventoryLimit: 3 } };
  // The dimension named is the property: read it out of the refusal and compare it.
  const named = (() => { try { writeInventory({ statement: statementOf([...states, rule('mgr-refund', 'manager', 'refunds', 'create', 'allow')]), binding: only }); } catch (e) { return /the "([a-z]+)" dimension multiplies it most/.exec(e.message)?.[1]; } return null; })();
  assert.equal(named, 'state');
  // On a create (one relation), a limit's points or a lifecycle's phases multiply most.
  const nameFor = r => { try { writeInventory({ statement: statementOf([r, rule('mgr-refund', 'manager', 'refunds', 'create', 'allow')]), binding: only }); } catch (e) { return /the "([a-z]+)" dimension multiplies it most/.exec(e.message)?.[1]; } return null; };
  assert.equal(nameFor(rule('cap', 'agent', 'refunds', 'create', 'allow', { limit: { pointer: '/amount', cap: 100, unit: 'USD' } })), 'point');
  assert.equal(nameFor(rule('life', 'agent', 'refunds', 'create', 'allow', { lifecycle: { transition: 'suspend', subject: 'actor', after: 'deny' } })), 'phase');
});

// ---- Stage 2: cases, selection, the plan ----------------------------------------------------------------------------
const planOf = (extra = {}) => buildWritePlan({ statement: statementOf(), binding: BINDING, matrices: [MATRIX], ...extra });
const principal = id => `p-${id}`;
// The multiturn scenario a case compiles to (vehicle S's shape; M3 compiles it for real): ids filled with literals.
const scenarioOf = c => ({ schema: MULTITURN_SCHEMA, id: c.caseId,
  actors: Object.fromEntries([...new Set(c.turns.map(t => t.actor))].map(id => [id, { principalId: principal(id) }])),
  turns: c.turns.map(t => ({ actor: t.actor, method: t.method, path: t.pathTemplate.replace('{{id}}', `${t.object ?? 'none'}-1`), ...(t.body ? { body: t.body } : {}), expect: t.expect })),
  assertions: c.assertions.map(a => ({ id: a.id, title: a.title, severity: a.severity, window: `turn-${a.window[0]}..turn-${a.window[1]}`,
    effect: { kind: a.kind, select: { source: a.select.source, operation: a.select.operation, name: a.select.name, actor: principal(a.select.actorRef) } }, ...(a.control ? { control: a.control } : {}) })) });

test('plan: every template drafts its shape, and every case compiles as a multiturn scenario', () => {
  const plan = planOf();
  assert.ok(verifyPlanId(plan));
  assert.deepEqual([...new Set(plan.cases.map(c => c.template))].sort(), Object.keys(TEMPLATES));
  for (const c of plan.cases) {
    assert.match(c.caseId, /^WC-[0-9A-F]{12}$/);
    assert.equal(c.confirmed, false);
    assert.equal(c.vehicle, c.template === 'T5' ? 'S' : 'P', `${c.template} vehicle`);
    const seq = compileScenario(scenarioOf(c));
    assert.equal(seq.id, c.caseId, `${c.template} ${c.caseId} compiles`);
  }
  const one = t => plan.cases.find(c => c.template === t);
  // T1: the attempt first, the owner's same-record pair, padding, the attacker's own liveness control late.
  const t1 = one('T1');
  assert.deepEqual(t1.turns.map(t => t.part).filter(p => p !== 'padding'), ['attempt', 'pair', 'liveness']);
  assert.equal(t1.turns.find(t => t.part === 'attempt').object, 'V');
  assert.equal(t1.turns.find(t => t.part === 'pair').object, 'V');
  assert.equal(t1.turns.find(t => t.part === 'liveness').object, 'W');
  // T2: a create prohibition paired with an allowed role's create on the same route.
  const t2 = one('T2');
  assert.deepEqual(t2.turns.filter(t => t.part !== 'padding').map(t => [t.part, BINDING.actors[t.actor].role]), [['attempt', 'manager'], ['pair', 'agent']]);
  assert.match(t2.residue, /reset to the seed/);
  // T3: over the cap refused, under it allowed, same actor and route.
  const t3 = plan.cases.find(c => c.template === 'T3' && c.variant.point === 'over');
  assert.deepEqual(t3.turns.filter(t => t.part !== 'padding').map(t => [t.part, t.body.amount]), [['attempt', 101], ['pair', 99]]);
  assert.equal(new Set(t3.turns.filter(t => t.part !== 'padding').map(t => t.actor)).size, 1);
  assert.deepEqual(t3.assertions.find(a => a.id === 'F').window, [1, 1], 'the prohibition window stops before the same actor\'s allowed control');
  // T4: P only; T5: S only, with the transition, the peer twin and the before-control the after-attempt pairs with.
  assert.ok(plan.cases.filter(c => c.template === 'T4').every(c => c.vehicle === 'P' && c.variant.creator !== null));
  const t5 = plan.cases.find(c => c.template === 'T5' && c.variant.phase === 'after');
  assert.deepEqual(t5.turns.filter(t => t.part !== 'padding').map(t => t.part), ['before-control', 'transition', 'attempt', 'peer-twin']);
  assert.equal(t5.turns.find(t => t.part === 'transition').pathTemplate, '/api/users/{{id}}/suspend');
  assert.equal(t5.assertions.find(a => a.id === 'F').control, 'C');
  // T6: a control-only twin for a stated allow.
  assert.ok(one('T6').assertions.every(a => a.severity === 'control' && a.kind === 'effect.exists'));
});

test('padding and order: every judged identity has three turns, a case has at most 21, and a consuming control comes last', () => {
  const plan = planOf();
  for (const c of plan.cases) {
    assert.ok(c.turns.length <= CASE_LIMITS.turns);
    for (const actor of new Set(c.assertions.map(a => a.select.actorRef))) assert.ok(c.turns.filter(t => t.actor === actor).length >= CASE_LIMITS.judgedTurns, `${c.caseId} ${actor}`);
    assert.ok(c.turns.filter(t => t.part === 'padding').every(t => t.method === 'GET' && !t.body), 'padding is GET only');
    // Forbidden attempts come before the controls they are paired with.
    const attempt = c.turns.findIndex(t => t.part === 'attempt'), pair = c.turns.findIndex(t => t.part === 'pair');
    if (attempt >= 0 && pair >= 0) assert.ok(attempt < pair);
  }
  // A DELETE consumes its object: the pair that deletes V is the last turn.
  const consuming = buildWritePlan({ statement: statementOf([...RULES, rule('del-peer', 'agent', 'orders', 'purge', 'deny', { relation: 'other-same-role' }), rule('del-own', 'agent', 'orders', 'purge', 'allow', { relation: 'own' })]),
    binding: { ...BINDING, routes: { ...BINDING.routes, orders: { ...BINDING.routes.orders, purge: route('DELETE', '/api/orders/{{id}}/purge', 'order') } }, effects: { ...BINDING.effects, orders: { ...BINDING.effects.orders, purge: effect('delete', 'orders') } } } });
  const purge = consuming.cases.find(c => c.variant.action === 'purge' && c.template === 'T1');
  assert.equal(purge.turns.at(-1).part, 'pair');
  assert.equal(purge.consumes, true);
});

test('assertions: refusals are the declared 4xx (404 only when declared), controls expect the 2xx, and every prohibition is paired with the same effect', () => {
  const plan = planOf();
  for (const c of plan.cases) {
    const route = BINDING.routes[c.variant.resource][c.variant.action];
    for (const t of c.turns.filter(x => x.part === 'attempt')) {
      assert.deepEqual(t.expect, route.refusal.kind === 'status' ? route.refusal.statuses : [route.refusal.status]);
      assert.ok(t.expect.every(x => x < 500), 'a 5xx is never a refusal');
      if (t.expect.includes(404)) assert.equal(route.refusal.notFoundIsRefusal, true);
    }
    for (const t of c.turns.filter(x => ['pair', 'control', 'liveness', 'before-control', 'peer-twin'].includes(x.part))) assert.ok(t.expect.length === 1 && t.expect[0] >= 200 && t.expect[0] < 300);
    for (const a of c.assertions) assert.ok(['effect.none', 'effect.exists'].includes(a.kind), 'effect assertions only, no json predicates');
    for (const f of c.assertions.filter(a => a.kind === 'effect.none')) {
      const ctl = c.assertions.find(a => a.id === f.control);
      assert.ok(ctl && ctl.severity === 'control' && ctl.kind === 'effect.exists', `${c.caseId} pairs ${f.id}`);
      const same = x => [x.select.source, x.select.operation, x.select.name];
      assert.deepEqual(same(ctl), same(f), 'the control selects the same effect, differing only in actor');
    }
  }
});

test('selection: base prohibitions first, round-robin by operation, cut at the budget; the rest are over-budget, never dropped', () => {
  const full = planOf();
  const ranks = full.cases.map(c => PRIORITY.indexOf(c.rank));
  assert.deepEqual(ranks, [...ranks].sort((a, b) => a - b), 'cases are in priority order');
  const baseRules = full.cases.filter(c => c.rank === 'base-prohibition').map(c => c.ruleId);
  assert.equal(new Set(baseRules).size, baseRules.length, 'one base prohibition per stated deny rule');
  const small = buildWritePlan({ statement: statementOf(), binding: { ...BINDING, budget: { maxCases: 5 } }, matrices: [MATRIX] });
  assert.equal(small.cases.length, 5);
  assert.deepEqual(small.cases.map(c => c.caseId), full.cases.slice(0, 5).map(c => c.caseId));
  assert.equal(small.variants.filter(v => v.reason === 'over-budget').length, full.cases.length - 5);
  assert.match(small.warnings[0], /over-budget: 5 of \d+ draftable cases selected/);
  // Round-robin: the allowed twins alternate across operations before repeating one.
  const twins = full.cases.filter(c => c.rank === 'allowed-twin').map(c => `${c.variant.resource} ${c.variant.action}`);
  assert.notEqual(twins[0], twins[1]);
  // Shuffled inputs give the same plan: rules, resources, actions within a resource, and actors.
  const reordered = structuredClone(BINDING);
  reordered.routes = Object.fromEntries(Object.entries(reordered.routes).reverse().map(([k, v]) => [k, Object.fromEntries(Object.entries(v).reverse())]));
  reordered.actors = Object.fromEntries(Object.entries(reordered.actors).reverse());
  assert.equal(buildWritePlan({ statement: statementOf([...RULES].reverse()), binding: reordered, matrices: [MATRIX] }).planId, full.planId);
  const actorsOnly = structuredClone(BINDING); actorsOnly.actors = Object.fromEntries(Object.entries(actorsOnly.actors).reverse());
  assert.equal(planOf({ binding: actorsOnly }).planId, full.planId, 'actor key order');
  // Two collection GETs on one resource, and two routes that perform one transition: their key order does not pick.
  const planIdOf = edit => { const b = structuredClone(BINDING); edit(b); const r = structuredClone(b); r.routes = Object.fromEntries(Object.entries(r.routes).reverse().map(([k, v]) => [k, Object.fromEntries(Object.entries(v).reverse())]));
    return [planOf({ binding: b }).planId, planOf({ binding: r }).planId]; };
  const [g1, g2] = planIdOf(b => { b.routes.refunds.search = route('GET', '/api/refunds/search', null); });
  assert.equal(g1, g2, 'padding route');
  const [t1, t2] = planIdOf(b => { b.routes.accounts = { lock: route('POST', '/api/accounts/{{id}}/lock', 'user', { transition: 'suspend' }) }; });
  assert.equal(t1, t2, 'transition route');
  // The base prohibition of a rule that covers several relations is its first by relation order (other-role first).
  const wide = buildWritePlan({ statement: statementOf([rule('upd-any', 'agent', 'orders', 'update', 'deny'), rule('upd-mgr', 'manager', 'orders', 'update', 'allow')]), binding: BINDING });
  assert.ok(wide.cases.filter(c => c.ruleId === 'upd-any').length >= 3);
  assert.deepEqual(wide.cases.filter(c => c.rank === 'base-prohibition').map(c => [c.ruleId, c.variant.relation]), [['upd-any', 'other-role']]);
});

test('sufficiency: a prohibition needs an observer that decides absence for the actor; a snapshot only for updates, with a change column or xmin', () => {
  const withEffect = e => { const b = structuredClone(BINDING); b.effects.orders.update = e; return writeInventory({ statement: statementOf(), binding: b }); };
  const reasonFor = i => variant(i, { role: 'agent', action: 'update', relation: 'other-role' }).reason;
  const twinReason = i => variant(i, { role: 'agent', action: 'update', relation: 'own' }).reason;
  assert.equal(reasonFor(withEffect({ source: 'sql-snapshot', operation: 'update', name: 'orders', actorAttributed: true })), 'insufficient-observation', 'a snapshot without exactness cannot decide an update absence');
  assert.equal(reasonFor(withEffect({ source: 'sql-snapshot', operation: 'update', name: 'orders', actorAttributed: true, exactness: 'xmin' })), null, 'Postgres xmin decides it');
  assert.equal(reasonFor(withEffect({ source: 'sql-snapshot', operation: 'update', name: 'orders', actorAttributed: true, exactness: 'change-column' })), null);
  assert.equal(reasonFor(withEffect({ source: 'otel-genai', operation: 'update', name: 'orders', actorAttributed: true })), 'insufficient-observation', 'presence-only telemetry');
  assert.equal(reasonFor(withEffect({ source: 'sql-audit-table', operation: 'update', name: 'orders', actorAttributed: false })), 'insufficient-observation', 'no actor attribution');
  assert.equal(twinReason(withEffect({ source: 'sql-snapshot', operation: 'update', name: 'orders', actorAttributed: true })), null, 'a presence (the allowed twin) needs no exactness');
  const del = structuredClone(BINDING); del.effects.orders.delete = { source: 'sql-snapshot', operation: 'delete', name: 'orders', actorAttributed: true };
  assert.equal(variant(writeInventory({ statement: statementOf(), binding: del }), { role: 'agent', action: 'delete', creator: 'manager', relation: 'own' }).reason, 'no-allowed-use-on-route');
  // A delete prohibition with an allowed role: an audit table decides it, a snapshot's delete does not.
  const delRules = statementOf([rule('del-other', 'agent', 'orders', 'delete', 'deny', { relation: 'other-role' }), rule('del-mgr', 'manager', 'orders', 'delete', 'allow')]);
  const delReason = e => { const b = structuredClone(BINDING); b.effects.orders.delete = e; return variant(writeInventory({ statement: delRules, binding: b }), { role: 'agent', action: 'delete', relation: 'other-role' }).reason; };
  assert.equal(delReason(effect('delete', 'orders')), null);
  assert.equal(delReason({ source: 'sql-snapshot', operation: 'delete', name: 'orders', actorAttributed: true }), 'insufficient-observation');
  assert.throws(() => validateWriteBinding({ ...BINDING, effects: { ...BINDING.effects, orders: { ...BINDING.effects.orders, create: { ...effect('insert', 'orders'), exactness: 'xmin' } } } }), /exactness .* applies to a sql-snapshot update only/);
  // Every case is padded with GETs: a collection with no GET route, or an object type with no precheck, has none.
  const noList = structuredClone(BINDING); delete noList.routes.refunds.list;
  const unpadded = writeInventory({ statement: statementOf(), binding: noList });
  assert.equal(variant(unpadded, { role: 'agent', resource: 'refunds', point: 'under' }).reason, 'no-route-bound');
  assert.doesNotThrow(() => buildWritePlan({ statement: statementOf(), binding: noList }));
});

test('a plan holds nothing above drafted, and its id detects edits', () => {
  const plan = planOf();
  const inventory = writeInventory({ statement: statementOf(), binding: BINDING, matrices: [MATRIX] });
  const { cells, cases } = planAccounting(plan, inventory);
  // Every case is drafted and unconfirmed, with no artifact or context bound yet, and no run anywhere in the plan.
  assert.equal(cases.length, plan.cases.length);
  assert.ok(cases.every(c => c.confirmed === false && c.artifactDigest === null && c.contextId === null));
  assert.ok(plan.cases.every(c => c.confirmed === false));
  assert.ok(!['runs', 'setup', 'values'].some(k => Object.hasOwn(plan, k)));
  const keys = new Set(cells.map(c => c.key));
  assert.ok(cases.every(c => keys.has(c.key) && !cells.find(x => x.key === c.key).reason), 'a drafted case\'s cell carries no reason');
  const edited = structuredClone(plan); edited.cases[0].turns[0].expect = [500];
  assert.equal(verifyPlanId(edited), false);
  assert.equal(verifyPlanId({ ...plan, planId: '0'.repeat(64) }), false);
});

test('plan edges: T5 needs a peer and a transition route; distinct objects keep a window open; ids follow their rule; reasons and residue reach the output', () => {
  const plan = planOf();
  // A lifecycle case needs another actor of the same role (the peer twin) and a route that performs the transition.
  const lonely = buildWritePlan({ statement: statementOf(), binding: { ...BINDING, actors: { a1: BINDING.actors.a1, m1: BINDING.actors.m1 }, identityControls: {} }, matrices: [MATRIX] });
  assert.ok(lonely.variants.filter(v => v.key.includes('"tickets","close"') && v.key.includes('"after"') && v.key.includes('"own"')).every(v => v.reason === 'needs-second-actor'));
  const noTransition = structuredClone(BINDING); delete noTransition.routes.users;
  assert.ok(buildWritePlan({ statement: statementOf(), binding: noTransition, matrices: [MATRIX] }).variants.filter(v => v.key.includes('"close"') && v.key.includes('"after"') && v.reason !== 'needs-second-actor').every(v => v.reason === 'no-route-bound'));
  // With an object resource on the effect, the attacker's liveness control on W cannot match the prohibition on V, so the window stays open.
  const named = structuredClone(BINDING); named.effects.orders.update = { ...named.effects.orders.update, resourceTemplate: 'orders/{{id}}' };
  const t1 = buildWritePlan({ statement: statementOf(), binding: named, matrices: [MATRIX] }).cases.find(c => c.template === 'T1' && c.assertions.some(a => a.id === 'L'));
  assert.equal(t1.assertions.find(a => a.id === 'F').window[1], t1.turns.length);
  assert.equal(plan.cases.find(c => c.caseId === plan.cases.find(x => x.template === 'T1' && x.assertions.some(a => a.id === 'L'))?.caseId).assertions.find(a => a.id === 'F').window[1] < plan.cases.find(x => x.template === 'T1' && x.assertions.some(a => a.id === 'L')).turns.length, true, 'without it, the window stops before the liveness turn');
  // A case id follows its rule: the same variant under an edited rule is another case.
  const relocated = statementOf(RULES.map(r => (r.ruleId === 'upd-cross' ? { ...r, source: { sourceId: 'policy', locator: 'moved' } } : r)));
  const before = plan.cases.find(c => c.ruleId === 'upd-cross'), after = buildWritePlan({ statement: relocated, binding: BINDING, matrices: [MATRIX] }).cases.find(c => c.ruleId === 'upd-cross');
  assert.notEqual(after.caseId, before.caseId);
  // Every stated deny rule with a draftable object or collection prohibition has its base prohibition.
  const denyRules = new Set(plan.cases.filter(c => ['T1', 'T2'].includes(c.template)).map(c => c.ruleId));
  assert.deepEqual(new Set(plan.cases.filter(c => c.rank === 'base-prohibition').map(c => c.ruleId)), denyRules);
  assert.ok(denyRules.size >= 2);
  // A create prohibition warns about residue; the plan's own reasons reach the accounting.
  assert.ok(plan.warnings.some(w => /reset to the seed/.test(w)));
  const small = buildWritePlan({ statement: statementOf(), binding: { ...BINDING, budget: { maxCases: 5 } }, matrices: [MATRIX] });
  const smallCells = planAccounting(small, writeInventory({ statement: statementOf(), binding: { ...BINDING, budget: { maxCases: 5 } }, matrices: [MATRIX] })).cells;
  assert.equal(smallCells.filter(c => c.reason === 'over-budget').length, small.variants.filter(v => v.reason === 'over-budget').length);
  assert.ok(smallCells.filter(c => c.reason === 'over-budget').length > 0);
  // Padding on an object route acts on an object its own actor owns.
  for (const c of plan.cases) for (const t of c.turns.filter(x => x.part === 'padding' && x.object))
    assert.equal(c.objects.find(o => o.ref === t.object)?.owner, t.actor, `${c.caseId} pads ${t.actor} on ${t.object}`);
});

test('pairs: a prohibition pairs with an actor the statement allows on that object, and without one it is not drafted; twins act where they are allowed', () => {
  const mini = (rules, actors) => buildWritePlan({ statement: statementOf(rules, { roles: ['agent', 'manager', 'admin'] }),
    binding: { ...BINDING, actors, identityControls: {}, routes: { orders: BINDING.routes.orders }, effects: { orders: { update: BINDING.effects.orders.update } }, objects: { order: BINDING.objects.order } } });
  const rules = [rule('a-other', 'agent', 'orders', 'update', 'deny', { relation: 'other-role' }), rule('a-own', 'agent', 'orders', 'update', 'allow', { relation: 'own' }),
    rule('m-own', 'manager', 'orders', 'update', 'deny', { relation: 'own' })];
  const two = { a1: { role: 'agent', tenant: 'acme' }, m1: { role: 'manager', tenant: 'acme' } };
  // The owner (a manager) may not update its own order and nobody else may: no pair, so the prohibition is not drafted.
  const unpaired = mini(rules, two);
  assert.equal(unpaired.variants.find(v => v.key === JSON.stringify(['agent', 'orders', 'update', 'other-role', null, null, null, null])).reason, 'no-allowed-use-on-route');
  // An admin the statement allows pairs instead: never the owner the statement refuses.
  const paired = mini([...rules, rule('admin-any', 'admin', 'orders', 'update', 'allow')], { ...two, ad1: { role: 'admin', tenant: 'acme' } });
  const c = paired.cases.find(x => x.ruleId === 'a-other');
  assert.equal(c.turns.find(t => t.part === 'pair').actor, 'ad1');
  // The classifier asks the same question as the case: an admin allowed only on other roles' orders pairs with a peer
  // prohibition, so it is drafted.
  const otherOnly = mini([rule('a-peer', 'agent', 'orders', 'update', 'deny', { relation: 'other-same-role' }), rule('ad-other', 'admin', 'orders', 'update', 'allow', { relation: 'other-role' })],
    { a1: { role: 'agent', tenant: 'acme' }, a2: { role: 'agent', tenant: 'acme' }, ad1: { role: 'admin', tenant: 'acme' } });
  const peerCase = otherOnly.cases.find(x => x.ruleId === 'a-peer');
  assert.equal(peerCase?.turns.find(t => t.part === 'pair').actor, 'ad1');
  // A twin for an allowed relation other than own acts on the other actor's object.
  const twin = planOf().cases.find(x => x.template === 'T6' && x.variant.relation === 'other-role');
  const acted = twin.turns.find(t => t.part === 'control');
  assert.equal(acted.object, 'V');
  assert.notEqual(twin.objects.find(o => o.ref === 'V').owner, acted.actor);
  // On an object route every padding turn names an object.
  for (const k of planOf().cases) if (BINDING.routes[k.variant.resource][k.variant.action].object !== null) assert.ok(k.turns.filter(t => t.part === 'padding').every(t => t.object), k.caseId);
});

test('values (scopehaven-policy-values/1): plain ids per case object, a digest that detects edits, and what a plan still needs', () => {
  const plan = planOf();
  const needed = valuesNeeded(plan);
  assert.equal(needed.length, plan.cases.reduce((n, c) => n + c.objects.length, 0));
  const records = Object.fromEntries(needed.slice(1).map((n, i) => [n.key, { id: `obj-${i}` }]));
  const v = validateValues({ schema: VALUES_SCHEMA, contextId: 'ctx-1', producer: 'operator-seed', records });
  assert.match(v.valuesDigest, /^[a-f0-9]{64}$/);
  assert.equal(validateValues({ ...v }).valuesDigest, v.valuesDigest);
  assert.deepEqual(missingValues(plan, v).map(n => n.key), [needed[0].key], 'setup is not ready for the case whose object has no id');
  const refuse = (edit, pattern) => assert.throws(() => validateValues({ schema: VALUES_SCHEMA, contextId: 'ctx-1', producer: 'operator-seed', records, ...edit }), pattern);
  refuse({ valuesDigest: '0'.repeat(64) }, /edited after it was computed/);
  refuse({ producer: 'capture' }, /reserved for core captures/);
  refuse({ producer: 'guess' }, /values.producer is/);
  refuse({ contextId: '' }, /contextId/);
  refuse({ records: { [needed[0].key]: { id: '../admin' } } }, /plain identifier value/);
  refuse({ records: { [needed[0].key]: { id: '..' } } }, /plain identifier value/);
  refuse({ records: { [needed[0].key]: { owner: 'x' } } }, /known placeholder/);
  refuse({ records: { 'not-a-case/V': { id: 'x' } } }, /under a case object key/);
  refuse({ extra: 1 }, /unknown field extra/);
});

// Kept apart so each guard runs even when an earlier refusal in the binding test fails first.
test('write binding: each route guard refuses its own input, which no neighbouring check covers', () => {
  const refuse = (edit, pattern) => { const x = structuredClone(BINDING); edit(x); assert.throws(() => validateWriteBinding(x), pattern); };
  // A route nothing else refers to (orders.read is the order's precheck, whose own guard also refuses a HEAD).
  refuse(x => { x.routes.orders.peek = route('HEAD', '/api/orders/{{id}}/peek', 'order'); }, /method is GET, POST, PUT, PATCH, DELETE/);
  refuse(x => { x.routes.orders.read.pathTemplate = '/api/orders/{{id}}/{{oid}}'; }, /unknown placeholder \{\{oid\}\}/);
  refuse(x => { x.routes.orders.read.pathTemplate = '/api/orders/{{id}}/a b'; }, /a path segment is literal text or one whole \{\{placeholder\}\}/);
  // An effect is what its route does: a GET reads, a consuming route never updates, a create neither updates nor deletes.
  const snapshotUpdate = { source: 'sql-snapshot', operation: 'update', name: 'orders', actorAttributed: true, exactness: 'xmin' };
  refuse(x => { x.effects.orders.read = snapshotUpdate; }, /a GET route binds a read effect only/);
  refuse(x => { x.effects.orders.delete = snapshotUpdate; }, /a route that consumes its object cannot bind an update/);
  refuse(x => { x.effects.orders.create = snapshotUpdate; }, /a create on a collection cannot bind an update or a delete/);
  refuse(x => { x.effects.orders.create = effect('delete', 'orders'); }, /a create on a collection cannot bind an update or a delete/);
  assert.doesNotThrow(() => validateWriteBinding({ ...BINDING, effects: { ...BINDING.effects, orders: { ...BINDING.effects.orders, read: { source: 'http-audit-log', operation: 'read', name: 'orders', actorAttributed: true } } } }));
});

test('T5: the peer twin is an actor the transition leaves alone, by its subject; a consuming route uses two objects and pads on a third', () => {
  const SUSPEND = [rule('suspend-mgr', 'manager', 'users', 'suspend', 'allow'), rule('suspend-agent', 'agent', 'users', 'suspend', 'allow')];
  const lifecycleRules = subject => [rule('close', 'agent', 'tickets', 'close', 'allow', { lifecycle: { transition: 'suspend', subject, after: 'deny' } }), rule('close-mgr', 'manager', 'tickets', 'close', 'allow'), ...SUSPEND];
  const peerOf = subject => {
    const p = buildWritePlan({ statement: statementOf(lifecycleRules(subject)), binding: BINDING });
    const c = p.cases.find(x => x.template === 'T5' && x.variant.phase === 'after' && x.variant.relation === 'own');
    return BINDING.actors[c.turns.find(t => t.part === 'peer-twin').actor];
  };
  // The actor is the subject: another agent, here in the attacker's own tenant.
  assert.deepEqual(peerOf('actor'), { role: 'agent', tenant: 'acme' });
  // The tenant is the subject: an agent in another tenant.
  assert.deepEqual(peerOf('tenant'), { role: 'agent', tenant: 'globex' });
  // The role is the subject: every agent is affected, so the twin is a manager the statement allows.
  assert.equal(peerOf('role').role, 'manager');
  // No unaffected actor the statement allows: not drafted.
  const noPeer = buildWritePlan({ statement: statementOf([lifecycleRules('role')[0]]), binding: BINDING });
  assert.ok(noPeer.variants.filter(v => v.key.includes('"close"') && v.key.includes('"after"') && v.key.includes('"own"')).every(v => v.reason === 'needs-second-actor'));
  // A consuming route: the before-control and the after-attempt act on different objects, and padding never reads a consumed one.
  const del = structuredClone(BINDING);
  del.routes.tickets.shred = route('DELETE', '/api/tickets/{{id}}/shred', 'ticket'); del.effects.tickets.shred = effect('delete', 'tickets');
  const shred = buildWritePlan({ statement: statementOf([rule('shred', 'agent', 'tickets', 'shred', 'allow', { lifecycle: { transition: 'suspend', subject: 'actor', after: 'deny' } }), ...SUSPEND]), binding: del });
  const c = shred.cases.find(x => x.template === 'T5' && x.variant.phase === 'after' && x.variant.relation === 'own');
  const before = c.turns.find(t => t.part === 'before-control').object, attempt = c.turns.find(t => t.part === 'attempt').object;
  assert.notEqual(before, attempt);
  const consumed = new Set(c.turns.filter(t => t.method === 'DELETE').map(t => t.object));
  assert.ok(c.turns.filter(t => t.part === 'padding').every(t => !consumed.has(t.object)), 'padding reads only objects no turn deletes');
  assert.ok(c.objects.every(o => o.subject || c.turns.some(t => t.object === o.ref)), 'no object is created that no turn uses');
  assert.equal(compileScenario(scenarioOf(c)).id, c.caseId);
});

test('T5 performers and phases: the transition is performed by an actor the statement allows, never the attacker or the peer; each phase follows its stated decision', () => {
  const caseOf = (p, phase) => p.cases.find(x => x.template === 'T5' && x.variant.phase === phase && x.variant.relation === 'own');
  const performerOf = c => c.turns.find(t => t.part === 'transition').actor;
  // Only an auditor may suspend, and none is bound: no performer, so neither phase that needs the transition is drafted.
  const close = [rule('close', 'agent', 'tickets', 'close', 'allow', { lifecycle: { transition: 'suspend', subject: 'actor', after: 'deny' } }), rule('close-mgr', 'manager', 'tickets', 'close', 'allow')];
  const noPerformer = buildWritePlan({ statement: statementOf([...close, rule('susp-mgr', 'manager', 'users', 'suspend', 'deny'), rule('susp-aud', 'auditor', 'users', 'suspend', 'allow')]), binding: BINDING });
  assert.equal(noPerformer.variants.find(v => v.key === JSON.stringify(['agent', 'tickets', 'close', 'own', null, null, null, 'after'])).reason, 'needs-second-actor');
  // The only allowed performer is the peer: not drafted either.
  const two = { ...BINDING, actors: { a1: BINDING.actors.a1, a2: BINDING.actors.a2 }, identityControls: {} };
  const peerOnly = buildWritePlan({ statement: statementOf([...close, rule('susp-agent', 'agent', 'users', 'suspend', 'allow')]), binding: two });
  assert.equal(peerOnly.variants.find(v => v.key === JSON.stringify(['agent', 'tickets', 'close', 'own', null, null, null, 'after'])).reason, 'needs-second-actor');
  // An allowed performer that is neither: drafted with it.
  const allowedFirst = buildWritePlan({ statement: statementOf([...close, rule('suspend-mgr', 'manager', 'users', 'suspend', 'allow')]), binding: BINDING });
  const after = caseOf(allowedFirst, 'after');
  assert.equal(performerOf(after), 'm1');
  assert.ok(![after.turns.find(t => t.part === 'attempt').actor, after.turns.find(t => t.part === 'peer-twin').actor].includes('m1'));
  // The performer's relation to the subject counts: a manager may suspend another role's user in its tenant but not
  // across tenants, so the globex manager (first by id) is passed over for the acme one.
  const spread = { ...BINDING, actors: { a1: BINDING.actors.a1, a2: BINDING.actors.a2, m0: { role: 'manager', tenant: 'globex' }, m1: BINDING.actors.m1 }, identityControls: {} };
  const relational = buildWritePlan({ statement: statementOf([...close, rule('susp-same', 'manager', 'users', 'suspend', 'allow', { relation: 'other-role' }), rule('susp-cross', 'manager', 'users', 'suspend', 'deny', { relation: 'cross-tenant' })]), binding: spread });
  const rc = caseOf(relational, 'after');
  assert.ok(rc, 'drafted, with the acme manager performing');
  assert.equal(performerOf(rc), 'm1');
  // Refused before the transition and allowed after it: the before phase is the prohibition (attempt, transition, the same
  // actor's control after it), and the after phase is a control after the transition.
  const denyFirst = buildWritePlan({ statement: statementOf([rule('close-approved', 'agent', 'tickets', 'close', 'deny', { relation: 'own', lifecycle: { transition: 'suspend', subject: 'actor', after: 'allow' } }),
    rule('close-mgr', 'manager', 'tickets', 'close', 'allow'), rule('suspend-mgr', 'manager', 'users', 'suspend', 'allow')]), binding: BINDING });
  const b = caseOf(denyFirst, 'before'), a = caseOf(denyFirst, 'after');
  assert.equal(b.decision, 'deny');
  assert.deepEqual(b.turns.filter(t => t.part !== 'padding').map(t => [t.part, t.actor, t.expect]), [['attempt', 'a1', [403, 409]], ['transition', 'm1', [200]], ['control', 'a1', [200]]]);
  const F = b.assertions.find(x => x.kind === 'effect.none'), C = b.assertions.find(x => x.id === F.control);
  assert.deepEqual([F.actor, C.actor, C.kind], ['a1', 'a1', 'effect.exists']);
  assert.ok(F.window[1] < b.turns.findIndex(t => t.part === 'control') + 1, 'the prohibition window ends before the allowed control');
  assert.equal(a.decision, 'allow');
  assert.deepEqual(a.turns.filter(t => t.part !== 'padding').map(t => t.part), ['transition', 'control']);
  assert.ok(a.assertions.every(x => x.kind === 'effect.exists'));
  // The other relations of the cell have no lifecycle rule: one variant each, with no phase.
  assert.ok(denyFirst.variants.filter(v => v.key.startsWith(JSON.stringify(['agent', 'tickets', 'close']).slice(0, -1)) && !v.key.includes('"own"')).every(v => v.key.endsWith(',null]')));
  for (const c of [b, a, after]) assert.equal(compileScenario(scenarioOf(c)).id, c.caseId);
});

test('objects: a T1 own-object prohibition names no W; a state-conditioned case marks the objects it acts on; no turn reads an object after a control deletes it', () => {
  const own = buildWritePlan({ statement: statementOf([rule('del-own', 'agent', 'orders', 'update', 'deny', { relation: 'own' }), rule('upd-mgr', 'manager', 'orders', 'update', 'allow')]), binding: BINDING });
  const c = own.cases.find(x => x.template === 'T1' && x.variant.relation === 'own');
  assert.ok(c.objects.every(o => o.subject || c.turns.some(t => t.object === o.ref)), 'every object is used by a turn');
  assert.ok(!c.objects.some(o => o.ref === 'W'));
  const shipped = buildWritePlan({ statement: statementOf([rule('upd-own', 'agent', 'orders', 'update', 'allow', { relation: 'own' }), rule('upd-peer-shipped', 'agent', 'orders', 'update', 'deny', { relation: 'other-same-role', state: 'shipped' }),
    rule('upd-mgr', 'manager', 'orders', 'update', 'allow')]), binding: BINDING });
  const s = shipped.cases.find(x => x.ruleId === 'upd-peer-shipped');
  assert.deepEqual(s.objects.map(o => [o.ref, o.state ?? null]), [['V', 'shipped'], ['W', null]]);
  assert.deepEqual(valuesNeeded(shipped).filter(n => n.key.startsWith(s.caseId)).map(n => n.state ?? null), ['shipped', null]);
  // A consuming lifecycle case on another role's objects acts on two of them and creates no third; with a state, the
  // before-control, attempt and peer-twin objects all carry it.
  const del = structuredClone(BINDING); del.routes.tickets.shred = route('DELETE', '/api/tickets/{{id}}/shred', 'ticket'); del.effects.tickets.shred = effect('delete', 'tickets');
  const life = { lifecycle: { transition: 'suspend', subject: 'actor', after: 'deny' } };
  const shredOther = buildWritePlan({ statement: statementOf([rule('shred-other', 'agent', 'tickets', 'shred', 'allow', { relation: 'other-role', state: 'open', ...life }), rule('shred-own', 'agent', 'tickets', 'shred', 'allow', { relation: 'own' }),
    rule('shred-mgr', 'manager', 'tickets', 'shred', 'allow'), rule('suspend-agent', 'agent', 'users', 'suspend', 'allow')]), binding: del });
  const so = shredOther.cases.find(x => x.template === 'T5' && x.variant.phase === 'after' && x.variant.relation === 'other-role');
  assert.ok(so.objects.every(o => o.subject || so.turns.some(t => t.object === o.ref)), `${so.caseId}: every object is used`);
  const stateOf = part => so.objects.find(o => o.ref === so.turns.find(t => t.part === part).object).state;
  assert.deepEqual(['before-control', 'attempt', 'peer-twin'].map(stateOf), ['open', 'open', 'open']);
  for (const k of [...planOf().cases, ...shipped.cases, ...shredOther.cases]) {
    k.turns.forEach((t, i) => { if (t.method === 'DELETE' && t.part !== 'attempt') assert.ok(!k.turns.slice(i + 1).some(x => x.object === t.object), `${k.caseId} reads ${t.object} after deleting it`); });
  }
});

test('padding: a read the statement refuses the actor, or ties to a lifecycle, is never padding; the collection GET is used instead, or the case is not drafted', () => {
  const reads = structuredClone(BINDING); reads.routes.orders.list = route('GET', '/api/orders', null);
  reads.effects.orders.read = { source: 'http-audit-log', operation: 'read', name: 'orders', actorAttributed: true };
  const rules = [rule('read-until', 'agent', 'orders', 'read', 'allow', { relation: 'own', lifecycle: { transition: 'suspend', subject: 'actor', after: 'deny' } }), rule('read-mgr', 'manager', 'orders', 'read', 'allow'),
    rule('suspend-mgr', 'manager', 'users', 'suspend', 'allow')];
  const c = buildWritePlan({ statement: statementOf(rules), binding: reads }).cases.find(x => x.template === 'T5' && x.variant.phase === 'after');
  const agentPads = c.turns.filter(t => t.part === 'padding' && BINDING.actors[t.actor].role === 'agent');
  assert.ok(agentPads.length > 0);
  assert.ok(agentPads.every(t => t.action === 'list' && !t.object), 'agents pad with the collection GET, not the read a lifecycle changes');
  // Without a collection GET there is nothing the agents may pad with: not drafted.
  const noList = structuredClone(reads); delete noList.routes.orders.list;
  assert.equal(buildWritePlan({ statement: statementOf(rules), binding: noList }).variants.find(v => v.key === c.key).reason, 'no-route-bound');
  // A stated refusal of the read rules it out as padding too.
  const refused = buildWritePlan({ statement: statementOf([...RULES, rule('read-agent', 'agent', 'orders', 'read', 'deny')]), binding: reads });
  const refusedPads = refused.cases.flatMap(k => k.turns).filter(t => t.part === 'padding' && BINDING.actors[t.actor].role === 'agent' && t.resource === 'orders');
  assert.ok(refusedPads.length > 0 && refusedPads.every(t => t.action === 'list'));
});

test('reads: a read prohibition needs an observer that records reads, and its window stops before the attacker\'s own reads of the same effect', () => {
  const readRules = [...RULES, rule('read-other', 'agent', 'orders', 'read', 'deny', { relation: 'other-role' }), rule('read-own', 'agent', 'orders', 'read', 'allow', { relation: 'own' }),
    rule('read-mgr', 'manager', 'orders', 'read', 'allow')];
  // No observer for reads: not drafted, never a crash.
  const unobserved = buildWritePlan({ statement: statementOf(readRules), binding: BINDING });
  assert.equal(unobserved.variants.find(v => v.key === JSON.stringify(['agent', 'orders', 'read', 'other-role', null, null, null, null])).reason, 'insufficient-observation');
  // An audit log that records reads by principal: the read prohibition is drafted, and the attacker's own reads (its
  // liveness read and padding on W, the same effect) fall outside its window.
  const reads = structuredClone(BINDING); reads.effects.orders.read = { source: 'http-audit-log', operation: 'read', name: 'orders', actorAttributed: true };
  const plan = buildWritePlan({ statement: statementOf(readRules), binding: reads });
  const c = plan.cases.find(x => x.ruleId === 'read-other');
  const F = c.assertions.find(a => a.id === 'F');
  const attackerLater = c.turns.map((t, i) => ({ t, at: i + 1 })).filter(({ t, at }) => at > F.window[0] && t.actor === F.actor);
  assert.ok(attackerLater.length > 0);
  assert.ok(attackerLater.every(({ at }) => at > F.window[1]), 'every later attacker read is outside the prohibition window');
  assert.equal(compileScenario(scenarioOf(c)).id, c.caseId);
  // A later attacker turn on another effect does not cut the window: in the update case, the attacker's padding reads
  // (no effect bound to reads here) stay inside it, and only its liveness update, the same effect, ends it.
  const t1 = planOf().cases.find(x => x.template === 'T1' && x.assertions.some(a => a.id === 'L'));
  assert.equal(t1.assertions.find(a => a.id === 'F').window[1], t1.turns.findIndex(t => t.part === 'liveness'));
  // With an object resource on the effect, reads of W cannot match the prohibition on V: the window stays open to the end.
  const named = structuredClone(reads); named.effects.orders.read.resourceTemplate = 'orders/{{id}}';
  const open = buildWritePlan({ statement: statementOf(readRules), binding: named }).cases.find(x => x.ruleId === 'read-other');
  assert.equal(open.assertions.find(a => a.id === 'F').window[1], open.turns.length);
  // A read log that does not record the principal cannot decide an actor's read absence.
  const anon = structuredClone(reads); anon.effects.orders.read.actorAttributed = false;
  assert.equal(buildWritePlan({ statement: statementOf(readRules), binding: anon }).variants.find(v => v.key === JSON.stringify(['agent', 'orders', 'read', 'other-role', null, null, null, null])).reason, 'insufficient-observation');
});


test('a scopehaven-policy-matrix/1 matrix (no gap identities) is still read, and gives the same cases; an edited one is refused', () => {
  const { matrixId: _id, ...body } = MATRIX;
  const legacy = { ...body, schema: 'scopehaven-policy-matrix/1' }, old = { ...legacy, matrixId: sha256(canonical(legacy)) };
  const plan = planOf({ matrices: [old] }), now = planOf();
  assert.deepEqual(plan.matrixIds, [old.matrixId]);
  assert.ok(now.cases.length > 0);
  assert.deepEqual(plan.cases, now.cases);
  assert.throws(() => planOf({ matrices: [{ ...old, application: 'other' }] }), /missing or was edited/);
  assert.throws(() => planOf({ matrices: [{ ...legacy, schema: 'scopehaven-policy-matrix/0', matrixId: sha256(canonical({ ...legacy, schema: 'scopehaven-policy-matrix/0' })) }] }), /missing or was edited/);
});
