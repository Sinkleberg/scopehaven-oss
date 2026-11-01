// Known-negative self-test: does every check in a profile prove that it can fail?
//
// A check that cannot fail is broken (trap T7: a broken or self-graded check reads pass on a vulnerable build). This
// mode plants violations through the evaluators a run itself uses, before any target is contacted:
//   fixed twin      one synthetic observation built to satisfy the predicate;
//   defective twin  per predicate, the fixed twin with exactly that predicate violated.
// Response predicates are judged by evaluateHttpCheck (src/contracts.mjs) on one complete JSON observation that satisfies
// every predicate it can. Core effect clauses are judged by decideEffects (src/http-effects.mjs) over one window per declared
// observer, as a run collects them: each window is built from what that observer can record (its source, its declared names
// and the operation each name is recorded with, the actors, resources and trace ids it records), with its evidence level (an
// egress recorder or SMTP sink without routing, a provider feed without a witnessed endpoint, and telemetry are
// presence-only), its best coverage (a snapshot is net-only) and its declared settle (applySettle), and is checked by
// validateWindow as collectWindow checks it; custody, then attribution, then the pairing stage apply in a run's order.
// Attribution (src/http-attribution.mjs attributionFindings and applyAttribution) runs exactly when a run runs it: the profile
// declares background sources ("attribution") or withholds late fails ("timing": { "lateFails": "withhold" }). It reads one
// row per check a run gives an effect window (declares effects or claims, and is not declared not applicable), in profile
// order: the planted clause in its own row, every declared observer's window empty in the others (which still carry their
// selectors, so an earlier check's selector explains a planted send as the late rules read it), and no gap or barrier event,
// with no correlation tokens (no returned-id seed). A plant attribution moves off fail therefore reads cannot-fail, and a fixed
// twin it withholds pass-unreachable, each with its reason (background-unattributed, background-unobserved,
// late-unattributed). Pairing is taken at its best (every declared twin and guard matched). The planted effect goes to the
// first declared observer that can record it (authoritative ones first, then profile order); when none can, the clause is
// unprovable and says why. It carries what that observer records on a real event, since attribution reads both: the pinned
// actor, or each principal the observer declares (an observer that names no principal records none), and the pinned
// resource, or each one the observer can record (an egress recorder's "METHOD <declared path>" and "METHOD *", a mail
// observer's addresses and "*"). Where attribution runs, each plant that differs in which background source or earlier
// selector it fits is judged, and the clause reads the best of them: proven when one plant is, cannot-fail only when every
// plant is absorbed. An observer that names principals or free-text resources the profile does not give plants none; a
// plant absorbed only through a rule that pins that missing value reads unprovable (actor-not-declared,
// resource-not-declared), never broken. A canary value is judged by canaryVerdict (src/canary.mjs), one planted form per
// channel it reports (CANARY_CHANNELS).
// Not modelled: judged late effects and the other settlement findings, and later outcomes, which touch a pass only, and app-log
// admissions, which only add a fail. Each can stop a pass this mode shows as reachable (withheld, or an admitted fail), never a
// fail, so a clause they would hold reads proven where a run does not pass it. The run-end follow rule and in-doubt re-decision read only late or in-doubt sends, and a
// plant is a committed send inside its window, so neither reaches it.
//
// A predicate is
//   proven            its fixed twin reads pass, and its defective twin reads fail on that predicate's own row for the planted
//                     reason: the planted effects are the ones it matched, the planted channel is the one that caught it;
//   cannot-fail       the plant reached the evaluator and the defective twin does not read fail (json.exists true at the root,
//                     json.noForeignValues with no other tenant's identifier, effect.exists on presence-only evidence, an
//                     effect fail attribution does not charge to the check: background-unattributed, background-unobserved,
//                     late-unattributed; an absence or count the evaluator never decides: name-not-exact, count-observers);
//   always-fails      its fixed twin reads fail too, so its fails mean nothing (contradictory predicates);
//   pass-unreachable  it can fail, but its fixed twin reads neither pass nor fail, so a repair can never be confirmed
//                     (custody, an attribution reason, a pairing reason, a name not given exactly, more than one counting
//                     observer, presence-only evidence, no declared settle, net-only coverage), with the reason;
//   unprovable        nothing the run could record was planted (no-observer, name-not-declared, operation-not-recorded,
//                     actor-not-recorded, resource-not-recorded, trace-not-recorded, plant-not-matched), a kind or form this
//                     mode does not plant (kind-not-planted, effect.only, countBy, body-fields, upstream, claim-rule,
//                     exact-coverage-not-planted; for a canary, no-plant), the profile gives no value attribution reads
//                     (actor-not-declared, resource-not-declared), or the plant was caught for another reason
//                     (failed-for-another-reason; for a canary, caught-on-another-channel); always named, never proven;
//   error             an evaluator threw (reason exception): neither proven nor broken.
// A check is broken when any predicate cannot fail or always fails, error when any predicate errored, proven when every
// predicate is proven, partial when some predicate can fail (proven or pass-unreachable) and the rest are not proven, and
// unprovable otherwise (no predicate, or none shown to fail). The target outcome ranks its checks the same way.
//
// Pure: no I/O, no clock, no randomness. The report names checks, positions, kinds, statuses and reason codes only, never an
// expected value, a planted value, a declared name or a canary.
import { Buffer } from 'node:buffer';
import { evaluateHttpCheck } from './contracts.mjs';
import { decideEffects, applySettle, settleDeclared, observerInstanceId, OBSERVER_OUTPUT } from './http-effects.mjs';
import { roleOfSeverity, decidingWindows } from './custody.mjs';
import { selectorPairs, allowedUseGuards, applyPairing, needsPairing, absenceClause } from './http-pairing.mjs';
import { attributionFindings, applyAttribution, fitsWide } from './http-attribution.mjs';
import { selectorsOf } from './http-settlement.mjs';
import { withoutUpstream } from './effect-outcome.mjs';
import { LATE_FAILS } from './http-timing.mjs';
import { makeEffect, matches, validateWindow, windowSees } from './effect-events.mjs';
import { validateEgressConfig } from './egress-rules.mjs';
import { validateSmtpConfig } from './smtp-rules.mjs';
import { validateProviderFeedConfig, providerFeedRecord } from './provider-feed-rules.mjs';
import { validateAuditFileConfig } from './audit-file-rules.mjs';
import { FOREIGN_VALUES_KIND, compileTenantValues, matcherFor, numberSourceReviver } from './tenant-values.mjs';
import { canaryVerdict, canaryValueReason } from './canary.mjs';

export const KNOWN_NEGATIVE_SCHEMA = 'scopehaven-known-negative/1';
export const PREDICATE_OUTCOMES = Object.freeze(['proven', 'cannot-fail', 'always-fails', 'pass-unreachable', 'unprovable', 'error']);
export const CHECK_OUTCOMES = Object.freeze(['proven', 'broken', 'partial', 'unprovable', 'error']);
// The kinds this mode plants. Any other kind reads unprovable (kind-not-planted), so a kind added later is never proven by
// accident; test/known-negative.test.mjs holds these lists against the validator's.
export const PLANTED_KINDS = Object.freeze({
  response: Object.freeze(['status.equals', 'status.in', 'json.equals', 'json.exists', 'json.notContains', FOREIGN_VALUES_KIND]),
  effect: Object.freeze(['effect.none', 'effect.exists', 'effect.count']),
});
const PLANTED = 'known-negative';
const UNSAFE = ['__proto__', 'prototype', 'constructor'];
const plainObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);

// JSON Pointer writes into a synthetic body. Intermediate nodes are objects ("/items/0" reads key "0" the same way).
const tokensOf = pointer => {
  const tokens = pointer === '' ? [] : pointer.slice(1).split('/').map(t => t.replaceAll('~1', '/').replaceAll('~0', '~'));
  if (tokens.some(t => UNSAFE.includes(t))) throw new Error('known-negative: unsafe JSON pointer');
  return tokens;
};
function put(root, pointer, value) {
  const tokens = tokensOf(pointer);
  if (!tokens.length) return value;
  const top = plainObject(root) ? root : {};
  let node = top;
  for (const token of tokens.slice(0, -1)) { if (!plainObject(node[token])) node[token] = {}; node = node[token]; }
  node[tokens.at(-1)] = value;
  return top;
}
function remove(root, pointer) {
  const tokens = tokensOf(pointer);
  let node = root;
  for (const token of tokens.slice(0, -1)) { if (!plainObject(node) || !Object.hasOwn(node, token)) return root; node = node[token]; }
  if (tokens.length && plainObject(node)) delete node[tokens.at(-1)];
  return root;
}
const differentFrom = expected => expected === PLANTED ? `${PLANTED}-planted` : PLANTED;
const cleanText = forbidden => ['clean', '0', 'ok'].find(text => !text.includes(forbidden));
// A complete JSON observation, as observeHttp reports one (no repeated member names, number source text kept).
const observe = (status, body) => {
  const text = JSON.stringify(body);
  return { status, complete: true, jsonParsed: true, json: JSON.parse(text), jsonSource: JSON.parse(text, numberSourceReviver), repeatedKeys: 0 };
};

// The status every status predicate accepts, if there is one.
function fixedStatus(assertions) {
  const sets = assertions.filter(a => a.kind === 'status.equals' || a.kind === 'status.in').map(a => a.kind === 'status.in' ? a.expected : [a.expected]);
  if (!sets.length) return 200;
  return sets[0].find(code => sets.every(set => set.includes(code))) ?? sets[0][0];
}
// The value at a pointer of a synthetic body, if one is there.
function found(root, pointer) {
  let node = root;
  for (const token of tokensOf(pointer)) { if (!plainObject(node) || !Object.hasOwn(node, token)) return { present: false }; node = node[token]; }
  return { present: true, value: node };
}
// The fixed body: each JSON predicate satisfied in order. A predicate the body already satisfies writes nothing (an exists over
// any present value, a notContains over a string without the text, a noForeignValues over a value with no foreign identifier),
// and a notContains never replaces a non-string an earlier predicate wrote (the evaluator reads it inconclusive there, so the
// pair can never both pass), so the order of predicates on one pointer never decides; a later write that still has to replace
// a value wins, and the evaluator then says which predicate cannot pass.
function fixedBody(assertions, rowsOf) {
  let body = {}, written = false;
  assertions.forEach((a, i) => {
    if (!PLANTED_KINDS.response.includes(a.kind) || a.kind.startsWith('status.') || rowsOf(body)[i].status === 'pass') return;
    if (a.kind === 'json.notContains') {
      const at = found(body, a.pointer);
      if (written && at.present && typeof at.value !== 'string') return;
    }
    if (a.kind === 'json.exists' && !a.expected) { body = remove(body, a.pointer); return; }
    body = put(body, a.pointer, a.kind === 'json.equals' ? a.expected : a.kind === 'json.exists' ? PLANTED : a.kind === 'json.notContains' ? cleanText(a.expected) : 'ok');
    written = true;
  });
  return body;
}
// Another tenant's declared identifiers, which the actor's own tenant does not also declare, in declared order.
function foreignIdentifiers(target, actorTenant) {
  const tenants = target.tenantValues?.tenants ?? {};
  const own = new Set((tenants[actorTenant]?.identifiers ?? []).map(v => v.trim()));
  return Object.values(tenants).flatMap(t => (t.identifiers ?? []).map(v => v.trim())).filter(v => !own.has(v));
}
// The defective twins of one JSON predicate: a list of planted bodies, any of which may show it can fail.
function violations(assertion, body, target, check) {
  const copy = () => structuredClone(body);
  if (assertion.kind === 'json.equals') return [put(copy(), assertion.pointer, differentFrom(assertion.expected))];
  if (assertion.kind === 'json.exists') return [assertion.expected ? remove(copy(), assertion.pointer) : put(copy(), assertion.pointer, PLANTED)];
  if (assertion.kind === 'json.notContains') return [put(copy(), assertion.pointer, `${PLANTED} ${assertion.expected} ${PLANTED}`)];
  // json.noForeignValues: a foreign identifier written literally as a whole token (at most 16 tried).
  return foreignIdentifiers(target, target.actors[check.actorId]?.tenantId).slice(0, 16).map(value => put(copy(), assertion.pointer, value));
}

// A judged predicate, from its two twins' readings. The order matters: one that cannot fail is reported as such whatever
// its fixed twin read.
const judgedOutcome = (fixed, defective) => defective !== 'fail' ? 'cannot-fail' : fixed === 'fail' ? 'always-fails' : fixed !== 'pass' ? 'pass-unreachable' : 'proven';
const judged = (layer, index, kind, fixed, defective, reason) => ({ layer, index, kind, outcome: judgedOutcome(fixed, defective), fixed, defective, ...(reason ? { reason } : {}) });
const unprovable = (layer, index, kind, reason, fixed = null, defective = null) => ({ layer, index, kind, outcome: 'unprovable', fixed, defective, reason });
// An exception is the self-test's own failure: it reads error, never a fail of the check and never proven.
const kindOf = kind => typeof kind === 'string' ? kind : null;
const errored = (layer, index, kind) => ({ layer, index, kind: kindOf(kind), outcome: 'error', fixed: null, defective: null, reason: 'exception' });
const guarded = (layer, index, kind, run) => { try { return run(); } catch { return errored(layer, index, kind); } };

function responsePredicates(check, target) {
  const assertions = Array.isArray(check.assertions) ? check.assertions : [];
  let judge, status, body, fixed;
  try {
    const compiled = target.tenantValues ? compileTenantValues(target.tenantValues) : null;
    const context = compiled ? { foreignValues: matcherFor(compiled, target.actors[check.actorId]?.tenantId, { path: check.path, body: check.body }) } : {};
    judge = observation => evaluateHttpCheck(check, observation, context).assertions;
    status = fixedStatus(assertions);
    body = fixedBody(assertions, candidate => judge(observe(status, candidate)));
    fixed = judge(observe(status, body));
  } catch {
    return assertions.map((assertion, i) => errored('response', i, assertion?.kind));
  }
  return assertions.map((assertion, i) => guarded('response', i, assertion?.kind, () => {
    if (!PLANTED_KINDS.response.includes(assertion.kind)) return unprovable('response', i, kindOf(assertion.kind), 'kind-not-planted');
    let defective;
    if (assertion.kind === 'status.equals' || assertion.kind === 'status.in') {
      const planted = assertion.kind === 'status.equals' && (assertion.expected < 200 || assertion.expected > 299) ? 200 : assertion.kind === 'status.in' ? 200 : 403;
      defective = judge(observe(planted, body))[i].status;
    } else {
      // Each reading is the predicate's own row: a plant another predicate caught never counts for this one.
      const outcomes = violations(assertion, body, target, check).map(planted => judge(observe(status, planted))[i].status);
      if (!outcomes.length) return judged('response', i, assertion.kind, fixed[i].status, 'not-planted', 'no-foreign-identifier');
      defective = outcomes.includes('fail') ? 'fail' : outcomes[0];
    }
    return judged('response', i, assertion.kind, fixed[i].status, defective);
  }));
}

// What each declared observer type can record, as its window's scope says and its events carry (integrations/observers/*):
// operations and names (pairs: the operation each name is recorded with; null: any name, for a tool observer that declares
// none), the actors it attributes to a declared principal, the resources it records for a name and a selector rule (none: it
// never records one the rule accepts; null: no resource), whether it records free-text resources the profile does not list
// (freeResource: an audit column, a span attribute, a snapshot key, a request path), whether it records a trace id, its evidence
// level, its best coverage, and the scope declarations custody reads (extra). The profile validators (src/*-rules.mjs) normalize
// the configurations whose rules they own.
const fits = (rule, value) => rule === undefined || (typeof rule === 'string' ? value === rule : typeof value === 'string' && value.startsWith(rule.prefix));
const freeText = rule => typeof rule === 'string' ? rule : rule.prefix;
const anyResource = (name, rule) => [rule === undefined ? null : freeText(rule)];
const noResource = (name, rule) => rule === undefined ? [null] : [];
const fromList = values => rule => values.filter(v => fits(rule, v));
const SEND_METHODS = ['POST', 'GET', 'PUT', 'PATCH', 'DELETE'];
const toolModel = (o, { actors, resources, freeResource, traceId }) => ({ operations: ['tool-call'], names: o.tools ?? null, pairs: o.tools ? o.tools.map(name => ({ name, operation: 'tool-call' })) : null,
  actorAttribution: 'principal', evidence: 'presence-only', actors, resources, freeResource, traceId });
// An audit table or endpoint records each declared action under its mapped operation; a denied action is never committed.
const auditModel = (actions, denied, principals, resourced) => ({ operations: [...new Set([...Object.values(actions ?? {}), 'update'])], names: [...new Set([...Object.keys(actions ?? {}), ...(denied ?? [])])],
  pairs: Object.entries(actions ?? {}).map(([name, operation]) => ({ name, operation })), actorAttribution: 'principal', evidence: 'authoritative', actors: principals ?? [],
  resources: resourced ? anyResource : noResource, freeResource: resourced, traceId: false });
// A snapshot records "<resourcePrefix or table>/<key>" per changed row, net-only; exact coverage (a change column, Postgres row
// versions) is not planted, so a clause it could decide is reported unprovable instead of judged on net-only coverage.
const snapshotModel = o => {
  const tables = o.tables ?? [], operations = ['insert', 'update', 'delete'];
  return { operations, names: tables.map(t => t.table), pairs: tables.flatMap(t => operations.map(operation => ({ name: t.table, operation }))), actorAttribution: 'none', evidence: 'authoritative',
    actors: [], traceId: false, coverage: 'net-only', reason: 'net-change-between-snapshots', freeResource: true,
    resources: (name, rule) => {
      if (rule === undefined) return [null];
      const t = tables.find(x => x.table === name), prefix = `${t.resourcePrefix ?? t.table}/`;
      const value = typeof rule === 'string' ? rule : rule.prefix.length > prefix.length ? rule.prefix : `${prefix}${PLANTED}`;
      return value.startsWith(prefix) && value.length > prefix.length && fits(rule, value) ? [value] : [];
    },
    exact: select => select.operation === 'update' && typeof select.name === 'string' && (o.type === 'pg-snapshot' || Boolean(tables.find(t => t.table === select.name)?.changeColumn)) };
};
// The WAL observer (pg-wal) decodes every committed change of its declared tables: complete coverage, the snapshot's resources, and
// no exact entries (none are needed). Its actor capture is not modelled: no actor-pinned negative is planted, as for a snapshot.
const walModel = o => { const { coverage: _coverage, reason: _reason, exact: _exact, ...model } = snapshotModel(o); return model; };
// A mail sink or provider feed records a declared address of the domain, or "*". A feed's window also names its feed record
// (scope.feed), whose declared key source decides its custody (src/custody.mjs feedKeyCustody).
const mailModel = (cfg, evidence, extra = {}) => ({ operations: ['send'], names: cfg.domains.map(d => d.domain), pairs: cfg.domains.map(d => ({ name: d.domain, operation: 'send' })), actorAttribution: 'none', evidence,
  actors: [], traceId: false, freeResource: false, resources: (name, rule) => fromList([...(cfg.domains.find(d => d.domain === name).addresses ?? []), '*'])(rule), extra });
const MODELS = Object.freeze({
  otel: o => toolModel(o, { actors: o.principals ?? [], resources: anyResource, freeResource: true, traceId: true }),
  'mcp-log': o => toolModel(o, { actors: [], resources: noResource, freeResource: false, traceId: false }),
  'sqlite-audit': o => auditModel(o.audit?.actions, o.audit?.deniedActions, o.principals, Boolean(o.audit?.resourceColumn)),
  'http-audit': o => auditModel(o.actions, o.deniedActions, o.principals, Boolean(o.fields?.resource)),
  // An audit log file records the request path as the resource, under the rule whose path template it matches.
  'audit-file': (o, target) => {
    const rules = validateAuditFileConfig(o, target.actors), operations = o.rules.map(r => r.operation ?? 'update');
    return { operations: [...new Set(operations)], names: rules.map(r => r.name), pairs: rules.map((r, k) => ({ name: r.name, operation: operations[k] })), actorAttribution: 'principal', evidence: 'authoritative',
      actors: Object.keys(o.logActors ?? {}), traceId: false, freeResource: true,
      resources: (name, rule) => rule === undefined ? [null] : rules.find(r => r.name === name).regex.test(freeText(rule)) ? [freeText(rule)] : [] };
  },
  'sqlite-snapshot': snapshotModel, 'pg-snapshot': snapshotModel, 'mysql-snapshot': snapshotModel, 'pg-wal': walModel,
  // An egress recorder records "METHOD <declared path prefix>" or "METHOD *", never an actor or a trace id.
  'egress-recorder': (o, target) => {
    const cfg = validateEgressConfig(o, target.actors);
    return { operations: ['send'], names: cfg.destinations.map(d => d.host), pairs: cfg.destinations.map(d => ({ name: d.host, operation: 'send' })), actorAttribution: 'none',
      evidence: cfg.routing ? 'authoritative' : 'presence-only', actors: [], traceId: false, freeResource: false,
      resources: (name, rule) => fromList([...(cfg.destinations.find(d => d.host === name).paths ?? []), '*'].flatMap(path => SEND_METHODS.map(method => `${method} ${path}`)))(rule) };
  },
  'smtp-sink': (o, target) => { const cfg = validateSmtpConfig(o, target.actors); return mailModel(cfg, cfg.routing ? 'authoritative' : 'presence-only'); },
  'provider-feed': (o, target) => { const cfg = validateProviderFeedConfig(o, target.actors); return mailModel(cfg, cfg.witness && cfg.feed.kind === 'endpoint' ? 'authoritative' : 'presence-only', { feed: providerFeedRecord(o) }); },
});
export const MODELLED_OBSERVER_TYPES = Object.freeze(Object.keys(MODELS));
// One model per declared observer, in profile order. A type without a model throws (the predicate reads error).
function observerModels(target) {
  return (Array.isArray(target.observers) ? target.observers : []).map(o => {
    if (!Object.hasOwn(MODELS, o?.type)) throw new Error('known-negative: observer type not modelled');
    const m = MODELS[o.type](o, target);
    return { ...m, ...OBSERVER_OUTPUT[o.type], instanceId: observerInstanceId(o.type, o.id), settleMs: settleDeclared(o.settleMs) ? o.settleMs : null,
      scope: { operations: m.operations, names: m.names, actorAttribution: m.actorAttribution, evidence: m.evidence, ...(m.extra ?? {}) }, coverage: m.coverage ?? 'complete', reason: m.reason ?? null };
  });
}
// The window scope each declared observer is planted with: { instanceId, source, scope }, in profile order.
export const observerScopes = target => observerModels(target).map(m => ({ instanceId: m.instanceId, source: m.source, scope: m.scope }));

// Why no observer can record a selected effect, from the farthest any observer got.
const UNRECORDED = ['no-observer', 'name-not-declared', 'operation-not-recorded', 'actor-not-recorded', 'resource-not-recorded', 'trace-not-recorded', 'plant-not-matched'];
const OBSERVED_AT = '2026-01-01T00:00:00.000Z';
const eventsOf = (m, effect, n) => Array.from({ length: n }, (_, k) => makeEffect({ ...effect, observer: { kind: m.kind, instanceId: m.instanceId }, seq: k + 1, observedAt: OBSERVED_AT }));
// Every declared observer's window, settled as the run settles it; the planted events in the chosen observer's window only.
const windowsOf = (models, plant, n) => models.map(m => applySettle(validateWindow({ source: m.source, instanceId: m.instanceId, scope: m.scope, coverage: m.coverage, reason: m.reason,
  events: plant && m === plant.model ? eventsOf(m, plant.effect, n) : [] }), m.settleMs));
// The effects a declared observer can record that the selector selects, and the observer: { model, effects } or { reason }. The
// first effect stands for all of them; all: every one, as attribution reads them (each actor and resource the observer records).
function plantFor(models, select, all = false) {
  let farthest = 0;
  const reached = depth => { farthest = Math.max(farthest, depth); };
  const ordered = [...models.filter(m => m.scope.evidence === 'authoritative'), ...models.filter(m => m.scope.evidence !== 'authoritative')];
  for (const m of ordered) {
    if (select.source !== undefined && select.source !== m.source) continue;
    reached(1);
    const pairs = (m.pairs ?? (select.name === undefined ? m.operations.map(operation => ({ name: PLANTED, operation })) : [])).filter(p => fits(select.name, p.name));
    if (!pairs.length) continue;
    reached(2);
    const operated = pairs.filter(p => select.operation === undefined || p.operation === select.operation);
    if (!operated.length) continue;
    reached(3);
    if (select.actor !== undefined && !(m.scope.actorAttribution === 'principal' && m.actors.includes(select.actor))) continue;
    reached(4);
    const pair = operated.find(p => m.resources(p.name, select.resource).length);
    if (!pair) continue;
    reached(5);
    // An OpenTelemetry trace id is 32 lowercase hex digits; no other observer records one.
    if (select.traceId !== undefined && !(m.traceId && /^[0-9a-f]{32}$/.test(select.traceId))) continue;
    reached(6);
    // The actor a real event carries: the pinned one, or each principal an observer that names principals declares.
    const actors = select.actor !== undefined ? [select.actor] : m.scope.actorAttribution === 'principal' && m.actors.length ? m.actors : [null];
    const effects = [];
    for (const actor of actors) for (const resource of m.resources(pair.name, select.resource)) {
      if (effects.length && !all) break;
      const effect = { source: m.source, actor, operation: pair.operation, name: pair.name, resource, outcome: 'committed', correlation: select.traceId === undefined ? {} : { traceId: select.traceId } };
      // The plant must be one the selector selects and the observer's own window sees: otherwise it proves nothing.
      const [window] = windowsOf([m], { model: m, effect }, 1);
      if (windowSees(window, select) && matches(window.events[0], { ...select, outcome: 'committed' })) effects.push(effect);
    }
    if (effects.length) return { model: m, effects };
  }
  return { reason: UNRECORDED[farthest] };
}
// The pairing stage (src/http-pairing.mjs) at its best: every twin and guard control the profile declares is sent and matches.
// A boundary absence that pins an actor, resource, trace id, fields or upstream passes only beside a twin for each pin that an
// observer deciding the absence can record (selector-unpaired, selector-not-shown-to-match); an unpinned absence of a check
// that accepts a success and has no positive clause, only beside a required allowed-use control (allowed-use-not-declared).
function pairingReason(check, target, models, effect, index, role, windows) {
  if (role === 'control' || !absenceClause(effect)) return null;
  const checks = Array.isArray(target.checks) ? target.checks : [];
  const profile = checks.includes(check) ? target : { ...target, checks: [...checks.filter(c => c?.id !== check.id), check] };
  if (!needsPairing(effect.select)) {
    const guard = (allowedUseGuards(profile).get(check.id) ?? []).find(e => e.effect === index);
    return guard && !guard.guards.length ? 'allowed-use-not-declared' : null;
  }
  const entry = (selectorPairs(profile).get(check.id) ?? []).find(e => e.effect === index);
  if (!entry || Object.values(entry.pins).some(twins => !twins.length)) return 'selector-unpaired';
  const deciders = new Set(decidingWindows(windows, { kind: effect.kind, select: effect.select, verdict: 'pass' }).map(w => w.instanceId));
  const shown = ({ checkId, effect: k }) => { const select = profile.checks.find(c => c?.id === checkId)?.effects?.[k]?.select; return models.some(m => deciders.has(m.instanceId) && !plantFor([m], select).reason); };
  return Object.values(entry.pins).every(twins => twins.some(shown)) ? null : 'selector-not-shown-to-match';
}
// Attribution as a run applies it (src/http-connector.mjs: attributionFindings over the settled rows, then applyAttribution),
// or the decision unchanged when the profile declares neither background sources nor withheld late fails. The rows: every check
// a run gives an effect window, in profile order (the checked one in its place, or last when the profile does not list it, as
// pairingReason places it); the checked clause alone in its row, over the planted windows; the other rows' selectors over every
// declared observer's window, empty; no gap or barrier event, and no correlation tokens.
const attributing = target => Boolean(target.attribution) || target.timing?.lateFails === LATE_FAILS;
function effectRows(check, target) {
  const checks = Array.isArray(target.checks) ? target.checks : [];
  const listed = checks.includes(check) ? checks : [...checks.filter(c => c?.id !== check.id), check];
  const rows = listed.filter(c => c === check || (Boolean(c?.effects || c?.claims) && c?.applicability?.applies !== false));
  return { rows, k: rows.indexOf(check) };
}
// Another row's clauses are never examined here (no verdict), only read for the selectors they declare.
const declaredOf = c => [...(Array.isArray(c.effects) ? c.effects : []).map(e => ({ ...e, verdict: null })), ...(Array.isArray(c.claims) ? c.claims : []).map(claim => ({ kind: null, select: claim?.select, verdict: null }))];
function attributed(check, target, models, decision, windows, role) {
  if (!attributing(target)) return decision;
  const { rows: listed, k } = effectRows(check, target);
  const rows = listed.map((c, j) => j === k ? { effects: [decision], windows } : { effects: declaredOf(c), windows: windowsOf(models, null, 0) });
  const findings = attributionFindings(rows, [...rows.map(() => []), []], undefined, { background: target.attribution?.background ?? [], lateFails: target.timing?.lateFails === LATE_FAILS });
  return applyAttribution([decision], findings[k], role)[0];
}
// The selectors attribution reads a plant in the checked row against: every background source's, and every earlier row's (an
// earlier check's late effect), as attributionFindings reads them (an upstream requirement set aside). A later row's never
// explains it, and there are no correlation tokens, so two plants that fit the same of these read the same.
function absorbingRules(check, target) {
  const { rows, k } = effectRows(check, target);
  return [...(target.attribution?.background ?? []).map(source => source.select), ...rows.slice(0, k).flatMap(c => declaredOf(c).flatMap(selectorsOf)).filter(plainObject).map(withoutUpstream)];
}
// The value a plant lacks that attribution read: the observer records an actor (or a free-text resource) the profile gives none
// of, and every rule the plant fits pins one it lacks, so a real value could fit none of them.
function lackedValue(model, event, rules) {
  const lacked = [model.scope.actorAttribution === 'principal' && event.actor === null ? 'actor' : null, model.freeResource && event.resource === null ? 'resource' : null].filter(Boolean);
  const fitting = rules.filter(rule => fitsWide(event, rule));
  if (!lacked.length || !fitting.length || !fitting.every(rule => lacked.some(key => rule[key] !== undefined))) return null;
  return `${lacked.find(key => fitting.some(rule => rule[key] !== undefined))}-not-declared`;
}
// Why a clause's fixed twin did not pass or its defective twin did not fail: attribution, custody, pairing, or what the evaluator
// read first: a name not given exactly, no authoritative observer (presence-only evidence), more than one counting observer, or the
// first gap the windows that can see it show (no declared settle, net-only coverage). Attribution touches only a pass or a fail, so
// a clause it moved to inconclusive was not held by custody; an allowed-use control's fail it only tags still fails.
function gapReason(decision, windows, select, kind) {
  if (decision.attribution && decision.verdict === 'inconclusive') return decision.attribution;
  if (decision.custodyReason) return 'custody';
  if (decision.pairing) return decision.pairing;
  if (typeof select.name !== 'string') return 'name-not-exact';
  const relevant = windows.filter(w => windowSees(w, select)), authoritative = relevant.filter(w => w.scope.evidence === 'authoritative');
  if (!authoritative.length) return 'presence-only';
  if (kind === 'effect.count' && authoritative.length !== 1) return 'count-observers';
  return authoritative.find(w => w.coverage !== 'complete')?.reason ?? undefined;
}
// How many matching committed effects satisfy (fixed) and violate (defective) a core clause.
const COUNTS = Object.freeze({ 'effect.none': () => [0, 1], 'effect.exists': () => [1, 0], 'effect.count': e => [e.expected, e.expected + 1] });
// The attribution reasons a plant's own fit decides (background-unobserved reads only the windows).
const ABSORBED = ['background-unattributed', 'late-unattributed'];
// Which plant's reading stands: one that proves the clause, then one that shows it can fail, then one that shows nothing, and
// a broken reading only when every plant gives one.
const PREFERRED = ['proven', 'pass-unreachable', 'unprovable', 'always-fails', 'cannot-fail'];
function effectPredicates(check, target) {
  const role = roleOfSeverity(check.severity);
  let models = null;
  return (Array.isArray(check.effects) ? check.effects : []).map((effect, i) => guarded('effect', i, effect?.kind, () => {
    const notPlanted = effect?.kind === 'effect.only' ? 'effect.only' : !PLANTED_KINDS.effect.includes(effect?.kind) ? 'kind-not-planted' : effect.countBy !== undefined ? 'countBy'
      : effect.select?.fields !== undefined ? 'body-fields' : effect.select?.upstream !== undefined ? 'upstream' : null;
    if (notPlanted) return unprovable('effect', i, kindOf(effect?.kind), notPlanted);
    models ??= observerModels(target);
    // Only attribution reads a plant's actor and resource, so only there does more than the first plant need judging.
    const rules = attributing(target) ? absorbingRules(check, target) : null;
    const plant = plantFor(models, effect.select, rules !== null);
    if (plant.reason) return unprovable('effect', i, effect.kind, plant.reason);
    const [ok, bad] = COUNTS[effect.kind](effect);
    const judge = planted => {
      // The run's own decision path, one clause at a time: decideEffects over every declared observer's window (custody
      // included), then attribution, which can move a pass or a fail to inconclusive.
      const decide = n => {
        const windows = windowsOf(models, { model: plant.model, effect: planted }, n);
        return { decision: attributed(check, target, models, decideEffects([effect], windows, { role })[0], windows, role), windows };
      };
      const fixed = decide(ok), defective = decide(bad);
      // Pairing withholds a pass only, after attribution, as the run applies it.
      const paired = pairingReason(check, target, models, effect, i, role, fixed.windows);
      if (paired) fixed.decision = applyPairing([fixed.decision], [paired], role)[0];
      const fixedVerdict = fixed.decision.verdict, defectiveVerdict = defective.decision.verdict;
      // The planted reason: a fail that matched exactly the planted effects (none for an absence the plant left empty). A fixed
      // twin that fails too is always-fails whatever its defective twin matched: the best observation fails, so the check is broken.
      if (defectiveVerdict === 'fail' && fixedVerdict !== 'fail' && defective.decision.matched !== bad) return unprovable('effect', i, effect.kind, 'failed-for-another-reason', fixedVerdict, defectiveVerdict);
      const outcome = judgedOutcome(fixedVerdict, defectiveVerdict);
      // The reason is read on the twin that missed: the defective one for a clause that cannot fail, the fixed one otherwise.
      const missed = outcome === 'cannot-fail' ? defective : fixed;
      const reason = outcome === 'proven' ? undefined : gapReason(missed.decision, missed.windows, effect.select, effect.kind);
      // Exact coverage could change a coverage reason, never a planted send attribution reads as another's.
      if (outcome !== 'proven' && !ABSORBED.includes(reason) && plant.model.exact?.(effect.select)) return unprovable('effect', i, effect.kind, 'exact-coverage-not-planted', fixedVerdict, defectiveVerdict);
      return judged('effect', i, effect.kind, fixedVerdict, defectiveVerdict, reason);
    };
    // One plant per set of absorbing rules it fits (two that fit the same read the same), best first; a proven one ends it.
    const eventOf = planted => eventsOf(plant.model, planted, 1)[0];
    const tried = new Set();
    let best = null;
    for (const planted of plant.effects) {
      if (rules) { const event = eventOf(planted), fit = rules.map(rule => fitsWide(event, rule) ? 1 : 0).join(''); if (tried.has(fit)) continue; tried.add(fit); }
      const row = judge(planted);
      if (!best || PREFERRED.indexOf(row.outcome) < PREFERRED.indexOf(best.row.outcome)) best = { row, planted };
      if (row.outcome === 'proven') break;
    }
    // Every plant absorbed, each only through a rule that pins a value the profile gives none of: not shown, never broken.
    const lacked = rules && ['cannot-fail', 'pass-unreachable'].includes(best.row.outcome) && ABSORBED.includes(best.row.reason) ? lackedValue(plant.model, eventOf(best.planted), rules) : null;
    return lacked ? unprovable('effect', i, effect.kind, lacked, best.row.fixed, best.row.defective) : best.row;
  }));
}

const outcomeOf = predicates => {
  const has = outcome => predicates.some(p => p.outcome === outcome);
  if (has('cannot-fail') || has('always-fails')) return 'broken';
  if (has('error')) return 'error';
  if (predicates.length && predicates.every(p => p.outcome === 'proven')) return 'proven';
  return has('proven') || has('pass-unreachable') ? 'partial' : 'unprovable';
};
// One check of a validated target (validateTargetFile).
export function knownNegativeCheck(check, target) {
  try {
    const predicates = [...responsePredicates(check, target), ...effectPredicates(check, target),
      ...(Array.isArray(check.claims) ? check.claims : []).map((_, i) => unprovable('claim', i, 'claim', 'claim-rule'))];
    return { id: check.id, outcome: outcomeOf(predicates), predicates };
  } catch {
    return { id: typeof check?.id === 'string' ? check.id : null, outcome: 'error', predicates: [], reason: 'exception' };
  }
}
export function knownNegativeTarget(target) {
  const checks = (Array.isArray(target?.checks) ? target.checks : []).map(check => knownNegativeCheck(check, target));
  const tally = list => Object.fromEntries(list.map(o => [o, 0]));
  const counts = { checks: tally(CHECK_OUTCOMES), predicates: tally(PREDICATE_OUTCOMES) };
  for (const c of checks) { counts.checks[c.outcome]++; for (const p of c.predicates) counts.predicates[p.outcome]++; }
  // An empty check list proves nothing.
  const outcome = counts.checks.broken ? 'broken' : counts.checks.error ? 'error' : checks.length && counts.checks.proven === checks.length ? 'proven'
    : counts.checks.proven || counts.checks.partial ? 'partial' : 'unprovable';
  return { schema: KNOWN_NEGATIVE_SCHEMA, targetId: target?.id ?? null, outcome, counts, checks };
}

// A seeded canary value: one planted form per channel, and a clean corpus that must pass. Each form must be caught on its
// own channel; a form another channel caught never exercised its own, so it reads unprovable (caught-on-another-channel).
//   verbatim  the value as it is;
//   folded    a zero-width space after its first character, which folding removes (unlike a case change, it needs no
//             cased letter in the value; the value rule now asks for an ASCII letter, so the two plants agree today);
//   skeleton  its letters and digits joined by a separator the value does not use, so the plant is never the value itself;
//   encoded   its bytes in base64, which the three channels above read as the value only when that base64 spells the
//             value's own letters and digits (a value built to do so reads unprovable: the skeleton channel catches it).
// A value canaryVerdict cannot judge (outside printable ASCII or not marker-shaped, too long, low entropy:
// canaryValueReason) cannot fail.
// test/known-negative.test.mjs holds these forms equal to CANARY_CHANNELS, so a channel canaryVerdict adds fails it until a
// plant for the new channel is added here (without one, a form the new channel catches first reads unprovable).
const SEPARATORS = ['-', '.', '_', ':', '/', '+', '~'];
export const CANARY_FORMS = Object.freeze(['verbatim', 'folded', 'skeleton', 'encoded']);
export function knownNegativeCanary(value) {
  const reason = canaryValueReason(value);
  if (reason) return { outcome: 'cannot-fail', reason };
  try {
    const chars = [...value], separator = SEPARATORS.find(s => !value.includes(s));
    const planted = { verbatim: value, folded: `${chars[0]}\u200B${chars.slice(1).join('')}`, skeleton: separator ? chars.filter(ch => /[\p{L}\p{N}]/u.test(ch)).join(separator) : null,
      encoded: Buffer.from(value, 'utf8').toString('base64') };
    const forms = CANARY_FORMS.map(form => {
      if (planted[form] === null) return { form, outcome: 'unprovable', caught: null, reason: 'no-plant' };
      const v = canaryVerdict([`${PLANTED} ${planted[form]} ${PLANTED}`], value, { complete: true });
      const outcome = v.outcome !== 'fail' ? 'cannot-fail' : v.channel === form ? 'proven' : 'unprovable';
      return { form, outcome, caught: v.channel ?? v.outcome, ...(outcome === 'unprovable' ? { reason: 'caught-on-another-channel' } : {}) };
    });
    const clean = canaryVerdict(['clean body', 'status', 'ok'], value, { complete: true }).outcome;
    const has = outcome => forms.some(f => f.outcome === outcome);
    const outcome = has('cannot-fail') ? 'cannot-fail' : clean === 'fail' ? 'always-fails' : has('unprovable') ? 'unprovable' : clean !== 'pass' ? 'pass-unreachable' : 'proven';
    return { outcome, fixed: clean, defective: Object.fromEntries(forms.map(f => [f.form, f.caught])), channels: Object.fromEntries(forms.map(f => [f.form, f.reason ? { outcome: f.outcome, reason: f.reason } : { outcome: f.outcome }])) };
  } catch {
    return { outcome: 'error', reason: 'exception' };
  }
}
