// Two identities by default (NC2 item 1). Pure: no I/O.
//
// A target that declares tenant-scoped resources ("tenantValues": each tenant's synthetic record values) is tested from
// both sides of its tenant boundary:
//   identityCoverage(target, plan)  the credentialed identities: actors with an "identityValue", a "tenantId" that is one of
//                              the declared tenants, and at least one identity control (plan: src/contracts.mjs
//                              identityControlPlan). Fewer than two distinct tenants is a single-identity profile:
//                              check-config warns, and assess refuses it unless --single-identity is given (src/cli.mjs).
//   mirrorPlan(target, plan)   for each boundary check (any severity but "control") of such an identity, the generated
//                              mirror under the second identity, or the reason none is generated. Mirrors are opt-in: a
//                              target that declares no "mirrors" object gets none (mirrors-undeclared) and runs exactly its
//                              declared checks, since mirrors add requests a per-user limit may not leave room for (below).
//                              The mirror is a check of the profile, sent in the mirror phase (below), "mirrorOf" naming its
//                              source: its json.noForeignValues assertions read the second identity's tenant, so its results
//                              feed the existing TENANT checks from the other side.
//   mirrorChecks(target, plan) the declared checks (every check without "mirrorOf"), then each generated mirror in its
//                              source's order; a check that declares "mirrorOf" must be exactly the mirror generated from its
//                              source. src/contracts.mjs validates the result as one profile and leaves out, one by one, a
//                              mirror that would break a profile rule (profile-rule).
//
// The rule: a mirror is generated only where the profile's own checks show what the second identity's request reaches, so it
// does not read a refusal as a leak, the second identity's own record as another tenant's, or one tenant's plan, settings or
// record state as the other's, and it never writes what a correct application accepts. It rests on the profile's
// declarations: the counterparts are equivalent records in the same state that no declared check changes, each declared
// value is held by its tenant alone (a declared check that sends it to the other tenant makes it held by both), the tenants
// are configured alike, and a GET changes nothing. Only declared values are rewritten: each declared counterpart pair
// between the two tenants ("mirrors": { "counterparts": [[a, b], ...] }), whole and written exactly. Nothing else in the
// check changes, so:
//   - a check that names either identity (its alias, principalId, identityValue or tenantId, in any letter case, anywhere in
//     the path, the body or a predicate; a name under three characters only as a whole text) is not mirrored
//     (names-an-identity): the profile's labels are not the application's values, and a route or field can share a label's
//     spelling;
//   - after the swap, a declared value of either tenant in any other form, or without a counterpart, or one two tenants
//     share, leaves the check unmirrored; so does an identifier the profile did not declare (undeclared-identifier): a
//     path segment or query part holding a digit (an API version such as v2 aside), a JSON number or a one-word string in
//     the body, and, in a check that expects a refusal, a word holding a digit in the body's text;
//   - a json.equals or json.notContains whose expected text is not a swapped value describes the first identity's view
//     (predicate-names-own-view), and so does any json.equals or json.exists in a check that expects a success (a swapped
//     value there would assume the pairs also match each other's relations); json.noForeignValues always stays;
//   - a request that names no declared value of either tenant says nothing about whose resource it reaches, so it is
//     mirrored only as an answer probe: json.noForeignValues as its only predicate and an expected 2xx (status.equals);
//   - a check expects a success (status.equals a 2xx) or a refusal (any other status; status.in holds only refusals and
//     redirects). A refusal is mirrored only across the boundary and only as a read: with a boundary status (401, 403, 404
//     or the declared sign-in redirect; a 409 or 422 is about a record's state, refusal-not-boundary-status), naming a
//     value of the second identity's tenant (one that names only the first's is about its own record or settings,
//     own-record-refusal), as a GET (a refused write the application might accept is never sent on a guess,
//     refusal-not-a-read), and only beside the first identity's own allowed twin (refusal-twin-not-shown): an applicable
//     success of that identity with the same method and route, part for part, holding the counterpart wherever the refusal
//     holds the other tenant's value of the pairs (its own records, in the same relation). The declared value is then the
//     only difference between the allowed request and the refused one, so a workspace slug, a search term, a filter or an
//     invitee is never what the mirror's refusal rests on. A success is mirrored only on the first tenant's own values
//     (foreign-record-success) or as an answer probe, and only as a read (success-not-a-read): a GET, or a POST answer
//     probe answered 200 on a route the profile declares read-only ("readOnlyRoutes": ["POST /api/chat"], an assistant
//     that only answers; the declaration covers every query on the route, and a mirrored turn resends the same message
//     under the second identity);
//   - no declared write changes a record the mirror names (counterpart-written): mirrors run after every declared check,
//     so a value named in the path, query or body of an applicable non-GET check that expects a success or a redirect (a
//     POST on a declared read-only route aside) is no longer in the state its pair declares by then. A write that reaches a
//     record without naming it (an assistant told to act on "my latest order", a cascade) is not seen: the counterparts are
//     declared as records no declared check changes. A mirror that names a written value anywhere, its body included, is
//     not generated;
//   - the route must be one the second identity's own applicable checks are shown on (a check that is not applicable shows
//     nothing). A refusal mirror needs the second identity's own allowed twin of the mirror (by the rule above, the source's
//     request in its own form), so both identities are shown allowed there with their own values and a symmetric
//     application refuses the mirror for the source's reason, with its status; a success mirror needs a check of the second
//     identity that expects a success within the mirror's statuses, on exactly the mirror's path for a GET (the counterpart
//     record itself, so its state is shown), on the same method and route for a read-only POST
//     (route-not-used-by-second-identity). The same request declared for the second identity with statuses none of which
//     the mirror expects contradicts it (contradicts-second-identity-check).
// Mirrors run in their own phase (src/http-connector.mjs): after every declared check, the final mark, the observers' stop and
// every actor's identity-refusal probes, outside the identity brackets, between probe points of their own that bind mirror rows
// only (src/contracts.mjs rowIdentityReason). So nothing a mirror sends reaches a declared check's request, window, probe or
// verdict. A per-user rate or question limit without room for them answers the mirrors, never a declared check: a mirror
// answered 429, or a status the declaration names ("rateLimitStatuses"), reads inconclusive (src/contracts.mjs
// evaluateHttpCheck, limitStatuses), and a mirror-phase probe point the limit answers withholds the mirrors it covers. mirrorReport's
// extraRequests counts each identity's added requests, the headroom that keeps the mirrors decided.
// The second identity is one in another declared tenant with the same declared role and the same declared refusals
// (refusesWith401, signInRedirectStatus): the one whose tenant the check names, else the first by alias in that tenant.
// Never mirrored: allowed-use controls, checks with effect clauses (their pairing twins and guards are the first
// identity's), checks that capture, use captures, declare a precondition, restsOn, a webhook or claim rules, a check that is
// not applicable, and any check of a target that declares a lifecycle or a timing plan. "mirrors": "off" turns generation
// off, as leaving "mirrors" out does.
import { compileTenantValues, matcherFor, FOREIGN_VALUES_KIND } from './tenant-values.mjs';

export const MIRROR_SCHEMA = 'scopehaven-mirrors/11';
export const MIRROR_SUFFIX = '-mirror';
export const MIRROR_LIMITS = Object.freeze({ counterparts: 512, readOnlyRoutes: 16, rateLimitStatuses: 4 });
// A mirror answered with one of these statuses was answered by a per-user rate or question limit, not by the tenant boundary:
// 429 always, and those the declaration names. Never a status a mirror expects (a 2xx, or a boundary refusal: 401, 403, 404 or
// a sign-in redirect, which is a 3xx), so a limit answer can never pass a mirror.
export const MIRROR_RATE_LIMIT_STATUS = 429;
const BOUNDARY_REFUSALS = [401, 403, 404];
export const mirrorLimitStatuses = target => [MIRROR_RATE_LIMIT_STATUS, ...(plain(target?.mirrors) ? [...(target.mirrors.rateLimitStatuses ?? [])].sort((a, b) => a - b) : [])];
// The run's record of them (src/contracts.mjs validateHttpRunEvidence): 429, then each declared one, in ascending order.
export const validMirrorLimitStatuses = list => Array.isArray(list) && list.length >= 1 && list.length <= 1 + MIRROR_LIMITS.rateLimitStatuses && list[0] === MIRROR_RATE_LIMIT_STATUS
  && list.slice(1).every((s, k, rest) => Number.isInteger(s) && s >= 400 && s <= 599 && !BOUNDARY_REFUSALS.includes(s) && s !== MIRROR_RATE_LIMIT_STATUS && (k === 0 || rest[k - 1] < s));
// Why a boundary check has no generated mirror, in the order they are tested (profile-rule: src/contracts.mjs).
export const MIRROR_SKIP_REASONS = Object.freeze(['mirrors-undeclared', 'mirrors-off', 'lifecycle-declared', 'timing-declared', 'not-applicable', 'actor-not-tenant-identity', 'role-undeclared', 'no-second-identity',
  'uses-capture', 'uses-precondition', 'uses-rests-on', 'uses-webhook', 'uses-claims', 'uses-effects', 'uses-read-back', 'names-an-identity', 'tenant-value-shared', 'tenant-value-without-counterpart',
  'tenant-value-variant', 'undeclared-identifier', 'predicate-names-own-view', 'resource-owner-unknown', 'refusal-not-boundary-status', 'own-record-refusal',
  'refusal-not-a-read', 'refusal-twin-not-shown', 'foreign-record-success', 'success-not-a-read', 'contradicts-second-identity-check', 'counterpart-written', 'route-not-used-by-second-identity', 'already-declared', 'mirror-id-unavailable', 'profile-rule']);
const UNSAFE_KEYS = ['__proto__', 'prototype', 'constructor'];
const STATUS_KINDS = ['status.equals', 'status.in'];
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const bad = message => { throw new Error(message); };

// The credentialed identities with a declared tenant and an identity control, and whether the profile is one-sided.
export function identityCoverage(target, plan) {
  if (!(plan instanceof Map)) throw new Error('identityCoverage needs the identity control plan (src/contracts.mjs identityControlPlan)');
  const tenantScoped = plain(target?.tenantValues) && plain(target.tenantValues.tenants);
  const tenants = tenantScoped ? Object.keys(target.tenantValues.tenants) : [];
  const identities = Object.entries(target?.actors ?? {}).filter(([alias, actor]) => typeof actor?.identityValue === 'string' && typeof actor.tenantId === 'string' && tenants.includes(actor.tenantId)
    && (plan.get(alias)?.identityControls?.length ?? 0) > 0)
    .map(([actor, { tenantId }]) => ({ actor, tenant: tenantId })).sort((a, b) => a.actor < b.actor ? -1 : a.actor > b.actor ? 1 : 0);
  const distinct = new Set(identities.map(i => i.tenant)).size;
  return { tenantScoped, identities, tenants: distinct, singleIdentity: tenantScoped && distinct < 2 };
}

// The declaration: "off", or { counterparts: [[value, value], ...], readOnlyRoutes?: ["POST /path", ...], rateLimitStatuses?:
// [503, ...] }. Each value is written exactly as one tenant, and only that tenant, declares it (an identifier or an attribute);
// a pair names two tenants; a value is in at most one pair. readOnlyRoutes are the POST routes (method and path, no query) the
// author declares answer without side effects, such as an assistant that only answers; each must be a route a declared check
// uses. rateLimitStatuses are the statuses besides 429 the application's per-user rate or question limits answer with (each
// from 400 to 599, never a boundary refusal: 401, 403 or 404). Messages name positions, never a value or a tenant id (as
// src/tenant-values.mjs does).
export function validateMirrorDeclaration(decl, tenantValues, checks = []) {
  if (decl === 'off') return;
  if (!plain(decl) || Reflect.ownKeys(decl).some(key => !['counterparts', 'readOnlyRoutes', 'rateLimitStatuses'].includes(key))) bad('must be "off" or { "counterparts": [[value, value], ...], "readOnlyRoutes": ["POST /path", ...], "rateLimitStatuses": [503, ...] }');
  const limits = Object.hasOwn(decl, 'rateLimitStatuses') ? decl.rateLimitStatuses : [];
  if (!Array.isArray(limits) || limits.length > MIRROR_LIMITS.rateLimitStatuses || new Set(limits).size !== limits.length) bad(`"rateLimitStatuses" must be a list of at most ${MIRROR_LIMITS.rateLimitStatuses} distinct statuses`);
  limits.forEach((status, s) => {
    if (!Number.isInteger(status) || status < 400 || status > 599) bad(`rate-limit status ${s + 1}: a status from 400 to 599`);
    if (BOUNDARY_REFUSALS.includes(status)) bad(`rate-limit status ${s + 1}: 401, 403 and 404 are the boundary refusals a mirror expects, never a limit answer`);
    if (status === MIRROR_RATE_LIMIT_STATUS) bad(`rate-limit status ${s + 1}: 429 is always read as a limit answer; declare only the others`);
  });
  const routes = Object.hasOwn(decl, 'readOnlyRoutes') ? decl.readOnlyRoutes : [];
  if (!Array.isArray(routes) || routes.length > MIRROR_LIMITS.readOnlyRoutes || new Set(routes).size !== routes.length) bad(`"readOnlyRoutes" must be a list of at most ${MIRROR_LIMITS.readOnlyRoutes} distinct routes`);
  routes.forEach((route, r) => {
    if (typeof route !== 'string' || !/^POST \/[^?#\s]*$/.test(route)) bad(`read-only route ${r + 1}: a route is "POST /path" (no query)`);
    if (!checks.some(check => `${check?.method} ${typeof check?.path === 'string' ? check.path.split('?')[0] : ''}` === route)) bad(`read-only route ${r + 1}: no declared check uses it`);
  });
  if (!plain(tenantValues)) bad('needs the target to declare "tenantValues" (mirrors are generated only for tenant-scoped resources)');
  const pairs = Object.hasOwn(decl, 'counterparts') ? decl.counterparts : [];
  if (!Array.isArray(pairs) || pairs.length > MIRROR_LIMITS.counterparts) bad(`"counterparts" must be a list of at most ${MIRROR_LIMITS.counterparts} pairs`);
  const owner = ownerOf(tenantValues), seen = new Set();
  pairs.forEach((pair, p) => {
    const where = `counterpart ${p + 1}`;
    if (!Array.isArray(pair) || pair.length !== 2 || pair.some(v => typeof v !== 'string')) bad(`${where}: a pair is two strings`);
    const [a, b] = pair.map(v => owner.get(v));
    if (a === undefined || b === undefined) bad(`${where}: each value must be written exactly as one tenant, and only that tenant, declares it in "tenantValues"`);
    if (a === b) bad(`${where}: the two values must belong to two different tenants`);
    for (const v of pair) { if (seen.has(v)) bad(`${where}: a value is in at most one pair`); seen.add(v); }
  });
}
// Each declared literal (trimmed, as the scan reads it) that exactly one tenant declares, with that tenant.
function ownerOf(tenantValues) {
  const owners = new Map();
  for (const [tenant, classes] of Object.entries(tenantValues.tenants ?? {})) for (const list of [classes?.identifiers ?? [], classes?.attributes ?? []]) for (const raw of list) {
    if (typeof raw !== 'string') continue;
    const literal = raw.trim();
    owners.set(literal, owners.has(literal) && owners.get(literal) !== tenant ? null : tenant);
  }
  for (const [literal, tenant] of owners) if (tenant === null) owners.delete(literal);
  return owners;
}

// Every string of a JSON value (object keys included), mapped by fn; numbers, booleans and null unchanged.
const mapStrings = (value, fn) => typeof value === 'string' ? fn(value) : Array.isArray(value) ? value.map(v => mapStrings(v, fn))
  : plain(value) ? Object.fromEntries(Object.entries(value).map(([k, v]) => [fn(k), mapStrings(v, fn)])) : value;
// A JSON value's string leaves (values, and keys separately) and how many numbers it holds.
const leaves = (value, out = { values: [], keys: [], numbers: 0 }) => {
  if (typeof value === 'string') out.values.push(value); else if (typeof value === 'number') out.numbers += 1;
  else if (Array.isArray(value)) value.forEach(v => leaves(v, out)); else if (plain(value)) for (const [k, v] of Object.entries(value)) { out.keys.push(k); leaves(v, out); }
  return out;
};
const escape = text => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
// Whole-token occurrences: not beside another letter or digit.
const tokenPattern = (literals, flags = 'gu') => literals.length ? new RegExp(`(?<![\\p{L}\\p{N}])(?:${[...literals].sort((a, b) => b.length - a.length || (a < b ? -1 : 1)).map(escape).join('|')})(?![\\p{L}\\p{N}])`, flags) : null;
const decoded = text => { try { return decodeURIComponent(text.replaceAll('+', ' ')); } catch { return text; } };
// The declared values whose loose reading (src/tenant-values.mjs: letters and digits, case folded, accents removed) occurs
// in the texts the request names, as the scan's echo rule reads them (the decoded path and query, body keys, strings and
// numbers), each body string read percent-decoded too.
function seenValues(compiled, request) {
  const body = request.body === undefined ? undefined : [request.body, leaves(request.body).values.map(decoded)];
  const looses = matcherFor(compiled, compiled.keys[0], { path: request.path, ...(body === undefined ? {} : { body }) }).echoLoose;
  return compiled.values.filter(v => looses.some(text => text.includes(v.loose)));
}
// A route's parts, each marked as a path segment ("/"), a query parameter's name ("?") or its value ("=") and decoded; the
// mark is never part of the decoded text, so an encoded "?" in a segment stays a segment and a query flag is never a value.
// partText is a part without its mark. In a route shape, a part that is a declared value (of any tenant, whole and exact)
// reads as {v}.
const routeParts = path => { const [route, query = ''] = path.split(/\?(.*)/s); return [...route.split('/').map(p => `/${decoded(p)}`), ...(query ? query.split('&').flatMap(p => { const at = p.indexOf('='); return at < 0 ? [`?${decoded(p)}`] : [`?${decoded(p.slice(0, at))}`, `=${decoded(p.slice(at + 1))}`]; }) : [])]; };
const partText = part => part.slice(1);
const routeShape = (method, path, declared) => `${method} ${routeParts(path).map(part => part[0] + (declared.has(partText(part).trim()) ? '{v}' : partText(part))).join('\u0000')}`;
const canonical = value => JSON.stringify(value, (_key, v) => plain(v) ? Object.fromEntries(Object.keys(v).sort().map(k => [k, v[k]])) : v);
const requestOf = check => ({ method: check.method, path: check.path, ...(Object.hasOwn(check, 'body') ? { body: check.body } : {}), assertions: check.assertions, ...(Object.hasOwn(check, 'effects') ? { effects: check.effects } : {}) });
// A check's expected statuses (its status.equals or status.in), and the request alone (method, path, body).
const statusesOf = check => { const s = check.assertions.find(a => STATUS_KINDS.includes(a.kind)); return !s ? [] : s.kind === 'status.equals' ? [s.expected] : [...s.expected]; };
const successes = statuses => statuses.length > 0 && statuses.every(s => s >= 200 && s <= 299);
const requestKey = check => canonical({ method: check.method, path: check.path, ...(Object.hasOwn(check, 'body') ? { body: check.body } : {}) });

// For each boundary check of the target, its generated mirror or the reason it has none (a validated target).
export function mirrorPlan(target, identityPlan) {
  const coverage = identityCoverage(target, identityPlan), plan = [];
  if (!coverage.tenantScoped) return { schema: MIRROR_SCHEMA, coverage, plan };
  const sources = target.checks.filter(check => check.severity !== 'control' && !Object.hasOwn(check, 'mirrorOf'));
  // Mirrors are opt-in: a target that declares no "mirrors" object runs exactly its declared checks. Such a target, and one
  // that sets them off or declares a lifecycle or a timing plan, returns here, before anything below is computed.
  const skipAll = !Object.hasOwn(target, 'mirrors') ? 'mirrors-undeclared' : target.mirrors === 'off' ? 'mirrors-off' : Object.hasOwn(target, 'lifecycle') ? 'lifecycle-declared' : Object.hasOwn(target, 'timing') ? 'timing-declared' : null;
  if (skipAll) return { schema: MIRROR_SCHEMA, coverage, plan: sources.map(check => ({ checkId: check.id, reason: skipAll })) };
  const compiled = compileTenantValues(target.tenantValues), keys = compiled.keys, owner = ownerOf(target.tenantValues);
  // An identity's own allowed twin of a request: an applicable success of that identity with the same method and the same
  // route part for part, holding, wherever the request holds another tenant's value of the swapped pairs, that value's
  // counterpart (so the twin names the identity's own records, in the same relation to each other as the request's).
  const twinShown = (who, method, path, tenant, swapped) => {
    const want = routeParts(path).map(p => { const text = partText(p).trim(); return swapped.has(text) && owner.get(text) !== tenant ? `${p[0]}${swapped.get(text)}` : p; }).join('\u0000');
    return (shown.get(who) ?? []).some(c => c.success && c.method === method && c.parts.join('\u0000') === want);
  };
  const pairs = plain(target.mirrors) ? target.mirrors.counterparts ?? [] : [], readOnlyRoutes = new Set(plain(target.mirrors) ? target.mirrors.readOnlyRoutes ?? [] : []);
  const ids = new Set(target.checks.map(check => check.id));
  const literals = new Set(compiled.values.flatMap(v => v.literals)), declaredPattern = tokenPattern([...literals]);
  // What each identity's applicable declared checks show (a check that is not applicable shows nothing): the route shape,
  // the expected statuses, the request alone and the request with its assertions.
  const shown = new Map();
  for (const c of target.checks) if (!Object.hasOwn(c, 'mirrorOf') && c.applicability?.applies !== false) {
    if (!shown.has(c.actorId)) shown.set(c.actorId, []);
    const statuses = statusesOf(c);
    shown.get(c.actorId).push({ method: c.method, path: c.path, parts: routeParts(c.path), shape: routeShape(c.method, c.path, literals), statuses, success: successes(statuses), request: requestKey(c), whole: canonical(requestOf(c)) });
  }
  // The declared values a request names: each whole token in any letter case in a path or query part (inside a longer part too,
  // such as ORD-2002.json or ORD-2002:archive) or in a body string or key, and each body number written as a declared value
  // (String(n)). Each reading only removes mirrors.
  const foldPattern = tokenPattern([...literals], 'giu'), folded = new Map();
  for (const l of literals) folded.set(l.toLowerCase(), [...(folded.get(l.toLowerCase()) ?? []), l]);
  const numbersOf = (value, out = []) => { if (typeof value === 'number') out.push(String(value)); else if (Array.isArray(value)) value.forEach(v => numbersOf(v, out)); else if (plain(value)) Object.values(value).forEach(v => numbersOf(v, out)); return out; };
  const namedValues = c => { if (!foldPattern) return []; const texts = [...routeParts(c.path).map(partText), ...(Object.hasOwn(c, 'body') ? [...leaves(c.body).values, ...leaves(c.body).keys] : [])];
    // Exact matches and case-folded ones both: a longer declared value that folds over a shorter one never hides it.
    return [...texts.flatMap(v => v.match(declaredPattern) ?? []), ...texts.flatMap(v => v.match(foldPattern) ?? []).flatMap(m => folded.get(m.toLowerCase()) ?? []),
      ...(Object.hasOwn(c, 'body') ? numbersOf(c.body).filter(n => literals.has(n)) : [])]; };
  // The declared values a declared write may change: those an applicable non-GET check that expects a success or a redirect
  // names (a POST on a declared read-only route aside). A write that reaches a record without naming it (an assistant told to
  // act on "my latest order", a cascade) is not seen: the counterparts are declared as records no declared check changes.
  const written = new Set(target.checks.filter(c => !Object.hasOwn(c, 'mirrorOf') && c.applicability?.applies !== false && c.method !== 'GET'
    && statusesOf(c).some(s => s >= 200 && s <= 399) && !(c.method === 'POST' && readOnlyRoutes.has(`POST ${c.path.split('?')[0]}`))).flatMap(namedValues));
  const sameRefusals = (a, b) => (a.refusesWith401 ?? null) === (b.refusesWith401 ?? null) && (a.signInRedirectStatus ?? null) === (b.signInRedirectStatus ?? null);
  for (const check of sources) {
    const skip = reason => plan.push({ checkId: check.id, reason });
    if (check.applicability?.applies === false) { skip('not-applicable'); continue; }
    const actor = target.actors[check.actorId];
    const own = coverage.identities.find(i => i.actor === check.actorId);
    if (!own) { skip('actor-not-tenant-identity'); continue; }
    if (typeof actor.role !== 'string') { skip('role-undeclared'); continue; }
    const candidates = coverage.identities.filter(i => i.tenant !== own.tenant && target.actors[i.actor].role === actor.role && sameRefusals(actor, target.actors[i.actor]));
    const namedTenants = new Set(seenValues(compiled, { path: check.path, ...(Object.hasOwn(check, 'body') ? { body: check.body } : {}) }).filter(v => v.owners.length === 1).map(v => keys[v.owners[0] - 1]));
    const second = candidates.find(i => namedTenants.has(i.tenant)) ?? candidates[0];
    if (!second) { skip('no-second-identity'); continue; }
    const other = target.actors[second.actor];
    const uses = /\{\{[A-Za-z][A-Za-z0-9_]{0,31}\}\}/.test([check.path, ...leaves(check.body ?? null).values].join('\n'));
    const blocked = Object.hasOwn(check, 'capture') || uses ? 'uses-capture' : Object.hasOwn(check, 'precondition') ? 'uses-precondition' : Object.hasOwn(check, 'restsOn') ? 'uses-rests-on'
      : Object.hasOwn(check, 'webhook') ? 'uses-webhook' : Object.hasOwn(check, 'claims') ? 'uses-claims' : Object.hasOwn(check, 'effects') ? 'uses-effects' : Object.hasOwn(check, 'readBack') ? 'uses-read-back' : null;
    if (blocked) { skip(blocked); continue; }
    const predicates = check.assertions.filter(a => !STATUS_KINDS.includes(a.kind));
    // Every text the check names: the decoded path and query parts, the body's keys and values, the predicates' pointers and
    // expected texts.
    const body = Object.hasOwn(check, 'body') ? leaves(check.body) : { values: [], keys: [], numbers: 0 };
    const texts = [...routeParts(check.path).map(partText), ...body.keys, ...body.values.flatMap(v => [v, decoded(v)]), ...predicates.flatMap(a => [a.pointer ?? '', ...(typeof a.expected === 'string' ? [a.expected] : [])])];
    // Either identity's names, in any letter case, outside the declared values (a declared address can hold a tenant id): a
    // short one (under three characters) only as a whole text.
    const names = [check.actorId, actor.principalId, actor.identityValue, actor.tenantId, second.actor, other.principalId, other.identityValue, other.tenantId].filter(n => typeof n === 'string' && n.length);
    const long = tokenPattern(names.filter(n => n.length >= 3), 'iu'), short = new Set(names.filter(n => n.length < 3).map(n => n.toLowerCase()));
    const outside = t => (declaredPattern ? t.replace(declaredPattern, ' ') : t);
    if (texts.map(outside).some(t => (long && long.test(t)) || short.has(t.trim().toLowerCase()))) { skip('names-an-identity'); continue; }
    // The swap: each counterpart between the two tenants, both ways, whole and exact; the residue has them removed.
    const tenantA = keys.indexOf(own.tenant) + 1, tenantB = keys.indexOf(second.tenant) + 1;
    const swap = new Map();
    for (const [a, b] of pairs) if ([owner.get(a), owner.get(b)].sort().join('\u0000') === [own.tenant, second.tenant].sort().join('\u0000')) { swap.set(a, b); swap.set(b, a); }
    const pattern = tokenPattern([...swap.keys()]);
    const swapText = text => pattern ? text.replace(pattern, found => swap.get(found)) : text;
    const residue = text => pattern ? text.replace(pattern, ' ') : text;
    const either = v => v.owners.includes(tenantA) || v.owners.includes(tenantB);
    const left = seenValues(compiled, { path: residue(check.path), body: mapStrings([check.body ?? null, ...predicates.map(a => ({ pointer: a.pointer ?? '', expected: a.expected ?? null }))], residue) }).filter(either);
    if (left.length) { skip(left.some(v => v.owners.length > 1) ? 'tenant-value-shared' : left.some(v => !v.literals.some(l => swap.has(l))) ? 'tenant-value-without-counterpart' : 'tenant-value-variant'); continue; }
    // An identifier the profile did not declare: a path segment or query part holding a digit (an API version aside), a JSON
    // number or a one-word string that is not a declared value in the body, and, where a refusal is expected, a word holding
    // a digit in the body's text (every declared value of any tenant set aside).
    const status = check.assertions.find(a => STATUS_KINDS.includes(a.kind)), statuses = statusesOf(check);
    const succeeds = successes(statuses), refuses = !succeeds;
    const answer = predicates.length > 0 && predicates.every(a => a.kind === FOREIGN_VALUES_KIND) && status?.kind === 'status.equals' && succeeds;
    const scrub = text => (declaredPattern ? text.replace(declaredPattern, ' ') : text).trim();
    if (routeParts(check.path).map(partText).some(part => /\d/.test(scrub(part)) && !/^v\d+$/i.test(part.trim()))
      || body.numbers > 0 || body.values.some(v => { const s = scrub(v); return s.length > 0 && (!/\s/.test(v.trim()) || (!answer && /\d/.test(s))); })) { skip('undeclared-identifier'); continue; }
    // In a success, json.equals and json.exists describe the first identity's records (a swapped value there assumes the pairs
    // also match each other's relations); json.notContains of a swapped value stays.
    if (predicates.some(a => ((a.kind === 'json.equals' || a.kind === 'json.notContains') && !(typeof a.expected === 'string' && swap.has(a.expected))) || ((a.kind === 'json.exists' || a.kind === 'json.equals') && succeeds))) { skip('predicate-names-own-view'); continue; }
    // A request naming no declared value of either tenant is mirrored only as an answer probe.
    const named = seenValues(compiled, { path: check.path, ...(Object.hasOwn(check, 'body') ? { body: check.body } : {}) }).filter(v => v.owners.length === 1 && either(v));
    if (!named.length && !answer) { skip('resource-owner-unknown'); continue; }
    // The direction: a refusal only across the boundary, and never a write the application might allow; a success only on
    // the first tenant's own values or as an answer probe, and only as a read.
    const foreign = named.some(v => v.owners[0] === tenantB);
    if (refuses) {
      const boundaryStatuses = [401, 403, 404, ...(typeof actor.signInRedirectStatus === 'number' ? [actor.signInRedirectStatus] : [])];
      if (statuses.some(s => !boundaryStatuses.includes(s))) { skip('refusal-not-boundary-status'); continue; }
      if (!foreign) { skip('own-record-refusal'); continue; }
      // A refused read only: a refused write the application might accept is never sent on a guess.
      if (check.method !== 'GET') { skip('refusal-not-a-read'); continue; }
      // The first identity's own allowed twin on the same route: then the declared value is the only difference between the
      // allowed request and the refused one, so the refusal turns on it (not on a workspace, a search term or an invitee).
      if (!twinShown(check.actorId, check.method, check.path, own.tenant, swap)) { skip('refusal-twin-not-shown'); continue; }
    } else {
      if (foreign && !answer) { skip('foreign-record-success'); continue; }
      // A read: a GET, or a POST answer probe answered 200 on a route the profile declares read-only.
      const readOnly = check.method === 'POST' && answer && statuses[0] === 200 && readOnlyRoutes.has(`POST ${check.path.split('?')[0]}`);
      if (check.method !== 'GET' && !readOnly) { skip('success-not-a-read'); continue; }
    }
    const suffix = ` (mirror under ${second.actor})`, title = check.title.length + suffix.length <= 200 ? `${check.title}${suffix}` : `${check.title.slice(0, 200 - suffix.length)}${suffix}`;
    const id = `${check.id}${MIRROR_SUFFIX}`;
    const mirror = { ...check, id, title, actorId: second.actor, path: swapText(check.path),
      ...(Object.hasOwn(check, 'body') ? { body: mapStrings(check.body, swapText) } : {}),
      assertions: check.assertions.map(a => ({ ...a, ...(typeof a.pointer === 'string' ? { pointer: swapText(a.pointer) } : {}), ...(typeof a.expected === 'string' ? { expected: swapText(a.expected) } : {}) })), mirrorOf: check.id };
    // The route must be one the second identity's own applicable checks are shown on, in the mirror's direction, and no
    // declared check of the second identity may expect other statuses for the same request.
    const theirs = shown.get(second.actor) ?? [], shape = routeShape(mirror.method, mirror.path, literals), request = requestKey(mirror);
    if (theirs.some(c => c.request === request && !c.statuses.some(s => statuses.includes(s)))) { skip('contradicts-second-identity-check'); continue; }
    // No declared write changes a record the mirror names: mirrors run after every declared check, so a counterpart written
    // (or deleted) by then is no longer in the state the pair declares.
    if ([...namedValues(check), ...namedValues(mirror)].some(v => written.has(v))) { skip('counterpart-written'); continue; }
    // A refusal needs the second identity's own allowed twin on the mirror's route (both identities shown allowed there with
    // their own values, so a symmetric application refuses the mirror for the source's reason, with its status); a success a
    // check of the second identity that expects a success within the mirror's statuses, on exactly the mirror's path for a
    // GET (that very record, so its state is shown), on the route for a read-only POST.
    const fits = c => c.success && c.statuses.every(s => statuses.includes(s)) && (mirror.method === 'GET' ? c.method === 'GET' && c.path === mirror.path : c.shape === shape);
    if (refuses ? !twinShown(second.actor, mirror.method, mirror.path, second.tenant, swap) : !theirs.some(fits)) { skip('route-not-used-by-second-identity'); continue; }
    // The second identity already declares this check (the profile tests both sides by hand).
    if (theirs.some(c => c.whole === canonical(requestOf(mirror)))) { skip('already-declared'); continue; }
    if (id.length > 80 || (ids.has(id) && !target.checks.some(c => c.id === id && c.mirrorOf === check.id))) { skip('mirror-id-unavailable'); continue; }
    plan.push({ checkId: check.id, mirror });
  }
  return { schema: MIRROR_SCHEMA, coverage, plan };
}

// The declared checks (every check without "mirrorOf", in their order), then each generated mirror in its source's order. A
// check that declares "mirrorOf" must be exactly the mirror generated from its source, key for key; one that is not (edited,
// stale, or of a source that has none) is refused.
export function mirrorChecks(target, identityPlan) {
  const declared = target.checks.filter(check => Object.hasOwn(check, 'mirrorOf'));
  for (const check of declared) if (typeof check.mirrorOf !== 'string' || UNSAFE_KEYS.includes(check.mirrorOf)) bad(`check "${check.id}": "mirrorOf" must name a check`);
  const { plan } = mirrorPlan(target, identityPlan), generated = new Map(plan.filter(p => p.mirror).map(p => [p.checkId, p.mirror]));
  for (const check of declared) {
    const expected = generated.get(check.mirrorOf);
    if (!expected || canonical(expected) !== canonical(check)) bad(`check "${check.id}": a check that declares "mirrorOf" must be exactly the mirror ScopeHaven generates from it; remove it (mirrors are generated from the target's "mirrors" declaration, and a target without one gets none)`);
  }
  return { declared: target.checks.filter(check => !Object.hasOwn(check, 'mirrorOf')), mirrors: [...generated.values()] };
}

// The value-free summary check-config prints for a tenant-scoped target: the coverage, the mirrors by check id, and the extra
// requests each identity sends because of them in the mirror phase (each mirror, a probe point of that identity's identity and
// surface controls before its first mirror and after each of them), the headroom that keeps its mirrors decided under a
// per-user rate or question limit. A generated mirror the profile does not hold was left out because it would break a profile
// rule (profile-rule).
export function mirrorReport(target, identityPlan) {
  const { coverage, plan } = mirrorPlan(target, identityPlan);
  const present = new Set(target.checks.filter(c => Object.hasOwn(c, 'mirrorOf')).map(c => c.mirrorOf));
  const held = target.checks.filter(c => Object.hasOwn(c, 'mirrorOf')), byActor = new Map();
  for (const c of held) byActor.set(c.actorId, (byActor.get(c.actorId) ?? 0) + 1);
  // Each mirror adds its request, and the mirror phase one more probe point than the identity has mirrors (src/contracts.mjs
  // identityPlanShape, which the request bound counts the same way).
  const extraRequests = [...byActor].sort(([a], [b]) => (a < b ? -1 : 1)).map(([actorId, mirrors]) => {
    const p = identityPlan.get(actorId), controls = p?.identityControls.length ? p.identityControls.length + p.surfaceControls.length : 0;
    return { actorId, mirrors, requests: mirrors + (mirrors + 1) * controls }; });
  return { tenantScoped: coverage.tenantScoped, identities: coverage.identities.map(i => i.actor), distinctTenants: coverage.tenants, singleIdentity: coverage.singleIdentity, extraRequests,
    mirrored: plan.filter(p => p.mirror && present.has(p.checkId)).map(p => ({ checkId: p.checkId, mirrorId: p.mirror.id, actorId: p.mirror.actorId })),
    notMirrored: plan.filter(p => p.reason || !present.has(p.checkId)).map(p => ({ checkId: p.checkId, reason: p.reason ?? 'profile-rule' })) };
}
