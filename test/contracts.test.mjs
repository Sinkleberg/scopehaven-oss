import test from 'node:test';
import assert from 'node:assert/strict';
import { ASSERTION_SCHEMA_VERSION, validateTargetFile, evaluateHttpCheck, contractDigest, statusLabel } from '../src/contracts.mjs';

function profile() {
  return { schemaVersion: 1, targets: [{ id: 'lab', name: 'Owned lab', applicationId: 'local-app', origin: 'http://127.0.0.1:5001/', buildLabel: 'baseline', contextId: 'synthetic-context', actors: { member: { credentialEnv: 'SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN', principalId: 'member-1', tenantId: 'one', role: 'member' }, anonymous: { principalId: 'anonymous' } }, requiredControlIds: ['allowed'], checks: [
    { id: 'allowed', title: 'Permitted record', category: 'Access', severity: 'control', actorId: 'member', method: 'GET', path: '/records/own', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.exists', pointer: '/record', expected: true }] },
    { id: 'denied', title: 'Forbidden record', category: 'Access', severity: 'high', actorId: 'anonymous', method: 'POST', path: '/records/foreign', body: { query: 'synthetic' }, evidenceRequirement: 'backend', assertions: [{ kind: 'status.equals', expected: 403 }, { kind: 'json.notContains', pointer: '/reply', expected: 'private-marker' }] },
  ] }] };
}
const observed = json => ({ status: 200, complete: true, jsonParsed: true, json, bytes: 100 });
function check(assertions, evidenceRequirement = 'response') {
  return { ...profile().targets[0].checks[0], evidenceRequirement, assertions: [{ kind: 'status.equals', expected: 200 }, ...assertions] };
}
function reject(mutator) { const input = profile(); mutator(input, input.targets[0]); assert.throws(() => validateTargetFile(input), /^Error: Invalid HTTP contract:/); }

test('valid bounded manifest normalizes origins and preserves explicit anonymous actors', () => {
  const input = profile(), targets = validateTargetFile(input);
  assert.equal(ASSERTION_SCHEMA_VERSION, 'http-contract/4');
  assert.equal(targets[0].origin, 'http://127.0.0.1:5001');
  assert.equal(targets[0].actors.anonymous.credentialEnv, undefined);
  targets[0].checks[0].title = 'Changed returned copy';
  assert.equal(input.targets[0].checks[0].title, 'Permitted record');
  input.targets[0].origin = 'http://127.0.0.1:80/';
  assert.equal(validateTargetFile(input)[0].origin, 'http://127.0.0.1:80');
});

test('unknown fields, invalid identity, duplicate IDs and unresolved actors are rejected safely', () => {
  for (const mutate of [
    input => { input.extra = 'secret-marker'; },
    (_, target) => { target.headers = { Authorization: 'secret-marker' }; },
    (_, target) => { target.actors.member.token = 'secret-marker'; },
    (_, target) => { target.checks[0].headers = {}; },
    (_, target) => { target.checks[0].assertions[0].extra = true; },
    (_, target) => { target.checks[0].actorId = 'unknown'; },
    (_, target) => { target.id = 'bad identity'; },
    (_, target) => { target.actors.member.credentialEnv = 'literal-secret!'; },
    (_, target) => { target.actors.member.principalId = 'unbounded principal identity'; },
    (_, target) => { target.actors.member.tenantId = 'x'.repeat(81); },
    (input, target) => { input.targets.push(structuredClone(target)); },
    (_, target) => { target.checks.push(structuredClone(target.checks[0])); },
  ]) reject(mutate);
  const secret = profile(); secret.targets[0].origin = 'https://secret-marker:secret-password@example.test';
  try { validateTargetFile(secret); assert.fail('Expected rejection'); } catch (error) { assert.doesNotMatch(error.message, /secret-marker|secret-password|example/); }
  const hostile = profile();
  Object.defineProperty(hostile.targets[0], 'origin', { enumerable: true, get() { throw new Error('Invalid HTTP contract: secret-getter-value'); } });
  assert.throws(() => validateTargetFile(hostile), error => !error.message.includes('secret-getter-value'));
});

test('only a literal HTTP loopback origin with a bounded nonzero port is accepted', () => {
  for (const origin of ['http://localhost:5001', 'http://127.1:5001', 'http://2130706433:5001', 'http://[::1]:5001', 'https://127.0.0.1:5001', 'http://127.0.0.1', 'http://127.0.0.1:0', 'http://127.0.0.1:65536', 'http://user@127.0.0.1:5001', 'http://127.0.0.1:5001/path', 'http://127.0.0.1:5001?x=1', 'http://127.0.0.1:5001#hash']) reject((_, target) => { target.origin = origin; });
});

test('fixed paths reject traversal, ambiguous separators, fragments and excessive bounds', () => {
  for (const path of ['//evil.test', '/x/../secret', '/./secret', '/%2e%2e/secret', '/%252e%252e/secret', '/x\\secret', '/x%5csecret', '/x%2f%2fsecret', '/x#fragment', '/x%zz', '/x\nHeader', `/${'x'.repeat(2048)}`]) reject((_, target) => { target.checks[0].path = path; });
  const input = profile(); input.targets[0].checks[0].path = '/records?fixed=one';
  assert.equal(validateTargetFile(input)[0].checks[0].path, '/records?fixed=one');
});

test('JSON request bodies obey method, shape, byte, depth and node limits', () => {
  reject((_, target) => { target.checks[0].body = {}; });
  for (const value of [[], null, 'raw body', { n: Infinity }, { data: 'x'.repeat(8192) }, { data: 'é'.repeat(5000) }, { data: Array.from({ length: 1001 }, () => 1) }]) reject((_, target) => { target.checks[1].body = value; });
  reject((_, target) => { let value = {}; for (let i = 0; i < 13; i++) value = { nested: value }; target.checks[1].body = value; });
  reject((_, target) => { target.checks[1].body = JSON.parse('{"__proto__":{"leak":true}}'); });
});

test('assertions and required permitted-use controls cannot be omitted or made ambiguous', () => {
  for (const mutate of [
    (_, target) => { target.requiredControlIds = []; },
    (_, target) => { target.requiredControlIds = ['allowed', 'allowed']; },
    (_, target) => { target.requiredControlIds = ['unknown']; },
    (_, target) => { target.requiredControlIds = ['denied']; },
    (_, target) => { target.checks[0].evidenceRequirement = 'backend'; },
    (_, target) => { target.checks[0].assertions = []; },
    (_, target) => { target.checks[0].assertions = [{ kind: 'json.exists', pointer: '/x', expected: true }]; },
    (_, target) => { target.checks[0].assertions.push({ kind: 'status.equals', expected: 200 }); },
    (_, target) => { target.checks[0].assertions[0].expected = 600; },
    (_, target) => { target.checks[0].assertions[0].expected = 200.5; },
    (_, target) => { target.checks[0].assertions.push({ kind: 'json.equals', pointer: '/x', expected: {} }); },
    (_, target) => { target.checks[0].assertions.push({ kind: 'json.notContains', pointer: '/x', expected: '' }); },
  ]) reject(mutate);
  for (const pointer of ['x', '/bad~2escape', '/constructor/x', '/__proto__', '/prototype', `/${'x'.repeat(512)}`]) reject((_, target) => { target.checks[0].assertions[1].pointer = pointer; });
});

test('expected 401 and 403 are valid observable response contracts', () => {
  for (const status of [401, 403]) {
    const result = evaluateHttpCheck(check([]), { ...observed({}), status });
    assert.equal(result.status, 'fail');
    const matched = evaluateHttpCheck({ ...check([]), assertions: [{ kind: 'status.equals', expected: status }] }, { ...observed({}), status });
    assert.equal(matched.status, 'pass');
    assert.match(matched.summary, /backend effects remain unverified/);
  }
});

test('complete empty or non-JSON responses satisfy status-only contracts while JSON predicates remain unknown', () => {
  for (const status of [204, 403]) {
    const statusOnly = { ...check([]), assertions: [{ kind: 'status.equals', expected: status }] };
    const response = { status, complete: true, jsonParsed: false, json: undefined, error: 'invalid-json', bytes: status === 204 ? 0 : 12 };
    assert.equal(evaluateHttpCheck(statusOnly, response).status, 'pass');
    const jsonRequired = { ...statusOnly, assertions: [...statusOnly.assertions, { kind: 'json.exists', pointer: '/record', expected: false }] };
    assert.equal(evaluateHttpCheck(jsonRequired, response).status, 'inconclusive');
    assert.equal(evaluateHttpCheck(statusOnly, { ...response, complete: false, error: 'timeout' }).status, 'error');
    assert.equal(evaluateHttpCheck(statusOnly, { ...response, status: 500 }).status, 'fail');
  }
});

test('RFC6901 lookup distinguishes absent from null, false, zero, and own properties', () => {
  for (const value of [null, false, 0, '']) {
    assert.equal(evaluateHttpCheck(check([{ kind: 'json.exists', pointer: '/value', expected: true }]), observed({ value })).status, 'pass');
  }
  assert.equal(evaluateHttpCheck(check([{ kind: 'json.exists', pointer: '/value', expected: false }]), observed({})).status, 'pass');
  assert.equal(evaluateHttpCheck(check([{ kind: 'json.equals', pointer: '/value', expected: null }]), observed({})).status, 'fail');
  assert.equal(evaluateHttpCheck(check([{ kind: 'json.exists', pointer: '/value', expected: false }]), observed(Object.create({ value: 'inherited' }))).status, 'pass');
  assert.equal(evaluateHttpCheck(check([{ kind: 'json.equals', pointer: '/a~1b/~0key/0', expected: 0 }]), observed({ 'a/b': { '~key': [0] } })).status, 'pass');
  assert.equal(evaluateHttpCheck(check([{ kind: 'json.equals', pointer: '', expected: null }]), observed(null)).status, 'pass');
});

test('missing or wrong-type notContains evidence is inconclusive rather than a false green', () => {
  const predicate = check([{ kind: 'json.notContains', pointer: '/reply', expected: 'secret-marker' }]);
  for (const json of [{}, { reply: null }, { reply: false }, { reply: 0 }, { reply: [] }, { reply: {} }]) assert.equal(evaluateHttpCheck(predicate, observed(json)).status, 'inconclusive');
  assert.equal(evaluateHttpCheck(predicate, observed({ reply: 'ordinary response' })).status, 'pass');
  assert.equal(evaluateHttpCheck(predicate, observed({ reply: 'contains secret-marker' })).status, 'fail');
  assert.equal(evaluateHttpCheck(predicate, { ...observed({ reply: 'ordinary' }), jsonParsed: false }).status, 'inconclusive');
});

test('backend evidence remains unknown and confirmed response failures take precedence', () => {
  const backend = check([{ kind: 'json.exists', pointer: '/record', expected: true }], 'backend');
  const unknown = evaluateHttpCheck(backend, observed({ record: 'present' }));
  assert.equal(unknown.status, 'inconclusive');
  assert.equal(unknown.assertions.at(-1).status, 'inconclusive');
  assert.equal(evaluateHttpCheck(backend, observed({})).status, 'fail');
  const failedPartial = evaluateHttpCheck(backend, { status: 403, complete: false, jsonParsed: false, error: 'timeout', bytes: 0 });
  assert.equal(failedPartial.status, 'fail');
  for (const error of ['timeout', 'too-large', 'network', 'invalid-json']) assert.equal(evaluateHttpCheck(backend, { status: 200, complete: false, jsonParsed: false, error, bytes: 0 }).status, 'error');
  assert.equal(evaluateHttpCheck(backend, { status: null, complete: false, jsonParsed: false, bytes: 0 }).status, 'error');
});

test('persisted evaluations never expose raw JSON or configured expected string values', () => {
  const secret = 'response-secret-123', marker = 'configured-sensitive-marker';
  const result = evaluateHttpCheck(check([{ kind: 'json.equals', pointer: '/secret', expected: marker }, { kind: 'json.notContains', pointer: '/secret', expected: marker }]), observed({ secret, nested: { credential: 'Bearer echoed-credential' } }));
  const serialized = JSON.stringify(result);
  assert.doesNotMatch(serialized, /response-secret-123|configured-sensitive-marker|echoed-credential|Bearer/);
  assert.equal(result.observed.predicates[0].type, 'string');
  assert.equal(result.status, 'fail');
});

test('semantic digest changes for contract boundaries but ignores build and display metadata or resolved credentials', () => {
  const target = validateTargetFile(profile())[0];
  const baseline = contractDigest(target);
  assert.match(baseline, /^[0-9a-f]{64}$/);
  assert.equal(contractDigest({ ...target, name: 'Different label', buildLabel: 'repaired', resolvedSecrets: { token: 'actual-secret' }, actors: { ...target.actors, member: { ...target.actors.member, token: 'another-secret' } } }), baseline);
  for (const mutate of [
    t => { t.origin = 'http://127.0.0.1:5002'; },
    t => { t.applicationId = 'other-app'; },
    t => { t.contextId = 'other-data'; },
    t => { t.actors.member.credentialEnv = 'SCOPEHAVEN_TARGET_OTHER_TOKEN'; },
    t => { t.actors.member.principalId = 'other-principal'; },
    t => { t.checks[0].assertions[0].expected = 201; },
    t => { t.checks[1].evidenceRequirement = 'response'; },
  ]) { const changed = structuredClone(target); mutate(changed); assert.notEqual(contractDigest(changed), baseline); }
});

const message = mutator => { const input = profile(); mutator(input, input.targets[0]); try { validateTargetFile(input); } catch (error) { return error.message; } assert.fail('Expected rejection'); };

test('existing profiles validate unchanged; the new optional fields are never injected', () => {
  const [target] = validateTargetFile(profile());
  for (const check of target.checks) { assert.equal(Object.hasOwn(check, 'timeoutMs'), false); assert.equal(check.assertions.some(a => a.kind === 'status.in'), false); }
  for (const actor of Object.values(target.actors)) assert.equal(Object.hasOwn(actor, 'credentialCookie'), false);
});

test('validation errors name the target, check, assertion and field without echoing configured values', () => {
  const exists = message((_, target) => { delete target.checks[0].assertions[1].expected; });
  assert.match(exists, /^Invalid HTTP contract: target "lab" > check "allowed" > assertion 2 \(json\.exists\): .*missing field "expected".*json\.exists needs "expected": true or false/);
  const header = message((_, target) => { target.checks[1].headers = { Authorization: 'secret-marker' }; });
  assert.match(header, /target "lab" > check "denied": .*unsupported field "headers"/); assert.doesNotMatch(header, /secret-marker/);
  const tokenKey = message((_, target) => { target.actors.member['sk-live.secret-marker'] = true; });
  assert.match(tokenKey, /actor "member": .*an unnamed field/); assert.doesNotMatch(tokenKey, /secret-marker|sk-live/);
  assert.match(message((_, target) => { target.checks[0].id = 'bad id with spaces'; }), /target "lab" > check 1: invalid or duplicate check identity/);
  assert.match(message((_, target) => { target.checks[1].method = 'TRACE'; }), /check "denied": .*"method" must be GET, POST, PUT, PATCH or DELETE/);
  assert.match(message((_, target) => { target.checks[0].path = '/x/../y'; }), /check "allowed" > "path": unsafe request path/);
  assert.match(message((_, target) => { target.requiredControlIds = ['denied']; }), /"requiredControlIds": invalid required control "denied"/);
  assert.match(message(input => { input.targets[0].id = 'x y'; }), /^Invalid HTTP contract: target 1: invalid target identity/);
});

test('status.in accepts a refusal set for boundaries only and evaluates membership', () => {
  const input = profile(); input.targets[0].checks[1].assertions[0] = { kind: 'status.in', expected: [401, 403, 404] };
  const [target] = validateTargetFile(input), denied = target.checks[1];
  const response = status => ({ status, complete: true, jsonParsed: true, json: { reply: 'ordinary' }, bytes: 20 });
  assert.equal(evaluateHttpCheck({ ...denied, evidenceRequirement: 'response' }, response(404)).status, 'pass');
  assert.equal(evaluateHttpCheck({ ...denied, evidenceRequirement: 'response' }, response(200)).status, 'fail');
  assert.equal(evaluateHttpCheck({ ...denied, evidenceRequirement: 'response' }, { status: null, complete: false, jsonParsed: false, error: 'timeout', bytes: 0 }).status, 'error');
  assert.equal(evaluateHttpCheck(denied, response(403)).assertions[0].expected, 'HTTP 401, 403 or 404');
  assert.equal(statusLabel([403]), 'HTTP 403'); assert.equal(statusLabel([302, 401]), 'HTTP 302 or 401');
  assert.notEqual(contractDigest(target), contractDigest(validateTargetFile(profile())[0]));
  for (const expected of [[401], [401, 403, 404, 405, 409, 410], [401, 401], [200, 403], [204, 403], [403, 600], ['401', 403], 403]) reject((_, t) => { t.checks[1].assertions[0] = { kind: 'status.in', expected }; });
  reject((_, t) => { t.checks[1].assertions.push({ kind: 'status.in', expected: [401, 403] }); });
  assert.match(message((_, t) => { t.checks[0].assertions[0] = { kind: 'status.in', expected: [200, 304] }; }), /status\.in needs/);
  assert.match(message((_, t) => { t.checks[0].assertions[0] = { kind: 'status.in', expected: [301, 302] }; }), /allowed-use controls need one exact status/);
});

test('per-check timeoutMs is bounded per check and per profile', () => {
  for (const timeoutMs of [1000, 30000, 120000]) { const input = profile(); input.targets[0].checks[1].timeoutMs = timeoutMs; assert.equal(validateTargetFile(input)[0].checks[1].timeoutMs, timeoutMs); }
  for (const timeoutMs of [999, 120001, 1500.5, '30000', null]) assert.match(message((_, t) => { t.checks[1].timeoutMs = timeoutMs; }), /check "denied": "timeoutMs" must be an integer from 1000 to 120000/);
  const many = profile(), template = many.targets[0].checks[1];
  many.targets[0].checks.push(...Array.from({ length: 6 }, (_, i) => ({ ...structuredClone(template), id: `slow-${i}`, timeoutMs: 120000 })));
  assert.throws(() => validateTargetFile(many), /exceed 600000 ms in total/);
  const changed = profile(); changed.targets[0].checks[1].timeoutMs = 30000;
  assert.notEqual(contractDigest(validateTargetFile(changed)[0]), contractDigest(validateTargetFile(profile())[0]));
});

test('credentialCookie needs a credential reference and an RFC 6265 cookie name, and changes the contract digest', () => {
  const input = profile(); input.targets[0].actors.member.credentialCookie = '__Secure-authjs.session-token';
  const [target] = validateTargetFile(input);
  assert.equal(target.actors.member.credentialCookie, '__Secure-authjs.session-token');
  assert.notEqual(contractDigest(target), contractDigest(validateTargetFile(profile())[0]));
  assert.match(message((_, t) => { t.actors.anonymous.credentialCookie = 'session'; }), /actor "anonymous": "credentialCookie" needs a "credentialEnv" reference/);
  for (const name of ['', 'a;b', 'a=b', 'a b', 'a,b', 'sessé', 'x'.repeat(129), 7, 'secret-marker;x']) {
    const text = message((_, t) => { t.actors.member.credentialCookie = name; });
    assert.match(text, /"credentialCookie" must be a cookie name/);
    if (typeof name === 'string' && name.length > 2) assert.equal(text.includes(name), false, 'Rejected cookie names are never echoed.');
  }
});

test('an unreadable configuration keeps the contract error prefix and never echoes the failing value', () => {
  const hostile = profile();
  Object.defineProperty(hostile.targets[0], 'name', { enumerable: true, get() { throw new Error('secret-getter-value'); } });
  assert.throws(() => validateTargetFile(hostile), error => error.message === 'Invalid HTTP contract: unreadable configuration.');
});

test('accepted limits: status.in from 300 to 599 with up to five codes, timeoutMs totalling exactly 600000 ms', () => {
  for (const expected of [[300, 599], [300, 401, 403, 404, 599]]) {
    const input = profile(); input.targets[0].checks[1].assertions[0] = { kind: 'status.in', expected };
    assert.deepEqual(validateTargetFile(input)[0].checks[1].assertions[0].expected, expected);
  }
  assert.equal(statusLabel([300, 401, 403, 404, 599]), 'HTTP 300, 401, 403, 404 or 599');
  const exact = profile(), template = exact.targets[0].checks[1];
  exact.targets[0].checks.push(...Array.from({ length: 5 }, (_, i) => ({ ...structuredClone(template), id: `slow-${i}`, timeoutMs: 120000 })));
  assert.equal(validateTargetFile(exact)[0].checks.reduce((total, check) => total + (check.timeoutMs ?? 0), 0), 600000);
});

test('identityValue and signInRedirectStatus are credentialed-actor fields with bounded values', () => {
  const valid = profile(); Object.assign(valid.targets[0].actors.member, { identityValue: 'member-1@example.test', signInRedirectStatus: 307 });
  assert.equal(validateTargetFile(valid)[0].actors.member.signInRedirectStatus, 307);
  assert.match(message((_, t) => { t.actors.anonymous.identityValue = 'anon'; }), /actor "anonymous": "identityValue" needs a "credentialEnv" reference/);
  assert.match(message((_, t) => { t.actors.anonymous.signInRedirectStatus = 302; }), /actor "anonymous": "signInRedirectStatus" needs a "credentialEnv" reference/);
  for (const value of ['', 'x'.repeat(201), 7, 'line\nbreak']) assert.match(message((_, t) => { t.actors.member.identityValue = value; }), /"identityValue" must be a nonempty string up to 200 characters/);
  for (const status of [300, 304, 200, 401, '302']) assert.match(message((_, t) => { t.actors.member.signInRedirectStatus = status; }), /"signInRedirectStatus" must be 301, 302, 303, 307 or 308/);
  const changed = profile(); changed.targets[0].actors.member.identityValue = 'member-1@example.test';
  assert.notEqual(contractDigest(validateTargetFile(changed)[0]), contractDigest(validateTargetFile(profile())[0]), 'The declared identity is part of the contract identity.');
});
