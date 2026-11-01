import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync, existsSync, readdirSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { CONNECTOR_SCHEMA, ConnectorError, listConnectors, readConnector, loadConnector, parseConnector, validateConnector, matchRecord, CATALOG_DIR, DEFAULT_BOUNDS } from './spec.mjs';
import { SETTLE_BOUNDS } from '../../src/http-effects.mjs';

const TEMPLATES = fileURLToPath(new URL('../class-templates/templates/', import.meta.url));
const shipped = async name => JSON.parse(await readFile(join(CATALOG_DIR, `${name}.json`), 'utf8'));
const refuses = (connector, pattern) => assert.throws(() => validateConnector(connector), e => e instanceof ConnectorError && pattern.test(e.message), `expected a refusal matching ${pattern}`);
const edit = (base, change) => { const c = structuredClone(base); change(c); return c; };

test('every shipped connector loads, is named for its stack and carries the sections of its kind', async () => {
  const names = listConnectors();
  assert.deepEqual(names, ['chat-completions', 'stripe', 'supabase']);
  for (const name of names) {
    const c = await readConnector(name);
    assert.equal(c.schema, CONNECTOR_SCHEMA);
    assert.equal(c.stack, name);
    assert.ok(Object.isFrozen(c) && Object.isFrozen(c.observers), 'a loaded connector is frozen');
    if (c.kind === 'http') assert.ok(c.identity && c.refusals && Object.hasOwn(c, 'backendRow'));
    if (c.kind === 'payments') assert.ok(c.payments && c.packs.includes('payments-pack'));
    if (c.kind === 'model') assert.ok(c.model);
  }
});

test('the model connector names class templates that ship and the base-URL variables frameworks read', async () => {
  const c = await readConnector('chat-completions');
  assert.equal(c.model.protocol, 'chat-completions');
  assert.ok(c.model.baseUrlEnv.length >= 1);
  for (const code of c.model.templates) {
    const n = Number(code.slice(3));
    const dir = `t${String(n).padStart(2, '0')}-`;
    if (existsSync(TEMPLATES)) assert.ok(readdirSync(TEMPLATES).some(t => t.startsWith(dir)), `${code} has a template folder`); // the class-template packs are not in the open edition
  }
});

test('the Supabase connector judges row-level security by body, decides the backend row from the WAL, and keeps the gateway key optional', async () => {
  const c = await readConnector('supabase');
  const twoHundred = c.refusals.filter(r => r.status >= 200 && r.status < 300);
  assert.ok(twoHundred.length >= 2 && twoHundred.every(r => r.body !== 'any'), 'every 2xx refusal names its body');
  assert.ok(twoHundred.some(r => r.status === 200 && r.body === 'empty-array'), 'PostgREST 200 []');
  assert.ok(c.refusals.some(r => r.status === 204), 'a filtered write answers 204');
  assert.equal(c.backendRow.observer, 'pg-wal');
  assert.equal(c.observers.find(o => o.type === 'pg-wal').role, 'absence');
  assert.equal(c.observers.find(o => o.type === 'pg-snapshot').role, 'presence');
  assert.deepEqual(c.identity.gatewayHeaders.map(g => [g.header, g.required]), [['apikey', false]]);
  assert.equal(c.identity.whoami[0].path, '/auth/v1/user');
  assert.equal(c.policyImporter.source, 'rls');
});

test('matchRecord names the table, key and id of a PostgREST record path, and nothing else', async () => {
  const c = await readConnector('supabase');
  assert.deepEqual(matchRecord(c, '/rest/v1/profiles?id=eq.a11ce000-0000-4000-8000-000000000001'), { table: 'profiles', key: 'id', id: 'a11ce000-0000-4000-8000-000000000001' });
  assert.deepEqual(matchRecord(c, '/rest/v1/threads?thread_id=eq.7&select=*'), { table: 'threads', key: 'thread_id', id: '7' });
  assert.equal(matchRecord(c, '/api/dashboard/threads/7a1e'), null);
  assert.equal(matchRecord(c, '/rest/v1/profiles?id=eq.1&or=(id.eq.2)'), null, 'an extra filter is not the template');
  assert.equal(matchRecord(c, '/rest/v1/pro;files?id=eq.1'), null, 'a table name is an identifier');
});

test('negative controls: malformed connectors are refused, each for its own reason', async () => {
  const supabase = await shipped('supabase');
  const stripe = await shipped('stripe');
  const model = await shipped('chat-completions');
  refuses(edit(supabase, c => { c.schema = 'scopehaven-connector/2'; }), /schema: must be scopehaven-connector\/1/);
  refuses(edit(supabase, c => { c.extra = true; }), /unknown key "extra"/);
  refuses(edit(supabase, c => { delete c.refusals; }), /needs "refusals"/);
  refuses(edit(supabase, c => { c.payments = stripe.payments; }), /"payments" belongs to a payments connector/);
  refuses(edit(supabase, c => { c.stack = 'Supa base'; }), /stack: must be/);
  // The rule the spec exists for: a 2xx refusal judged by status alone.
  refuses(edit(supabase, c => { c.refusals[0].body = 'any'; }), /2xx refusal must name its body shape/);
  refuses(edit(supabase, c => { c.refusals[3].body = 'empty-array'; }), /non-2xx refusal is judged by its status/);
  refuses(edit(supabase, c => { c.refusals.push(structuredClone(c.refusals[0])); }), /lists one refusal twice/);
  // Identity: a reserved header, a credential header repeated as a gateway header, a 2xx signed-out answer.
  refuses(edit(supabase, c => { c.identity.gatewayHeaders[0].header = 'authorization'; }), /gatewayHeaders\[0\]\.header/);
  refuses(edit(supabase, c => { c.identity.gatewayHeaders[0].header = 'x-forwarded-user'; }), /gatewayHeaders\[0\]\.header/);
  refuses(edit(supabase, c => { c.identity.credential = 'header:apikey'; }), /repeats the credential header/);
  refuses(edit(supabase, c => { c.identity.credential = 'header:cookie'; }), /credential: names a header/);
  refuses(edit(supabase, c => { c.identity.signedOut = [200]; }), /must not answer 2xx/);
  refuses(edit(supabase, c => { c.identity.whoami[0].path = 'auth/v1/user'; }), /absolute app path/);
  refuses(edit(supabase, c => { c.identity.whoami[0].path = '/auth/../user'; }), /absolute app path/);
  // Observers: an unknown type, a wrong source, a subject-writable record deciding an absence, a remote host, init's own fields.
  refuses(edit(supabase, c => { c.observers[0].type = 'pg-trigger'; }), /type: must be one of/);
  refuses(edit(supabase, c => { c.observers[0].source = 'sql-snapshot'; }), /source: is the window source pg-wal writes/);
  refuses(edit(supabase, c => { c.observers[1].role = 'absence'; }), /only an observer held outside the application/);
  refuses(edit(supabase, c => { c.observers[0].defaults.host = 'db.example.com'; }), /host: must be the literal 127\.0\.0\.1/);
  refuses(edit(supabase, c => { c.observers[0].defaults.credentialEnv = 'SCOPEHAVEN_TARGET_X'; }), /may not set "credentialEnv"/);
  refuses(edit(supabase, c => { c.observers.push(structuredClone(c.observers[0])); }), /lists one observer type twice/);
  // Defaults may set only an observer type's connection and timing fields: never what a window may leave out or wait for.
  for (const key of ['ignore', 'queues', 'runLease', 'drainTimeoutMs', 'pollMs', 'actorCapture', 'tables', 'id', 'type']) refuses(edit(supabase, c => { c.observers[0].defaults[key] = key === 'runLease' ? false : ['public']; }), new RegExp(`may not set "${key}" on pg-wal`));
  refuses(edit(supabase, c => { c.observers[2].defaults.port = 2525; }), /may not set "port" on smtp-sink/);
  refuses(edit(supabase, c => { c.observers[0].defaults.platform = 'other'; }), /platform: must be none or supabase/);
  refuses(edit(supabase, c => { c.observers[0].defaults.port = 'abc'; }), /port: must be a TCP port/);
  // Timings within the product's own bounds, so a value the profile check would refuse is refused before init sends anything.
  refuses(edit(supabase, c => { c.observers[0].defaults.settleMs = -1; }), /settleMs: must be an integer from 250 to 30000/);
  refuses(edit(supabase, c => { c.observers[0].defaults.settleMs = 100; }), /settleMs: must be an integer from 250 to 30000/);
  refuses(edit(supabase, c => { c.observers[0].defaults.barrierMs = 50; }), /barrierMs: must be an integer from 100 to 30000/);
  // The loader's bounds are the product's: each one matches the range src/contracts.mjs states for that field, so a later change
  // there fails here instead of drifting.
  const contracts = await readFile(fileURLToPath(new URL('../../src/contracts.mjs', import.meta.url)), 'utf8');
  for (const [key, [min, max]] of Object.entries(DEFAULT_BOUNDS).filter(([key]) => key !== 'settleMs')) assert.ok(contracts.includes(`"${key}" must be an integer from ${min} to ${max}`), `${key} bounds match src/contracts.mjs`);
  assert.deepEqual(DEFAULT_BOUNDS.settleMs, [SETTLE_BOUNDS.minMs, SETTLE_BOUNDS.maxMs]);
  refuses(edit(supabase, c => { c.observers[0].defaults.database = 'x; drop'; }), /database: must be a database name/);
  refuses(edit(supabase, c => { delete c.observers[0].unloggedTables[0].live; }), /is missing "live"/);
  refuses(edit(supabase, c => { c.observers[0].unloggedTables[0].live = 'pg_cron'; }), /live: must be one of pg_net/);
  refuses(edit(supabase, c => { delete c.observers[0].unloggedTables[0].scan; }), /is missing "scan"/);
  refuses(edit(supabase, c => { c.observers[0].unloggedTables[0].scan = ['../other']; }), /scan\[0\]: is a path inside the app folder/);
  refuses(edit(supabase, c => { c.records.templates = [42]; }), /templates\[0\]: must be a path template string/);
  refuses(edit(supabase, c => { c.backendRow.observer = 'pg-snapshot'; }), /role is "absence"/);
  refuses(edit(supabase, c => { c.backendRow.observer = 'mysql-snapshot'; }), /one of the connector's observers/);
  // The backend row is wired as a database observer with a port and its own credential: the egress recorder (absence, but no
  // database) or a database observer without credentialEnvSuffix is refused.
  refuses(edit(supabase, c => { const r = c.observers.find(o => o.type === 'egress-recorder'); r.credentialEnvSuffix = 'EGRESS'; c.backendRow.observer = 'egress-recorder'; }), /database observer with a default host and port and a credentialEnvSuffix/);
  refuses(edit(supabase, c => { delete c.observers.find(o => o.type === 'pg-wal').credentialEnvSuffix; }), /database observer with a default host and port and a credentialEnvSuffix/);
  // The backend row's observer needs its own host too.
  refuses(edit(supabase, c => { delete c.observers.find(o => o.type === 'pg-wal').defaults.host; }), /database observer with a default host and port/);
  // The file half of a live check is pinned too: every string it scans for, and the migrations folder.
  refuses(edit(supabase, c => { c.observers.find(o => o.type === 'pg-wal').unloggedTables[0].usedBy = ['zzz']; }), /must list every string its live check's file half scans for/);
  refuses(edit(supabase, c => { c.observers.find(o => o.type === 'pg-wal').unloggedTables[0].scan = ['supabase/seed.sql']; }), /must include supabase\/migrations/);
  // A live check covers only its own table: pg_net's check reports on its own queue and no other table.
  for (const entry of ['public.messages', 'auth.users']) refuses(edit(supabase, c => { c.observers.find(o => o.type === 'pg-wal').unloggedTables[0].entry = entry; }), /must be the table its live check covers \(pg_net: net\.http_request_queue\)/);
  refuses(edit(supabase, c => { c.records.templates = ['/rest/v1/{table}?id=eq.{row}']; }), /no other placeholder/);
  refuses(edit(supabase, c => { c.policyImporter.paths = ['/etc/migrations']; }), /a path inside the app folder/);
  refuses(edit(supabase, c => { c.packs = ['no-such-pack']; }), /a shipped pack/);
  refuses(edit(supabase, c => { c.packs = ['payments-pack']; }), /only a payments connector/);
  refuses(edit(supabase, c => { c.reset.argv = ['supabase', 'db', 'reset;', 'rm']; }), /no shell syntax/);
  refuses(edit(stripe, c => { c.packs = ['refund-window']; }), /ships the payments pack/);
  refuses(edit(stripe, c => { c.identity = supabase.identity; }), /"identity" belongs to a http connector/);
  refuses(edit(model, c => { c.model.protocol = 'another-protocol'; }), /protocol: must be one of/);
  refuses(edit(model, c => { c.model.baseUrlEnv = ['model_base_url']; }), /environment variable name/);
});

test('parseConnector refuses bytes that are not JSON, too large, or filed under another stack name', async () => {
  const bytes = await readFile(join(CATALOG_DIR, 'supabase.json'));
  assert.throws(() => parseConnector(Buffer.from('{"schema":'), { file: 'supabase.json' }), /not valid JSON/);
  assert.throws(() => parseConnector(Buffer.alloc(70 * 1024, 32), { file: 'supabase.json' }), /larger than/);
  assert.throws(() => parseConnector(bytes, { file: 'postgres.json' }), /named for its stack \(supabase\.json\)/);
  assert.equal(parseConnector(bytes, { file: 'supabase.json' }).stack, 'supabase');
  // loadConnector's digest is of the bytes it validated.
  const { connector, sha256 } = await loadConnector('supabase');
  assert.equal(connector.stack, 'supabase');
  assert.equal(sha256, createHash('sha256').update(bytes).digest('hex'));
});

test('readConnector refuses a name that is not shipped before opening any file', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven connectors '));
  try {
    writeFileSync(join(dir, 'other.json'), JSON.stringify({ schema: CONNECTOR_SCHEMA }));
    await assert.rejects(readConnector('supabase', { dir }), /not a shipped connector \(shipped: other\)/);
    await assert.rejects(readConnector('../supabase'), /lower-case letters/);
    await assert.rejects(readConnector('other', { dir }), /is missing "stack"/);
    assert.ok(existsSync(join(dir, 'other.json')));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
