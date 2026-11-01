// Live MIDTASK-ANY run on one practice copy of a third-party agent stack.
//
//   node run-stack.mjs <stack> <start-only|recheck> <revoke|control> <out dir>
//
// Environment: MP_SIGNING_KEY (required) is the PEM private key the run's files are signed
// with (integrations/attest, written as run.dsse.json); MP_UPSTREAM (default
// http://127.0.0.1:11434) is the model server, which must be a literal loopback origin
// (checked before anything is sent to it); MP_MODEL is the model the app asks for;
// MP_TASK_TIMEOUT_MS (default 420000, at most 540000, inside the sequence's 600 s budget) is
// how long the user's task may run before it reads task-not-finished.
//
// Starts the model path (hold gate, then the model tap, then local Ollama on
// 127.0.0.1:11434), starts the stack's practice copy with its model base URL pointed at
// the gate, runs the MIDTASK-ANY sequence, stops the app, unloads the model and writes
// record.json (scopehaven-model-path-run/1), reading.json, tap.jsonl, access.db and the
// app log to <out dir>, which must not exist yet.
//
// Local only: the upstream is the loopback Ollama origin, the model is the derived
// 8K-context model (MP_MODEL, see ollama-model.mjs), the run refuses to start while any
// other model is loaded, and the user and admin tokens are fresh random values that are
// passed to the app and the sequence through the environment and never written out.
// Run it only under a HOLD line in $SCOPEHAVEN_PRACTICE_DIR/HOLDS.txt.
import { createHash, randomBytes } from 'node:crypto';
import { mkdirSync, existsSync, readdirSync, readFileSync, statSync, writeFileSync, openSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { createSqliteAuditObserver } from '../../observers/sqlite.mjs';
import { startModelPath, runModelPath, signModelPathRunFiles } from '../model-path.mjs';
import { upstreamKind } from '../../model-identity/tap.mjs';
import { midtaskAnySequence, judgeMidtask } from '../midtask-any.mjs';
import { STACKS } from './stacks.mjs';

// MP_UPSTREAM exists for a dry run against an owned stub model; startModelPath refuses
// anything that is not a loopback origin.
const OLLAMA = process.env.MP_UPSTREAM || 'http://127.0.0.1:11434';
const MODEL = process.env.MP_MODEL || 'sh-sup2-qwen9b-8k:latest';
const TASK_TIMEOUT_MS = Math.min(540000, Math.max(1000, Number(process.env.MP_TASK_TIMEOUT_MS) || 420000));
const [stackName, build, variant, outArg] = process.argv.slice(2);
const stack = STACKS[stackName];
if (!stack || !['start-only', 'recheck'].includes(build) || !['revoke', 'control'].includes(variant) || !outArg) {
  console.error(`usage: run-stack.mjs <${Object.keys(STACKS).join('|')}> <start-only|recheck> <revoke|control> <out dir>`); process.exit(2);
}
const out = resolve(outArg);
if (existsSync(out)) { console.error(`${out} exists`); process.exit(2); }
if (upstreamKind(OLLAMA) !== 'loopback') { console.error('MP_UPSTREAM must be a literal loopback origin.'); process.exit(2); }
if (!process.env.MP_SIGNING_KEY || !existsSync(process.env.MP_SIGNING_KEY)) { console.error('MP_SIGNING_KEY must name the PEM private key the run is signed with.'); process.exit(2); }

// One model at a time on the shared Ollama: refuse while anything is loaded.
const ps = await (await fetch(`${OLLAMA}/api/ps`, { redirect: 'error' })).json();
if (ps.models?.length) { console.error(`Ollama has a model loaded (${ps.models.map(m => m.name).join(', ')}); not starting.`); process.exit(3); }
const tags = await (await fetch(`${OLLAMA}/api/tags`, { redirect: 'error' })).json();
if (!tags.models?.some(m => m.name === MODEL)) { console.error(`${MODEL} is not installed; run ollama-model.mjs create first.`); process.exit(3); }

mkdirSync(out, { recursive: true });
const copyDir = stack.copyDir(build);
// The copy's own files, hashed: the build identity of this run.
const buildDigest = (() => {
  const files = {};
  const walk = dir => { for (const name of readdirSync(dir).sort()) { if (stack.skip.includes(name) || name.startsWith('.')) continue; const p = join(dir, name); if (statSync(p).isDirectory()) walk(p); else files[p.slice(copyDir.length + 1)] = createHash('sha256').update(readFileSync(p)).digest('hex'); } };
  walk(copyDir);
  return { files: Object.keys(files).length, sha256: createHash('sha256').update(JSON.stringify(files)).digest('hex') };
})();

const tokens = { user: randomBytes(24).toString('base64url'), admin: randomBytes(24).toString('base64url') };
const accessDb = join(out, 'access.db');
// The access tables exist before the app or the observer opens the file.
{ const db = new DatabaseSync(accessDb); db.exec('CREATE TABLE suspended (principal TEXT PRIMARY KEY); CREATE TABLE audit (id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT, action TEXT, resource TEXT);'); db.close(); }
const appEnv = { SH_ACCESS_DB: accessDb, SH_USER_TOKEN: tokens.user, SH_ADMIN_TOKEN: tokens.admin, SH_USER_PRINCIPAL: 'user-1', SH_ADMIN_PRINCIPAL: 'admin-1' };
const started = new Date().toISOString();
const path = await startModelPath({ upstream: OLLAMA, rules: [{ id: 'model-call', method: 'POST', pathPrefix: stack.modelPathPrefix, holds: 1 }], tapLogPath: join(out, 'tap.jsonl') });
let app = null, record = null, error = null, appRecords = null;
try {
  app = await stack.start({ copyDir, build, gateUrl: path.url, model: MODEL, env: appEnv, log: openSync(join(out, 'app.log'), 'wx', 0o600) });
  // The user's principal is the app's own id for them where it has one (the Vercel guest user's id).
  const user = app.userPrincipal ?? 'user-1';
  // The refusal row is the app's own committed record that it refused the write, so the template can require it.
  const observer = createSqliteAuditObserver({ instanceId: `sqlite-audit-${stackName}`, path: accessDb, principals: [user, 'admin-1'],
    audit: { table: 'audit', idColumn: 'id', actorColumn: 'actor', actionColumn: 'action', resourceColumn: 'resource',
      actions: { [stack.writeAction]: 'update', 'tool.invoked': 'tool-call', [stack.deniedAction]: 'tool-call', 'user.suspend': 'access-change' }, deniedActions: [] } });
  const sequence = midtaskAnySequence({ id: `${stackName}-${build}`, variant, rule: 'model-call',
    actors: { user: { principalId: user, credentialEnv: 'SCOPEHAVEN_TARGET_MP_USER', ...(stack.cookie ? { credentialCookie: stack.cookie } : {}) }, admin: { principalId: 'admin-1', credentialEnv: 'SCOPEHAVEN_TARGET_MP_ADMIN' } },
    task: await stack.task(app, MODEL), revoke: { method: 'POST', path: stack.revokePath, body: { principal: user } },
    write: { source: 'sql-audit-table', actor: user, name: stack.writeAction }, attempt: { source: 'sql-audit-table', actor: user, name: 'tool.invoked' },
    refusal: { source: 'sql-audit-table', actor: user, name: stack.deniedAction }, accessChange: { source: 'sql-audit-table', actor: 'admin-1', name: 'user.suspend' },
    taskTimeoutMs: TASK_TIMEOUT_MS, holdTimeoutMs: 180000 });
  if (stack.beforeTask) await stack.beforeTask(app);
  record = await runModelPath({ sequence, origin: app.origin, observers: [observer], path, env: { SCOPEHAVEN_TARGET_MP_USER: app.userCredential ?? tokens.user, SCOPEHAVEN_TARGET_MP_ADMIN: tokens.admin } });
  if (stack.afterTask) appRecords = await stack.afterTask(app);
} catch (e) { error = String(e?.message ?? e).slice(0, 500); }
finally {
  if (app) await app.stop();
  await path.stop();
  try { await fetch(`${OLLAMA}/api/generate`, { method: 'POST', redirect: 'error', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ model: MODEL, keep_alive: 0 }) }); } catch {}
}
const reading = record ? judgeMidtask(record) : { reading: 'error', reason: error };
const unloaded = (await (await fetch(`${OLLAMA}/api/ps`, { redirect: 'error' })).json()).models?.length === 0;
writeFileSync(join(out, 'reading.json'), `${JSON.stringify({ stack: stackName, build, variant, model: MODEL, started, finished: new Date().toISOString(), copy: { dir: copyDir, ...buildDigest }, reading, appRecords, error, unloaded }, null, 2)}\n`);
if (record) {
  writeFileSync(join(out, 'record.json'), `${JSON.stringify(record, null, 2)}\n`, { flag: 'wx' });
  signModelPathRunFiles(out, { privateKey: readFileSync(process.env.MP_SIGNING_KEY, 'utf8') });
}
console.log(JSON.stringify({ stack: stackName, build, variant, reading, unloaded, ...(record ? { verdicts: record.verdicts?.map(v => `${v.id}:${v.status}`), heldModels: record.holds.map(h => h.identity.models?.map(m => m.served)) } : {}) }));
