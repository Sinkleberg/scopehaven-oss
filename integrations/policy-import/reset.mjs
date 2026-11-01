// Seed and reset (scopehaven-reset/1): a declared reset command that init can wire, and a hash check that the seed
// state is identical before each run. docs/ONBOARDING.md: a POST, PUT, PATCH or DELETE check is a real change on the target,
// and a timeout does not undo it; reset the target to the same seed before every run a comparison uses. The declaration
// says how to reset (an argv list, never a shell string; a cwd; a bounded timeout; plain environment values only) and what
// the seed state is read from (files, a command's stdout, or loopback GET bodies), in that order. ensureSeed runs the reset,
// hashes the seed sources and compares the hash with the recorded one: a different hash refuses the run. The first time,
// with no recorded hash, it returns the hash to record in a new declaration file (nothing here edits a file in place).
// The reset command's environment is minimal (PATH, HOME, TMPDIR and the declared plain values): it never inherits the
// caller's secrets. A loopback seed read may carry one credential from a SCOPEHAVEN_TARGET_ variable; its value is sent,
// never stored or printed.
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile, lstat } from 'node:fs/promises';
import { request } from 'node:http';
import { isAbsolute } from 'node:path';

export const RESET_SCHEMA = 'scopehaven-reset/1';
export const RESET_LIMITS = Object.freeze({ timeoutMs: 600000, defaultTimeoutMs: 60000, stdoutBytes: 64 * 1024 * 1024, fileBytes: 256 * 1024 * 1024, httpBytes: 4 * 1024 * 1024, httpTimeoutMs: 10000, sources: 64 });
export const LOOPBACK_HOSTS = Object.freeze(['127.0.0.1', 'localhost', '[::1]']);
const SECRET_KEY = /pass(?:word|wd)|secret|token|api[-_]?key|credential|private/i;
const IDENT = /^[A-Za-z0-9_-]{1,80}$/;
const fail = message => { throw new Error(`reset: ${message}`); };
const plain = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const argv = (list, where) => { if (!Array.isArray(list) || !list.length || list.some(a => typeof a !== 'string' || !a.length || a.includes('\0'))) fail(`${where}.command is a non-empty argv list (never a shell string)`); };

export function validateReset(decl) {
  if (decl?.schema !== RESET_SCHEMA) fail(`a reset declaration needs schema "${RESET_SCHEMA}"`);
  if (typeof decl.targetId !== 'string' || !IDENT.test(decl.targetId)) fail('targetId names the profile target the reset belongs to');
  if (!plain(decl.reset)) fail('reset is { command, cwd, timeoutMs?, env? }');
  argv(decl.reset.command, 'reset');
  if (typeof decl.reset.cwd !== 'string' || !isAbsolute(decl.reset.cwd)) fail('reset.cwd is an absolute path');
  if (decl.reset.timeoutMs !== undefined && !(Number.isInteger(decl.reset.timeoutMs) && decl.reset.timeoutMs >= 1000 && decl.reset.timeoutMs <= RESET_LIMITS.timeoutMs)) fail(`reset.timeoutMs is 1000 to ${RESET_LIMITS.timeoutMs}`);
  if (decl.reset.env !== undefined) {
    if (!plain(decl.reset.env)) fail('reset.env is an object of plain values');
    for (const [k, v] of Object.entries(decl.reset.env)) { if (!/^[A-Z_][A-Z0-9_]*$/.test(k) || typeof v !== 'string') fail('reset.env keys are UPPER_CASE names with string values'); if (SECRET_KEY.test(k)) fail(`reset.env.${k} looks like a secret; a reset declaration carries no secret values`); }
  }
  if (!plain(decl.seed)) fail('seed is { files?, command?, http?, expected }');
  const sources = (decl.seed.files?.length ?? 0) + (decl.seed.command ? 1 : 0) + (decl.seed.http?.paths?.length ?? 0);
  if (!sources) fail('seed names at least one source: files, a command, or http paths');
  if (sources > RESET_LIMITS.sources) fail(`seed names at most ${RESET_LIMITS.sources} sources`);
  if (decl.seed.files !== undefined && (!Array.isArray(decl.seed.files) || decl.seed.files.some(f => typeof f !== 'string' || !isAbsolute(f)))) fail('seed.files is a list of absolute paths');
  if (decl.seed.command !== undefined) argv(decl.seed.command, 'seed');
  if (decl.seed.http !== undefined) {
    const h = decl.seed.http;
    if (!plain(h) || typeof h.origin !== 'string' || !Array.isArray(h.paths) || !h.paths.length) fail('seed.http is { origin, paths, credentialEnv? }');
    let u; try { u = new URL(h.origin); } catch { fail('seed.http.origin is a URL'); }
    if (u.protocol !== 'http:' || !LOOPBACK_HOSTS.includes(u.hostname === '::1' ? '[::1]' : u.hostname) || u.pathname !== '/' || u.search || u.hash) fail('seed.http.origin is a plain http loopback origin (http://127.0.0.1:PORT)');
    if (h.paths.some(p => typeof p !== 'string' || !p.startsWith('/') || p.startsWith('//') || p.includes('#') || /[\u0000- \u007f]/.test(p))) fail('seed.http.paths are absolute request paths');
    if (h.credentialEnv !== undefined && !/^SCOPEHAVEN_TARGET_[A-Z0-9_]{1,110}$/.test(h.credentialEnv)) fail('seed.http.credentialEnv is a SCOPEHAVEN_TARGET_ variable name');
    if (h.credentialHeader !== undefined && (typeof h.credentialHeader !== 'string' || !/^[A-Za-z0-9-]{1,64}$/.test(h.credentialHeader))) fail('seed.http.credentialHeader is a header name');
  }
  if (!(decl.seed.expected === null || (typeof decl.seed.expected === 'string' && /^[a-f0-9]{64}$/.test(decl.seed.expected)))) fail('seed.expected is the recorded sha256, or null before the first record');
  return decl;
}

// Runs an argv list without a shell, in a minimal environment, bounded by the timeout. Never throws on a non-zero exit:
// the caller reads exitCode. A timeout kills the process group's leader and reads as exitCode null with timedOut true.
export function runCommand(command, { cwd, timeoutMs = RESET_LIMITS.defaultTimeoutMs, env = {}, stdoutLimit = RESET_LIMITS.stdoutBytes, baseEnv = process.env } = {}) {
  return new Promise(resolve => {
    const started = performance.now();
    const minimal = { PATH: baseEnv.PATH ?? '', HOME: baseEnv.HOME ?? '', TMPDIR: baseEnv.TMPDIR ?? '', ...env };
    let child;
    // detached: the command leads its own process group, so a timeout kills the whole group (a reset script's children too).
    try { child = spawn(command[0], command.slice(1), { cwd, env: minimal, stdio: ['ignore', 'pipe', 'pipe'], shell: false, detached: true }); }
    catch (error) { return resolve({ exitCode: null, signal: null, timedOut: false, spawnError: error.code ?? error.message, durationMs: 0, stdout: Buffer.alloc(0), stdoutBytes: 0, stderrTail: '' }); }
    const out = [], err = []; let outBytes = 0, errBytes = 0, timedOut = false, spawnError = null;
    child.stdout.on('data', d => { outBytes += d.length; if (outBytes <= stdoutLimit) out.push(d); });
    child.stderr.on('data', d => { errBytes += d.length; if (errBytes <= 65536) err.push(d); });
    const timer = setTimeout(() => { timedOut = true; try { process.kill(-child.pid, 'SIGKILL'); } catch { child.kill('SIGKILL'); } }, timeoutMs);
    child.on('error', error => { spawnError = error.code ?? error.message; });
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      resolve({ exitCode: code, signal, timedOut, spawnError, durationMs: Math.round(performance.now() - started), stdout: Buffer.concat(out), stdoutBytes: outBytes, stdoutTruncated: outBytes > stdoutLimit, stderrTail: Buffer.concat(err).toString('utf8').slice(-2000) });
    });
  });
}

function loopbackGet(origin, path, { credentialEnv, credentialHeader = 'Authorization', env }) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, origin);
    if (url.origin !== new URL(origin).origin) return reject(new Error('reset: a seed path never leaves the declared origin'));
    const headers = { Accept: 'application/json', Connection: 'close' };
    if (credentialEnv) {
      const value = env[credentialEnv];
      if (typeof value !== 'string' || !value.length) return reject(new Error(`reset: ${credentialEnv} is not set`));
      headers[credentialHeader] = credentialHeader.toLowerCase() === 'authorization' && !/^\w+\s/.test(value) ? `Bearer ${value}` : value;
    }
    const req = request(url, { method: 'GET', headers, agent: false, timeout: RESET_LIMITS.httpTimeoutMs }, res => {
      const chunks = []; let bytes = 0;
      res.on('data', d => { bytes += d.length; if (bytes <= RESET_LIMITS.httpBytes) chunks.push(d); });
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks), truncated: bytes > RESET_LIMITS.httpBytes }));
      res.on('error', reject);
    });
    req.on('timeout', () => req.destroy(new Error('reset: seed read timed out')));
    req.on('error', reject);
    req.end();
  });
}

// The seed state's hash: one sha256 over the labelled digests of every declared source, in declaration order. Each part is
// listed with its own digest, so a changed source is named; no content is kept.
export async function seedHash(decl, { env = process.env } = {}) {
  validateReset(decl);
  const parts = [];
  for (const file of decl.seed.files ?? []) {
    const st = await lstat(file).catch(() => null);
    if (!st || !st.isFile() || st.isSymbolicLink()) fail(`seed file ${file} is missing or not a regular file`);
    if (st.size > RESET_LIMITS.fileBytes) fail(`seed file ${file} is larger than ${RESET_LIMITS.fileBytes} bytes`);
    parts.push({ kind: 'file', ref: file, sha256: sha256(await readFile(file)), bytes: st.size });
  }
  if (decl.seed.command) {
    const r = await runCommand(decl.seed.command, { cwd: decl.reset.cwd, timeoutMs: decl.reset.timeoutMs ?? RESET_LIMITS.defaultTimeoutMs, env: decl.reset.env, baseEnv: env });
    if (r.exitCode !== 0 || r.stdoutTruncated) fail(`seed command ${r.timedOut ? 'timed out' : r.spawnError ? `could not start (${r.spawnError})` : r.stdoutTruncated ? 'wrote more than the limit' : `exited ${r.exitCode}`}${r.stderrTail ? `: ${r.stderrTail.trim().split('\n').at(-1)}` : ''}`);
    parts.push({ kind: 'command', ref: decl.seed.command.join(' '), sha256: sha256(r.stdout), bytes: r.stdoutBytes });
  }
  for (const path of decl.seed.http?.paths ?? []) {
    const r = await loopbackGet(decl.seed.http.origin, path, { credentialEnv: decl.seed.http.credentialEnv, credentialHeader: decl.seed.http.credentialHeader, env });
    if (r.truncated) fail(`seed read ${path} is larger than ${RESET_LIMITS.httpBytes} bytes`);
    parts.push({ kind: 'http', ref: path, status: r.status, sha256: sha256(Buffer.concat([Buffer.from(`${r.status}\n`), r.body])), bytes: r.body.length });
  }
  const hash = sha256(parts.map(p => `${p.kind}\u0000${p.ref}\u0000${p.sha256}`).join('\n'));
  return { hash, parts };
}

export async function runReset(decl, { env = process.env } = {}) {
  validateReset(decl);
  const r = await runCommand(decl.reset.command, { cwd: decl.reset.cwd, timeoutMs: decl.reset.timeoutMs ?? RESET_LIMITS.defaultTimeoutMs, env: decl.reset.env, baseEnv: env });
  const ok = r.exitCode === 0 && !r.timedOut && !r.spawnError;
  return { ok, exitCode: r.exitCode, timedOut: r.timedOut, spawnError: r.spawnError, durationMs: r.durationMs, stderrTail: r.stderrTail };
}

// Reset, then check the seed. Returns a receipt { reset, seed: { hash, parts, expected, matches }, recorded, at }. Throws when
// the reset fails or the seed differs from the recorded hash; with no recorded hash it returns the hash to record (recorded: true)
// and the declaration to write as a new file (nothing is edited in place).
export async function ensureSeed(decl, { env = process.env, now = new Date(), skipReset = false } = {}) {
  validateReset(decl);
  const reset = skipReset ? { ok: true, skipped: true } : await runReset(decl, { env });
  if (!reset.ok) fail(`the reset command ${reset.timedOut ? 'timed out' : reset.spawnError ? `could not start (${reset.spawnError})` : `exited ${reset.exitCode}`}${reset.stderrTail ? `: ${reset.stderrTail.trim().split('\n').at(-1)}` : ''}`);
  const seed = await seedHash(decl, { env });
  const expected = decl.seed.expected;
  const matches = expected === null ? null : seed.hash === expected;
  const receipt = { schema: 'scopehaven-reset-receipt/1', targetId: decl.targetId, at: now.toISOString(), reset, seed: { ...seed, expected, matches }, recorded: expected === null };
  if (matches === false) {
    const changed = seed.parts.map(p => p.ref);
    fail(`the seed state differs from the recorded seed (${seed.hash.slice(0, 12)} vs ${expected.slice(0, 12)}); the reset did not restore it, or the declaration's sources changed (${changed.length} source${changed.length === 1 ? '' : 's'}: ${changed.join(', ')}). Fix the reset, or record the new seed deliberately.`);
  }
  if (expected === null) receipt.declaration = { ...decl, seed: { ...decl.seed, expected: seed.hash } };
  return receipt;
}
