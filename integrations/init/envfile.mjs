// The two inputs init reads from the environment, and how it keeps their values off disk.
//
// readCredentialFile: the operator's private env file with the test identities' credentials. It must be a regular file
// (not a symlink or FIFO), owned by the current user, mode 0600, at most 64 KiB. Its SCOPEHAVEN_TARGET_ keys become the
// actors' credentialEnv references. Values stay in memory: init passes them to its own child processes' environment and
// never writes them anywhere.
//
// variableNames: the NAMES in an app's .env file or in the environment, never the values. A .env line is cut at the first
// "=" and everything after it is dropped before anything else reads it.
import { constants } from 'node:fs';
import { lstat, open } from 'node:fs/promises';

export class InitError extends Error {
  constructor(code, message) { super(message); this.name = 'InitError'; this.code = code; }
}

const KEY = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const TARGET_KEY = /^SCOPEHAVEN_TARGET_[A-Z0-9_]{1,110}$/;
const MAX_BYTES = 65536;

async function readPrivate(path, { requireMode600, maxBytes = MAX_BYTES, what = 'the env file', withStat = false }) {
  let handle;
  try { handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK); }
  catch (error) { throw new InitError('env-file', error?.code === 'ELOOP' ? `${what} is a symlink; give the real file` : `${what} could not be opened`); }
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) throw new InitError('env-file', `${what} is not a regular file`);
    if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) throw new InitError('env-file', `${what} is not owned by the current user`);
    if (requireMode600 && (stat.mode & 0o077) !== 0) throw new InitError('env-file', `${what} has mode ${(stat.mode & 0o777).toString(8)}; it holds credentials, so make it private first: chmod 600 FILE`);
    if (stat.size > maxBytes) throw new InitError('env-file', `${what} is larger than ${Math.round(maxBytes / 1024)} KiB`);
    const text = await handle.readFile('utf8');
    // The identity of the file the content came from (the same handle), for the session swap check.
    return withStat ? { text, stat } : text;
  } finally { await handle.close(); }
}

// KEY=VALUE lines; "export " prefixes, blank lines and # comments are allowed; one pair of matching quotes is removed.
function parseLines(text, onPair) {
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const body = line.startsWith('export ') ? line.slice(7).trimStart() : line;
    const at = body.indexOf('=');
    if (at <= 0) continue;
    const key = body.slice(0, at).trim();
    if (!KEY.test(key)) continue;
    onPair(key, () => {
      let value = body.slice(at + 1).trim();
      if (value.length >= 2 && (value[0] === '"' || value[0] === "'") && value.at(-1) === value[0]) value = value.slice(1, -1);
      return value;
    });
  }
}

// Returns { keys: [...SCOPEHAVEN_TARGET_ names in file order], values: Map } (values in memory only).
export async function readCredentialFile(path) {
  const text = await readPrivate(path, { requireMode600: true });
  const keys = [], values = new Map(), other = [];
  parseLines(text, (key, value) => {
    if (!TARGET_KEY.test(key)) { other.push(key); return; }
    if (values.has(key)) throw new InitError('env-file', `the env file sets ${key} twice`);
    const v = value();
    if (!v) throw new InitError('env-file', `${key} is empty in the env file`);
    if (/[\s;,"\\]/.test(v)) throw new InitError('env-file', `${key} holds whitespace, ";", ",", a quote or a backslash, which no credential slot accepts`);
    keys.push(key); values.set(key, v);
  });
  if (!keys.length) throw new InitError('env-file', `the env file has no SCOPEHAVEN_TARGET_ keys${other.length ? ` (it names ${other.length} other key${other.length === 1 ? '' : 's'}; rename each identity's credential to SCOPEHAVEN_TARGET_<APP>_A and _B)` : ''}`);
  return { keys, values };
}

// Names only. An app .env need not be 0600 (it is the app's), but it must be a regular file the user owns.
export async function appEnvNames(path) {
  const text = await readPrivate(path, { requireMode600: false });
  const names = [];
  parseLines(text, key => { if (!names.includes(key)) names.push(key); });
  return names;
}

export const environmentNames = env => Object.keys(env).filter(name => KEY.test(name));

// A recorded session (a HAR file or a JSON-lines request log) for the session-import hook. Init passes only its path
// to the hook. It reads the file itself only to collect, in memory, the credential-like values it holds (header and
// cookie values, and any string under a key that names a token, secret, password, key, cookie or session), so that no
// proposal written to disk can carry one. The file must be private (0600): a HAR holds live session cookies.
const SECRET_KEY = /(authorization|cookie|token|secret|passw(or)?d|api[-_]?key|session|csrf|bearer|jwt|^auth$)/i;
const SECRET_HEADER = /^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-?key|x-auth-token|x-csrf-token|x-xsrf-token)$/i;
const MIN_SECRET = 8;
const COOKIE_ATTRIBUTES = /^(path|domain|expires|max-age|samesite|secure|httponly|priority|partitioned)$/i;
function addSecret(out, value) {
  if (typeof value !== 'string') return;
  const v = value.trim();
  if (v.length < MIN_SECRET) return;
  out.add(v);
  const bearer = /^(?:bearer|basic|token)\s+(.+)$/i.exec(v);
  if (bearer && bearer[1].length >= MIN_SECRET) out.add(bearer[1]);
  // name=value pieces of a cookie line, without the Set-Cookie attributes (a path or expiry is not a credential).
  for (const part of v.split(/;\s*/)) { const at = part.indexOf('='); if (at > 0 && !COOKIE_ATTRIBUTES.test(part.slice(0, at).trim()) && part.length - at - 1 >= MIN_SECRET) out.add(part.slice(at + 1).split(';')[0]); }
}
// Strings that hold a body or a URL are opened up too: a JSON body (a HAR's postData.text or content.text, a request
// log's body), a form body, and a URL's query, where a password or token sits under an ordinary key.
const BODY_KEY = /^(text|postData|body|requestBody|responseBody|content|data|payload)$/i;
function collectString(key, value, out, depth) {
  if (SECRET_KEY.test(key) || SECRET_HEADER.test(key)) { addSecret(out, value); return; }
  if (BODY_KEY.test(key)) {
    const trimmed = value.trim();
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) { try { collect(JSON.parse(trimmed), out, depth + 1); return; } catch {} }
    if (/^[^\s=&]+=[^\s&]*(&[^\s=&]+=[^\s&]*)*$/.test(trimmed)) collectQuery(new URLSearchParams(trimmed), out);
    return;
  }
  if (/^(url|uri|href|path|target)$/i.test(key)) {
    try { collectQuery(new URL(value, 'http://session.invalid').searchParams, out); } catch {}
  }
}
function collectQuery(params, out) {
  for (const [name, value] of params) if (SECRET_KEY.test(name) || SECRET_HEADER.test(name)) addSecret(out, value);
}
function collect(node, out, depth = 0) {
  if (depth > 12 || node === null || typeof node !== 'object') return;
  if (Array.isArray(node)) { for (const item of node) collect(item, out, depth + 1); return; }
  // A HAR header, cookie or query parameter: { name, value }.
  if (typeof node.name === 'string' && typeof node.value === 'string' && (SECRET_HEADER.test(node.name) || SECRET_KEY.test(node.name))) addSecret(out, node.value);
  for (const [key, value] of Object.entries(node)) {
    if (key === 'cookies' && Array.isArray(value)) for (const c of value) addSecret(out, c?.value);
    if (typeof value === 'string') collectString(key, value, out, depth);
    else collect(value, out, depth + 1);
  }
}
// Collects the session file's credential-like values and notes the file's identity, so a swap of the file between this
// check and the hooks' reads can be detected afterwards (sessionUnchanged).
export async function sessionSecrets(path) {
  const { text, stat } = await readPrivate(path, { requireMode600: true, maxBytes: 32 * 1024 * 1024, what: 'the session file', withStat: true });
  const out = new Set();
  let parsed = false;
  try { collect(JSON.parse(text), out); parsed = true; } catch {}
  if (!parsed) for (const line of text.split(/\r?\n/)) { if (!line.trim()) continue; try { collect(JSON.parse(line), out); parsed = true; } catch {} }
  if (!parsed) throw new InitError('session', 'the session file is neither JSON (a HAR) nor JSON lines (a request log)');
  return { secrets: out, identity: { dev: stat.dev, ino: stat.ino, size: stat.size, mtimeMs: stat.mtimeMs } };
}
export async function sessionUnchanged(path, identity) {
  try { const stat = await lstat(path); return stat.isFile() && !stat.isSymbolicLink() && stat.dev === identity.dev && stat.ino === identity.ino && stat.size === identity.size && stat.mtimeMs === identity.mtimeMs; }
  catch { return false; }
}
// True when the serialized value holds any of the secrets.
// The serialized text is searched for each secret as written and as JSON escapes it (a value with a quote or backslash).
export const holdsSecret = (value, secrets) => {
  const text = typeof value === 'string' ? value : JSON.stringify(value ?? null);
  return [...secrets].some(secret => secret && (text.includes(secret) || text.includes(JSON.stringify(secret).slice(1, -1))));
};
