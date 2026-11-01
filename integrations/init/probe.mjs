// Read-only discovery against an app already running on loopback. Every request is a GET to the literal 127.0.0.1
// origin the authorization record covers, follows no redirect, reads at most 64 KiB and keeps no response body: only
// the status, the content type, a Location header's path and, for a JSON body, the parsed value in memory for the
// identity search below.
import { request } from 'node:http';
import { randomBytes } from 'node:crypto';
import { InitError } from './envfile.mjs';
import { credentialHeaderProblem } from '../../src/contracts.mjs';

// Session-derived "who am I" routes common in web frameworks, most specific first. n8n answers GET /rest/login with the
// signed-in user (its session is the n8n-auth cookie below).
export const WHOAMI_CANDIDATES = Object.freeze(['/api/auth/session', '/api/me', '/api/users/me', '/api/user', '/api/v1/auths/', '/api/v1/me', '/api/v1/users/me',
  '/api/whoami', '/api/auth/me', '/api/auth/user', '/api/session', '/api/account', '/api/profile', '/api/current-user', '/api/v1/user', '/auth/v1/user', '/rest/login', '/me', '/whoami', '/user']);
// Login or session-issuing routes, reported so the operator knows where to mint the two sessions.
export const LOGIN_CANDIDATES = Object.freeze(['/api/auth/signin', '/api/auth/providers', '/api/auth/csrf', '/api/auth/login', '/api/login', '/api/v1/auths/signin',
  '/auth/login', '/login', '/signin', '/api/auth/guest']);
// Cookie names session middlewares use by default (http only: __Secure- names need https).
export const COOKIE_CANDIDATES = Object.freeze(['authjs.session-token', 'next-auth.session-token', 'session', 'token', 'sid', 'connect.sid', 'jwt', 'access_token', 'sessionid', 'session_id', '_session', 'app_session', 'lab_session', 'n8n-auth']);
// Routes an assistant or agent usually answers on. Found ones are listed: assistant-turn checks are not drafted by v0.
export const CHAT_CANDIDATES = Object.freeze(['/api/chat', '/api/chat/completions', '/api/v1/chat/completions', '/api/messages', '/api/assistant', '/api/agent', '/api/agents', '/api/conversations']);
// Keys that usually name the signed-in principal, best first.
const IDENTITY_KEYS = ['email', 'username', 'user_name', 'login', 'preferred_username', 'principalId', 'principal', 'sub', 'userId', 'user_id', 'id', 'handle', 'name'];
const MAX_BODY = 65536;
// The redirect statuses a profile may declare as an actor's signInRedirectStatus (src/contracts.mjs).
export const SIGN_IN_REDIRECTS = Object.freeze([301, 302, 303, 307, 308]);

// The request-path rules of src/contracts.mjs validPath (not exported there), applied before any probe so init never
// sends a path the profile loader would refuse: absolute, no fragment, decodable, and after up to five decodings no
// backslash, "//", control or space character, "." or ".." segment.
export function safePath(path) {
  if (typeof path !== 'string' || !path.length || path.length > 2048 || !path.startsWith('/') || path.includes('#')) return false;
  try { decodeURIComponent(path); } catch { return false; }
  let decoded = path;
  for (let count = 0; count < 5; count++) {
    if (decoded.includes('\\') || decoded.includes('//') || /[\u0000-\u0020\u007f]/.test(decoded) || decoded.split('?')[0].split('/').some(part => part === '.' || part === '..')) return false;
    if (!/%[0-9a-f]{2}/i.test(decoded)) return true;
    try { decoded = decodeURIComponent(decoded); } catch { return false; }
  }
  return false;
}

export function loopbackOrigin(baseUrl) {
  let url;
  try { url = new URL(baseUrl); } catch { throw new InitError('base-url', 'the base URL is not a URL (for example http://127.0.0.1:3000)'); }
  if (url.protocol !== 'http:') throw new InitError('base-url', 'init runs against an http app on loopback; a remote or https target needs the full setup in docs/ONBOARDING.md');
  const host = url.hostname === 'localhost' ? '127.0.0.1' : url.hostname;
  if (host !== '127.0.0.1') throw new InitError('base-url', 'the base URL must be on loopback (127.0.0.1 or localhost)');
  const port = Number(url.port || 80);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new InitError('base-url', 'the base URL has no usable port');
  return { origin: `http://127.0.0.1:${port}`, port };
}

// A credential slot: how one identity's value travels. { kind: 'bearer' } | { kind: 'cookie', name } | { kind: 'header', name }.
export function parseSlot(text) {
  if (text === 'bearer') return { kind: 'bearer' };
  const m = /^(cookie|header):([A-Za-z0-9!#$%&'*+.^_`|~-]{1,128})$/.exec(text ?? '');
  if (!m) throw new InitError('credential', '--credential is bearer, cookie:NAME or header:NAME');
  // A header the connector, HTTP framing or a proxy owns is refused before any request, as the profile loader refuses it.
  if (m[1] === 'header' && credentialHeaderProblem(m[2].toLowerCase()) !== null) throw new InitError('credential', `header:${m[2]} is not a header a credential may use (${credentialHeaderProblem(m[2].toLowerCase())})`);
  return { kind: m[1], name: m[2] };
}
export const slotLabel = slot => slot.kind === 'bearer' ? 'bearer' : `${slot.kind}:${slot.name}`;
const headersFor = (slot, value) => !slot || value === undefined ? {} : slot.kind === 'bearer' ? { authorization: `Bearer ${value}` }
  : slot.kind === 'cookie' ? { cookie: `${slot.name}=${value}` } : { [slot.name.toLowerCase()]: value };

export function makeProber({ port, beforeRequest = () => {}, timeoutMs = 3000 }) {
  let sent = 0;
  const seenCookies = new Set();
  const get = (path, { slot, value } = {}) => new Promise(resolve => {
    beforeRequest();
    sent += 1;
    // A fresh connection per request (agent: false, as src/http-connector.mjs, plus Connection: close), so no reused socket can hand back a stale reply.
    const req = request({ host: '127.0.0.1', port, method: 'GET', path, agent: false, headers: { accept: 'application/json', 'user-agent': 'scopehaven-init/0', ...headersFor(slot, value), connection: 'close' }, timeout: timeoutMs }, res => {
      const chunks = []; let size = 0;
      res.on('data', chunk => { size += chunk.length; if (size <= MAX_BODY) chunks.push(chunk); else res.destroy(); });
      res.on('close', () => {
        const type = String(res.headers['content-type'] ?? '');
        let json; let jsonParsed = false;
        if (/json/i.test(type) && size <= MAX_BODY) { try { json = JSON.parse(Buffer.concat(chunks).toString('utf8')); jsonParsed = true; } catch {} }
        let location = null;
        if (typeof res.headers.location === 'string') { try { location = new URL(res.headers.location, 'http://127.0.0.1').pathname; } catch {} }
        // Cookie names only (never values), so a custom session cookie name can be tried.
        const cookieNames = [].concat(res.headers['set-cookie'] ?? []).map(line => /^\s*([^=;\s]+)=/.exec(line)?.[1]).filter(Boolean);
        resolve({ status: res.statusCode, type, json, jsonParsed, location, html: /html/i.test(type), cookieNames });
      });
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', () => resolve({ status: null, type: '', jsonParsed: false, location: null, html: false, cookieNames: [] }));
    req.end();
  });
  const tracked = async (path, options) => { const answer = await get(path, options); for (const name of answer.cookieNames ?? []) seenCookies.add(name); return answer; };
  return { get: tracked, sent: () => sent, cookieNames: () => [...seenCookies] };
}

// String leaves up to depth 4 as [pointer, key, value].
function leaves(value, pointer = '', key = '', depth = 0, out = []) {
  if (typeof value === 'string') { if (value.length >= 1 && value.length <= 200) out.push([pointer, key, value]); return out; }
  if (depth >= 4 || value === null || typeof value !== 'object') return out;
  for (const [k, v] of Array.isArray(value) ? value.entries() : Object.entries(value)) leaves(v, `${pointer}/${String(k).replaceAll('~', '~0').replaceAll('/', '~1')}`, String(k), depth + 1, out);
  return out;
}
// A key's rank: an exact identity key, or one that ends in email, user id or username (owner_email, created_by_user_id).
const keyRank = key => {
  const i = IDENTITY_KEYS.indexOf(key);
  if (i !== -1) return i;
  // owner_email or user_email names a user; support_email or billing_email names a mailbox the whole tenant shares.
  if (/e-?mail$/i.test(key)) return /^(support|billing|contact|info|help|sales|noreply|no_reply|admin|team|company|business|org)/i.test(key) ? IDENTITY_KEYS.length : 6.5;
  if (/user_?name$/i.test(key)) return 1.5;
  if (/user_?id$/i.test(key)) return 8.5;
  return IDENTITY_KEYS.length;
};
// A field under a tenant-like object (a business, org, team or workspace) may be shared by every user of that tenant, so
// it ranks after the user's own fields.
const TENANT_PARENT = /^(business|org|organization|organisation|tenant|team|workspace|company|account|project|group)$/i;
const rankAt = (pointer, key) => keyRank(key) + (pointer.split('/').slice(1, -1).some(part => TENANT_PARENT.test(part)) ? 20 : 0);
const valueAt = (json, pointer) => pointer.split('/').slice(1).map(p => p.replaceAll('~1', '/').replaceAll('~0', '~'))
  .reduce((node, part) => (node !== null && typeof node === 'object' && Object.hasOwn(node, part) ? node[part] : undefined), json);
const flat = json => JSON.stringify(json ?? null);

// Identity pointers in A's who-am-I answer: a string leaf with an identity-like key whose value the anonymous answer does
// not carry and, with a second identity, B's answer carries at the same pointer as a different value.
// A leaf that equals, contains or (8 characters or longer) is contained in a credential value is never an identity:
// an app that echoes the session token as an id would otherwise put the credential into the profile.
const credentialLike = (value, secrets) => secrets.some(secret => typeof secret === 'string' && secret && (value === secret || value.includes(secret) || (value.length >= 8 && secret.includes(value))));
export function identityPointers(answerA, answerAnon, answerB, secrets = []) {
  if (!answerA?.jsonParsed || !(answerA.status >= 200 && answerA.status < 300)) return [];
  const anonText = answerAnon?.jsonParsed && answerAnon.status >= 200 && answerAnon.status < 300 ? flat(answerAnon.json) : '';
  return leaves(answerA.json).filter(([, key, value]) => keyRank(key) < IDENTITY_KEYS.length && !anonText.includes(JSON.stringify(value)) && !credentialLike(value, secrets))
    .filter(([pointer, , value]) => answerB === undefined || (typeof valueAt(answerB.json, pointer) === 'string' && valueAt(answerB.json, pointer) !== value && !credentialLike(valueAt(answerB.json, pointer), secrets)))
    .sort((x, y) => rankAt(x[0], x[1]) - rankAt(y[0], y[1]) || x[0].length - y[0].length)
    .map(([pointer, key, value]) => ({ pointer, key, value }));
}

// The login routes that answer differently from a path that cannot exist (an app that serves its page for every path
// would otherwise list them all).
export async function findLoginRoutes(prober) {
  const control = await prober.get(`/scopehaven-init-absent-${randomBytes(6).toString('hex')}`);
  const found = [];
  for (const path of LOGIN_CANDIDATES) {
    const answer = await prober.get(path);
    if (answer.status === null || answer.status === 404) continue;
    if (answer.status === control.status && answer.type === control.type) continue;
    found.push({ path, status: answer.status });
  }
  return { found, catchAll: control.status !== 404 && control.status !== null, control };
}

// Assistant or agent routes that answer differently from a path that cannot exist (GET only; a POST-only route usually
// answers 405).
export async function findChatRoutes(prober, control) {
  const found = [];
  for (const path of CHAT_CANDIDATES) {
    const answer = await prober.get(path);
    if (answer.status === null || answer.status === 404) continue;
    if (control && answer.status === control.status && answer.type === control.type) continue;
    found.push({ path, status: answer.status });
  }
  return found;
}

// Finds the who-am-I route and the credential slot. Explicit choices narrow the search; nothing is guessed silently:
// the result names what matched, or null so the caller can ask.
export async function findWhoami(prober, { valueA, valueB, slot, whoami }) {
  const paths = whoami ? [whoami] : WHOAMI_CANDIDATES;
  const anon = new Map();
  for (const path of paths) anon.set(path, await prober.get(path));
  // Cookie names the app set on any answer so far (login pages, the signed-out probes) are tried before the defaults.
  const seen = prober.cookieNames?.() ?? [];
  const names = [...new Set([...seen.filter(name => /sess|sid|token|auth|jwt/i.test(name)), ...COOKIE_CANDIDATES])];
  const slots = slot ? [slot] : [{ kind: 'bearer' }, ...names.map(name => ({ kind: 'cookie', name }))];
  // What came back, per route, under identity A: kept to explain a miss.
  const byPath = new Map(paths.map(path => [path, new Set()]));
  // An app that answers no probe, or only 5xx, is not searched further: every slot would wait the same way. Only when no
  // route was given, and only when one signed-in request (identity A, bearer or the given slot) also gets no answer or a
  // 5xx: some handlers fail signed out and answer signed in.
  const signedOutDown = [...anon.values()].every(answer => answer.status === null || answer.status >= 500);
  const signedInDown = !whoami && signedOutDown && (st => st === null || st >= 500)((await prober.get(paths[0], { slot: slot ?? { kind: 'bearer' }, value: valueA })).status);
  if (signedInDown) {
    for (const [path, answer] of anon) byPath.get(path).add(answer.status === null ? 'no answer' : answer.status);
    return { found: null, tried: { routes: paths.length, slots: 0, cookieNames: [], byPath, noIdentity: [], unhealthy: true } };
  }
  const noIdentity = new Set();
  for (const s of slots) for (const path of paths) {
    const a = await prober.get(path, { slot: s, value: valueA });
    byPath.get(path).add(a.status === null ? 'no answer' : a.status);
    if (!(a.status >= 200 && a.status < 300 && a.jsonParsed)) continue;
    let b;
    if (valueB !== undefined) {
      b = await prober.get(path, { slot: s, value: valueB });
      if (!(b.status >= 200 && b.status < 300 && b.jsonParsed)) continue;
    }
    const pointers = identityPointers(a, anon.get(path), b, [valueA, valueB]);
    if (!pointers.length) { noIdentity.add(path); continue; }
    const best = pointers[0];
    return { found: { path, slot: s, status: a.status, pointer: best.pointer, key: best.key, valueA: best.value, valueB: b === undefined ? undefined : valueAt(b.json, best.pointer), anonymousStatus: anon.get(path).status } };
  }
  return { found: null, tried: { routes: paths.length, slots: slots.length, cookieNames: names, byPath, noIdentity: [...noIdentity] } };
}

// Why discovery missed, from what came back: an unhealthy app, a session the slots tried did not carry, or routes that
// answered without naming each identity.
export function whoamiMiss(tried) {
  const statuses = [...tried.byPath.values()].flatMap(set => [...set]);
  const lines = [tried.unhealthy ? `tried ${tried.routes} route${tried.routes === 1 ? '' : 's'} signed out and one signed in, and stopped there` : `tried ${tried.routes} route${tried.routes === 1 ? '' : 's'} x ${tried.slots} credential slot${tried.slots === 1 ? '' : 's'}; none named each identity with its own value`];
  if (statuses.length && statuses.every(st => st === 'no answer' || st >= 500)) lines.push('every answer was a 5xx or no answer: is the app healthy? Warm a dev server up first (open one page) and check its own log');
  else {
    const refused = [...tried.byPath].filter(([, set]) => [...set].every(st => st === 401 || st === 403)).map(([path]) => path);
    if (refused.length) lines.push(`${refused.slice(0, 3).join(', ')} answered only 401 or 403 under every slot tried, so the session was not carried the way the app expects (cookie names tried: ${tried.cookieNames.slice(0, 8).join(', ')}${tried.cookieNames.length > 8 ? ', ...' : ''}); give --credential cookie:NAME or header:NAME`);
    if (tried.noIdentity.length) lines.push(`${tried.noIdentity.slice(0, 3).join(', ')} answered 2xx JSON for both identities but no field told them apart: check that the two sessions are different accounts, or give --whoami for a route that names the signed-in user`);
  }
  lines.push('if the app\'s who-am-I route is elsewhere (for example /api/dashboard/settings), give --whoami PATH and --credential SLOT');
  return lines.join('; ');
}

// GET one record path as its owner and signed out. The owner's parsed body stays in memory: init takes the record's
// own values from it (recordValues) and a record predicate (recordPredicate). Nothing of it is stored except the values
// the profile declares.
export async function probeRecord(prober, path, { slot, value }) {
  const owner = await prober.get(path, { slot, value });
  const anonymous = await prober.get(path);
  return { ownerStatus: owner.status, ownerJson: owner.jsonParsed, ownerBody: owner.jsonParsed ? owner.json : undefined,
    anonymousStatus: anonymous.status, anonymousRedirect: SIGN_IN_REDIRECTS.includes(anonymous.status) ? anonymous.status : null, anonymous: answerShape(anonymous) };
}

// One GET as another identity (the prohibited read, sent once during discovery under the confirmed authorization).
export async function probeAs(prober, path, { slot, value }) { return answerShape(await prober.get(path, { slot, value })); }

// The shape of an answer: its status and whether its JSON body is empty (an empty list, null or {}), populated, or not JSON.
export function answerShape(answer) {
  const json = answer.json;
  const shape = !answer.jsonParsed ? 'not-json' : json === null ? 'null' : Array.isArray(json) ? (json.length ? 'populated' : 'empty-array')
    : typeof json === 'object' ? (Object.keys(json).length ? 'populated' : 'empty-object') : 'populated';
  // A list wrapped in an object ({ data: [] }, { items: [], total: 0 }): an empty member named like a list of rows, whose
  // other members are all scalars. An empty "errors" or "warnings" array is not the list of rows.
  const members = shape === 'populated' && !Array.isArray(json) && typeof json === 'object' ? Object.entries(json) : [];
  const rows = members.filter(([key, v]) => Array.isArray(v) && /^(data|items|results|rows|records|entries|list|hits)$/i.test(key));
  const scalarsElsewhere = members.every(([key, v]) => (rows.length === 1 && key === rows[0][0]) || v === null || typeof v !== 'object');
  const wrapped = rows.length === 1 && rows[0][1].length === 0 && scalarsElsewhere ? `/${rows[0][0]}` : null;
  return { status: answer.status, shape: wrapped ? 'empty-wrapped' : shape, ...(wrapped ? { listPointer: wrapped } : {}), body: answer.jsonParsed ? json : undefined };
}

// The record's own values, for tenantValues: string leaves of the owner's body that a reader could not guess, from keys
// that name the record (ids, titles, names, emails) and not times or kinds. ASCII text of 3 to 200 characters with a
// letter or digit; one per loose reading; at most 12.
const VALUE_KEY = /(^|_)(id|uuid|slug|email|e-mail|title|name|label|subject|number|ref|reference|handle|phone|account)$/i;
const SKIP_KEY = /(created|updated|deleted|modified|date|time|_at$|^at$|kind|type|status|role|visibility|lang|locale|version)/i;
export function recordValues(json) {
  const out = [], loose = new Set();
  for (const [, key, raw] of leaves(json)) {
    if (!VALUE_KEY.test(key) || SKIP_KEY.test(key)) continue;
    const value = raw.trim();
    if (value.length < 3 || value.length > 200 || !/^[\x20-\x7e]+$/.test(value) || !/[A-Za-z0-9]/.test(value)) continue;
    const reading = value.toLowerCase().replace(/[^a-z0-9]/g, '');
    if (!reading || loose.has(reading)) continue;
    loose.add(reading); out.push(value);
    if (out.length >= 12) break;
  }
  return out;
}

// A predicate that shows the owner's record was served: json.equals on its most specific naming field.
export function recordPredicate(json) {
  const candidates = leaves(json).filter(([, key, value]) => VALUE_KEY.test(key) && !SKIP_KEY.test(key) && value.length >= 1 && value.length <= 200);
  const rankOf = key => ['id', 'uuid', 'slug', 'email', 'title', 'name', 'label'].indexOf(key.toLowerCase());
  candidates.sort((x, y) => ((rankOf(x[1]) + 8) % 8) - ((rankOf(y[1]) + 8) % 8) || x[0].length - y[0].length);
  return candidates.length ? { pointer: candidates[0][0], value: candidates[0][2] } : null;
}
