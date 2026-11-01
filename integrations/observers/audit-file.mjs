// Audit-log file observer: reads an application's own request-path audit log
// (JSON lines, one per answered request), for example Open WebUI's
// $DATA_DIR/audit.log. It is authoritative only when every line in a window
// is accounted for, so it is deliberately strict:
//   - every line must parse, carry a method and a request URI on the declared
//     origin (exact scheme, host and port; the app may build the URI from the
//     client's Host header), and a plain path (no ";" parameters, "//" or dot
//     segments); otherwise the window is partial
//   - every line must match exactly one rule, or a declared ignore entry; an
//     unknown or ambiguous line makes the window partial
//   - only an integer 2xx status is committed; a status in a rule's
//     refusedStatuses is 'denied' (an operator assertion, like a response
//     contract); a missing or non-integer status ("audit-status-missing") or
//     any other status ("audit-status-undecided") keeps the window partial
//   - the logged path is used as logged: frameworks such as Starlette log the
//     already-decoded path, so it is never decoded again. A "?" that could
//     belong to the path (the query and path reading disagree on the route)
//     makes the line ambiguous, and a control character makes it unreadable
//
// rules:  [{ name, method, path, operation?, refusedStatuses? }] - effects, named by rule
// ignore: [{ method?, path }] - routes that are audited but never an effect for these checks
//   path is a template: "/api/v1/knowledge/{id}/update" ({x} matches one segment).
// actors: { <principal>: <value of the log's actor field> }; any other value is "unlisted:".
// origin: the application's origin as it appears in the log, e.g. "http://127.0.0.1:4420".
// witness: a rule the test itself issues once at the END of each window, after
//   the agent has finished, with the query parameter scopehaven_witness=<nonce>
//   where <nonce> is the start mark's witnessNonce. The window is complete only
//   when that exact witness line is present, no rule line follows it, and the
//   end mark was not taken in the middle of a line. The witness line is the
//   test's own request, never an effect; a witness line from another window
//   makes the window partial.
// Settle: collect() waits up to settleMs for the witness, then keeps reading
//   past the end mark until the file has not grown at all for quietMs (bytes
//   of a line still being written count as growth). Lines that arrive in that
//   time are read like any other: a committed rule line counts (and, after the
//   witness, also makes the window partial). A line still incomplete when
//   collect() returns makes the window partial. A writer that pauses longer
//   than quietMs between lines after the witness is not observed: that bound
//   is the observer's declared limit.
// Late collect: the extension past the end mark is only taken when collect()
//   starts right after the end mark. A later collect() reads [from, to] only,
//   and anything written after the end mark makes the window partial.
// Rotation: each mark compares the file's inode with the previous mark (or
//   start()); a window that starts on a file replaced since then fails, since
//   the writer may still hold the old file open. Rotation before start() is
//   not detected: the app must reopen its log before testing starts.
// Windows are byte ranges of the file. Each mark fingerprints the bytes just
// before its position, and every byte already read must stay unchanged until
// collect() returns, so a file that shrank, was replaced (rotation) or was
// truncated in place and regrown (copytruncate) fails the window.
import { statSync, openSync, readSync, closeSync, existsSync } from 'node:fs';
import { randomUUID, createHash, createHmac, randomBytes } from 'node:crypto';
import { digest } from '../../src/domain.mjs';
import { makeEffect, OPERATIONS } from './events.mjs';
import { compileAuditPath as compilePath, AUDIT_FILE_METHODS as METHODS } from '../../src/audit-file-rules.mjs';

// At most this many '?' positions are read per logged URI; a URI with more is ambiguous, never
// classified. Each reading is a full scan of its prefix, so the cap keeps one line linear.
export const AUDIT_FILE_MAX_QUERY_CUTS = 16;
export const AUDIT_FILE_LIMITS = Object.freeze({ windowBytes: 16 * 1024 * 1024, lineBytes: 256 * 1024, rules: 64, settleMs: 3000, quietMs: 300, fingerprintBytes: 4096, pollMs: 100, lateCollectMs: 250 });
const pointer = (root, path) => {
  let value = root;
  for (const token of path === '' ? [] : path.slice(1).split('/').map(t => t.replaceAll('~1', '/').replaceAll('~0', '~'))) {
    if (['__proto__', 'prototype', 'constructor'].includes(token) || value === null || typeof value !== 'object' || !Object.hasOwn(value, token)) return undefined;
    value = value[token];
  }
  return value;
};

// Defaults fit Open WebUI's audit log (verb, request_uri, response_status_code, user.id).
export const OPEN_WEBUI_FIELDS = Object.freeze({ method: '/verb', uri: '/request_uri', status: '/response_status_code', actor: '/user/id' });

export function createAuditFileObserver({ instanceId = 'audit-file-1', path, origin, rules, ignore = [], actors = {}, fields = OPEN_WEBUI_FIELDS, witness, settleMs = AUDIT_FILE_LIMITS.settleMs, quietMs = AUDIT_FILE_LIMITS.quietMs }) {
  if (!Number.isInteger(settleMs) || settleMs < 0 || settleMs > 30000 || !Number.isInteger(quietMs) || quietMs < 100 || quietMs > 10000) throw new Error('The witness wait (witnessWaitMs) must be 0-30000 ms and quietMs 100-10000 ms.');
  if (typeof path !== 'string' || !path) throw new Error('Declare the audit log file path.');
  let expected;
  try { expected = new URL(origin); } catch { throw new Error('Declare the application origin as it appears in the log ("origin").'); }
  if (!['http:', 'https:'].includes(expected.protocol) || expected.pathname !== '/' || expected.search || expected.hash || expected.username || expected.password) throw new Error('"origin" must be scheme://host:port only.');
  const originPrefix = `${expected.protocol}//${expected.host}`;
  if (!Array.isArray(rules) || !rules.length || rules.length > AUDIT_FILE_LIMITS.rules) throw new Error('Declare 1 to 64 audit rules.');
  const compiled = rules.map(rule => {
    if (!/^[A-Za-z0-9_.:-]{1,128}$/.test(rule.name || '') || !METHODS.includes(rule.method)) throw new Error('Each audit rule needs a name and an HTTP method.');
    if (rule.operation !== undefined && !OPERATIONS.includes(rule.operation)) throw new Error('Audit rule operations must be supported operations.');
    if (rule.refusedStatuses !== undefined && !(Array.isArray(rule.refusedStatuses) && rule.refusedStatuses.every(s => Number.isInteger(s) && s >= 400 && s <= 499))) throw new Error('refusedStatuses may only list 4xx statuses.');
    return { ...rule, operation: rule.operation ?? 'update', regex: compilePath(rule.path), refused: rule.refusedStatuses ?? [] };
  });
  if (new Set(compiled.map(r => r.name)).size !== compiled.length) throw new Error('Audit rule names must be unique.');
  if (!Array.isArray(ignore) || ignore.length > 256 || !ignore.every(i => i && (i.method === undefined || METHODS.includes(i.method)))) throw new Error('"ignore" lists { method?, path } templates.');
  const ignored = ignore.map(i => ({ method: i.method, regex: compilePath(i.path) }));
  if (!compiled.some(r => r.name === witness)) throw new Error('"witness" must name one of the rules.');
  const byValue = new Map(Object.entries(actors).map(([principal, value]) => [String(value), principal]));
  const observer = { kind: 'audit-log-file', instanceId };
  // An actor that is not a declared principal, and the line it came from, are kept only as digests keyed with a secret
  // this observer never stores: an unkeyed hash of a guessable value (an email, a user id) is confirmed by hashing guesses.
  const key = randomBytes(32), keyed = value => createHmac('sha256', key).update(digest(value)).digest('hex');

  const readRange = (fd, start, end) => { const buf = Buffer.alloc(end - start); readSync(fd, buf, 0, buf.length, start); return buf; };
  // The inode the previous mark (or start()) saw: a mark on a different file flags rotation.
  let knownIno = null;
  // Where the log ended when the witness request was sent, per window nonce: anything
  // logged after it may be the witness route's own doing and is never attributed.
  const witnessRequestAt = new Map();
  // End-mark nonce -> the byte offset where its window stopped attributing lines: where a settlement
  // gap window (src/http-settlement.mjs) that starts at that end mark begins.
  const attributedThrough = new Map();
  // The end of the last complete line, a fingerprint of the bytes before it, and the file identity.
  const position = () => {
    if (!existsSync(path)) return { ok: false, reason: 'audit-file-missing' };
    const fd = openSync(path, 'r');
    try {
      const st = statSync(path);
      let pos = st.size;
      if (pos > 0) {
        const tailStart = Math.max(0, pos - AUDIT_FILE_LIMITS.lineBytes), tail = readRange(fd, tailStart, pos), cut = tail.lastIndexOf(0x0a);
        pos = cut < 0 ? tailStart : tailStart + cut + 1;
      }
      const fpStart = Math.max(0, pos - AUDIT_FILE_LIMITS.fingerprintBytes);
      return { ok: true, pos, size: st.size, at: Date.now(), ino: st.ino, partialTail: st.size > pos, fingerprint: { start: fpStart, sha256: createHash('sha256').update(readRange(fd, fpStart, pos)).digest('hex') }, witnessNonce: randomUUID() };
    } finally { closeSync(fd); }
  };
  // The content that a cursor saw is still there, byte for byte.
  const stillThere = cursor => {
    if (!existsSync(path)) return false;
    const st = statSync(path);
    if (st.ino !== cursor.ino || st.size < cursor.pos) return false;
    const fd = openSync(path, 'r');
    try { return createHash('sha256').update(readRange(fd, cursor.fingerprint.start, cursor.pos)).digest('hex') === cursor.fingerprint.sha256; } finally { closeSync(fd); }
  };
  // The route a logged path names: one rule, ignored, unknown, ambiguous or unreadable.
  const routeOf = (verb, path) => {
    if (/[\u0000-\u001f\u007f]/.test(path) || /\/\/|;|\/\.\.?(\/|$)/.test(path)) return { kind: 'unreadable' };
    const matched = compiled.filter(r => r.method === verb && r.regex.test(path));
    if (matched.length > 1) return { kind: 'ambiguous' };
    if (!matched.length) return ignored.some(i => (!i.method || i.method === verb) && i.regex.test(path)) ? { kind: 'ignored' } : { kind: 'unknown-route' };
    return { kind: 'rule', rule: matched[0] };
  };
  const classify = (line, from) => {
    let entry;
    try { if (Buffer.byteLength(line) > AUDIT_FILE_LIMITS.lineBytes) throw new Error(); entry = JSON.parse(line); } catch { return { kind: 'unreadable' }; }
    const method = pointer(entry, fields.method), uri = pointer(entry, fields.uri);
    if (typeof method !== 'string' || !METHODS.includes(method.toUpperCase()) || typeof uri !== 'string') return { kind: 'unreadable' };
    // The URI must name the declared origin exactly; anything else (a crafted Host header) is unreadable.
    if (!uri.startsWith(`${originPrefix}/`)) return { kind: 'unreadable' };
    let url;
    try { url = new URL(uri); } catch { return { kind: 'unreadable' }; }
    if (url.protocol !== expected.protocol || url.host !== expected.host || url.username || url.password || url.hash) return { kind: 'unreadable' };
    // The logged path is already decoded: use it as logged. The first "?" is read as
    // the query start, but any "?" could be part of a decoded path: when another
    // reading names a rule or an ignored route the first reading does not, the line
    // is ambiguous (a reading that names no known route cannot hide an effect).
    const verb = method.toUpperCase(), rest = uri.slice(originPrefix.length);
    const cuts = [...rest.matchAll(/\?/g)].map(m => m.index);
    if (cuts.length > AUDIT_FILE_MAX_QUERY_CUTS) return { kind: 'ambiguous' };
    const readings = [...cuts.map(i => rest.slice(0, i)), rest].map(path => ({ path, route: routeOf(verb, path) }));
    const key = r => r.route.kind === 'rule' ? `rule:${r.route.rule.name}` : r.route.kind;
    if (readings.slice(1).some(r => ['rule', 'ignored'].includes(r.route.kind) && key(r) !== key(readings[0]))) return { kind: 'ambiguous' };
    const { path, route } = readings[0];
    if (route.kind !== 'rule') return { kind: route.kind };
    const rule = route.rule;
    const rawStatus = pointer(entry, fields.status);
    // Only an integer status counts; "2e2", " 403 " or null are missing.
    const status = Number.isInteger(rawStatus) && rawStatus >= 100 && rawStatus <= 599 ? rawStatus : null;
    const actorValue = pointer(entry, fields.actor);
    const actor = actorValue === undefined || actorValue === null ? null : byValue.get(String(actorValue)) ?? `unlisted:${keyed(String(actorValue)).slice(0, 16)}`;
    const witnessParams = url.searchParams.getAll('scopehaven_witness');
    const isWitness = rule.name === witness && witnessParams.length === 1 && witnessParams[0] === from.witnessNonce;
    return { kind: 'rule', rule, status, actor, path, isWitness, foreignWitness: !isWitness && witnessParams.length > 0,
      outcome: status !== null && status >= 200 && status <= 299 ? 'committed' : status !== null && rule.refused.includes(status) ? 'denied' : 'unknown' };
  };
  function gapWindow(from, to) {
    const startPos = attributedThrough.get(from.witnessNonce) ?? from.pos;
    if (startPos > to.pos) return { events: [], coverage: 'failed', reason: 'audit-file-truncated-or-rotated' };
    if (to.pos - startPos > AUDIT_FILE_LIMITS.windowBytes) return { events: [], coverage: 'partial', reason: 'audit-window-too-large' };
    const fd = openSync(path, 'r');
    let list;
    try { list = readRange(fd, startPos, to.pos).toString('utf8').split('\n').filter(Boolean); } finally { closeSync(fd); }
    const problems = new Set(), events = [];
    let offset = startPos;
    for (const line of list) {
      const at = offset; offset += Buffer.byteLength(line) + 1;
      const c = classify(line, from);
      if (c.kind === 'ignored') continue;
      if (c.kind !== 'rule') { problems.add(`${c.kind}-audit-line`); continue; }
      if (c.isWitness || c.foreignWitness) continue;
      if (c.status === null) problems.add('audit-status-missing');
      else if (c.outcome === 'unknown') problems.add('audit-status-undecided');
      events.push(makeEffect({ source: 'file-audit-log', observer, seq: at + 1, actor: c.actor, operation: c.rule.operation, name: c.rule.name, resource: c.path.slice(0, 200),
        outcome: c.outcome, correlation: {}, content: keyed(line) }));
    }
    if (to.partialTail) problems.add('end-mark-inside-a-line');
    const reason = problems.size ? [...problems].sort().join(',').slice(0, 200) : null;
    return { events, coverage: reason ? 'partial' : 'complete', reason };
  }
  return {
    kind: observer.kind, instanceId, source: 'file-audit-log',
    // Whether a request (method, origin-form path) is logged as the witness rule.
    witnessRouteMatches: (method, requestPath) => { const rule = compiled.find(r => r.name === witness); return typeof requestPath === 'string' && rule.method === method && rule.regex.test(requestPath.split('?')[0]); },
    scope: Object.freeze({ operations: [...new Set(compiled.map(r => r.operation))], names: compiled.map(r => r.name), actorAttribution: 'principal', evidence: 'authoritative' }),
    // Called by the connector immediately before it sends this window's witness request.
    markWitnessRequest(from) { if (from?.ok && typeof from.witnessNonce === 'string') { const p = position(); if (p.ok) witnessRequestAt.set(from.witnessNonce, p.size); } },
    async start() { const p = position(); if (!p.ok) throw new Error(p.reason); knownIno = p.ino; },
    async mark() {
      const p = position();
      if (p.ok) { const rotated = knownIno !== null && p.ino !== knownIno; knownIno = p.ino; return { ...p, rotated }; }
      return p;
    },
    // gap: a settlement gap window, an exact range from where the previous window stopped attributing
    // lines to this end mark: no witness, no waiting, and every witness line skipped (never an effect).
    async collect(from, to, { gap = false } = {}) {
      const failed = reason => ({ events: [], coverage: 'failed', reason });
      if (!from.ok || !to.ok) return failed((from.ok ? to : from).reason);
      if (from.rotated) return failed('audit-file-rotated-before-window');
      if (to.pos < from.pos || to.ino !== from.ino || !stillThere(from) || !stillThere(to)) return failed('audit-file-truncated-or-rotated');
      if (gap) return gapWindow(from, to);
      if (to.pos - from.pos > AUDIT_FILE_LIMITS.windowBytes) return { events: [], coverage: 'partial', reason: 'audit-window-too-large' };
      const rangeHash = (start, stop) => { const fd = openSync(path, 'r'); try { return createHash('sha256').update(readRange(fd, start, stop)).digest('hex'); } finally { closeSync(fd); } };
      // Every byte already read stays unchanged until collect() returns: same file, no
      // shrink below what was read, both mark fingerprints and the read range intact.
      let end = to, readHash = rangeHash(from.pos, end.pos);
      const intact = now => now.ok && now.ino === from.ino && now.pos >= end.pos && stillThere(from) && stillThere(to) && rangeHash(from.pos, end.pos) === readHash;
      const lines = () => { const fd = openSync(path, 'r'); try { return readRange(fd, from.pos, end.pos).toString('utf8').split('\n').filter(Boolean); } finally { closeSync(fd); } };
      // classify() is pure for a given line and window, so each line is classified once per collect().
      const classified = new Map(), classifyOnce = line => { if (!classified.has(line)) classified.set(line, classify(line, from)); return classified.get(line); };
      const hasWitness = list => list.some(line => { const c = classifyOnce(line); return c.kind === 'rule' && c.isWitness; });
      const problems = new Set();
      // Wait up to settleMs for this window's witness, then keep reading until the
      // file has not grown for quietMs. Lines that arrive meanwhile are read too.
      // Only a collect() that starts right after the end mark may extend past it.
      let list = lines(), waitedMs = 0, quietFor = 0, witnessFound = hasWitness(list), stillGrowing = false, lastSize = position().size;
      const late = Date.now() - to.at > AUDIT_FILE_LIMITS.lateCollectMs;
      if (late) { if (lastSize > to.pos) problems.add('audit-collect-late'); }
      else {
        const capMs = settleMs + 10 * quietMs;
        while (witnessFound ? quietFor < quietMs : waitedMs < settleMs) {
          if (waitedMs >= capMs) { stillGrowing = true; break; }
          await new Promise(resolve => setTimeout(resolve, AUDIT_FILE_LIMITS.pollMs)); waitedMs += AUDIT_FILE_LIMITS.pollMs;
          const now = position();
          if (!intact(now)) return failed('audit-file-truncated-or-rotated');
          // Any growth, including bytes of a line not yet ended, is activity.
          const grew = now.size !== lastSize; lastSize = now.size;
          if (now.pos > end.pos) {
            if (now.pos - from.pos > AUDIT_FILE_LIMITS.windowBytes) return { events: [], coverage: 'partial', reason: 'audit-window-too-large' };
            end = now; readHash = rangeHash(from.pos, end.pos); list = lines();
            if (!witnessFound && hasWitness(list)) witnessFound = true;
          }
          quietFor = grew ? 0 : quietFor + AUDIT_FILE_LIMITS.pollMs;
        }
      }
      const last = position();
      if (!intact(last)) return failed('audit-file-truncated-or-rotated');
      // Anything past what was read when collect() returns: a line still being written, or
      // (on a prompt collect) growth after the quiet period ended. Not covered.
      if (!late && last.size > end.pos) problems.add(last.pos > end.pos ? 'audit-log-grew-at-collect' : 'audit-line-incomplete-at-collect');
      const events = [];
      const requestAt = witnessRequestAt.get(from.witnessNonce) ?? Infinity; witnessRequestAt.delete(from.witnessNonce);
      let offset = from.pos, witnessSeen = false, boundary = end.pos;
      for (const line of list) {
        const at = offset; offset += Buffer.byteLength(line) + 1;
        // Lines from the witness request (or the witness) on are not this window's: a gap window starts there.
        if (boundary === end.pos && (at >= requestAt || witnessSeen)) boundary = at;
        const c = classifyOnce(line);
        if (c.kind === 'ignored') continue;
        if (c.kind !== 'rule') { problems.add(`${c.kind}-audit-line`); continue; }
        // The witness is the test's own request, never an effect of its rule.
        if (c.isWitness) { if (boundary === end.pos) boundary = at; if (witnessSeen) problems.add('duplicate-audit-witness'); witnessSeen = true; continue; }
        if (c.foreignWitness) { problems.add('foreign-audit-witness'); continue; }
        // A rule line after the witness, or logged after the witness request was sent, cannot be
        // attributed to the check (it may be the witness route's own doing or a later action):
        // the window is partial, and the line never satisfies effect.exists or effect.count.
        if (witnessSeen) { problems.add('rule-line-after-witness'); continue; }
        if (at >= requestAt) { problems.add('audit-line-after-witness-request'); continue; }
        if (c.status === null) problems.add('audit-status-missing');
        else if (c.outcome === 'unknown') problems.add('audit-status-undecided');
        events.push(makeEffect({ source: 'file-audit-log', observer, seq: at + 1, actor: c.actor, operation: c.rule.operation, name: c.rule.name, resource: c.path.slice(0, 200),
          outcome: c.outcome, correlation: {}, content: keyed(line) }));
      }
      attributedThrough.set(to.witnessNonce, boundary);
      if (!witnessSeen) problems.add('audit-witness-not-logged');
      if (stillGrowing) problems.add('audit-log-still-growing');
      // The end mark was taken while a line was being written: that line is not covered.
      if (end.partialTail) problems.add('end-mark-inside-a-line');
      this.lastFreshness = { waitedMs, extendedPastMarkBytes: end.pos - to.pos, witnessSeen };
      const reason = problems.size ? [...problems].sort().join(',').slice(0, 200) : null;
      return { events, coverage: reason ? 'partial' : 'complete', reason };
    },
    async stop() {},
  };
}
