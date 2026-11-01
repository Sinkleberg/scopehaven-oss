// Run model identity: which models served the calls in one window of a model
// tap log, and how strongly each one is identified.
//
// Strength, weakest to strongest:
//   requested-only       the application asked for a name; no response named a model
//   vendor-model-string  the response named the model
//   vendor-fingerprint   the response also carried a system_fingerprint
//   weights-digest       a local Ollama server listed the same weights digest for
//                        that name before and after the window
// A vendor's model string and fingerprint are the vendor's own readings; only a
// local server's digest names weights, and only as that server reports them.
//
// States: observed (one model), mixed (several), not-observed (no successful
// call), partial (something in the window cannot be vouched for, including a
// successful call that identified no model at all). Routing is declared by the
// operator: the tap sees only the calls sent through it, so "not-observed" never
// means "no model was used".
import { readFileSync } from 'node:fs';
import { digest } from '../../src/domain.mjs';
import { ollamaName, TAP_SCHEMA, CHAIN_START, chainHash, upstreamKind } from './tap.mjs';

export const IDENTITY_SCHEMA = 'scopehaven-model-identity/2';
export const STRENGTHS = Object.freeze(['none', 'requested-only', 'vendor-model-string', 'vendor-fingerprint', 'weights-digest']);
export const weakest = list => list.length ? STRENGTHS[Math.min(...list.map(s => STRENGTHS.indexOf(s)))] : 'none';
// Gaps that put every later position of the log in doubt, wherever they sit.
const LOG_GAPS = new Set(['unreadable-log-line', 'log-seq-break', 'log-chain-break', 'log-write-failed']);

// Frames of a tap log file. A line that does not parse, a sequence number that
// does not follow the previous one (a removed, inserted, duplicated or reordered
// line) or a hash that does not chain to the previous line (an edited line)
// becomes a gap at that position.
export function readTapLog(path) {
  const frames = [];
  let expected = 1, head = CHAIN_START, chained = true;
  for (const line of readFileSync(path, 'utf8').split('\n')) {
    if (!line) continue;
    let frame;
    try { frame = JSON.parse(line); } catch { frames.push({ kind: 'gap', reason: 'unreadable-log-line', seq: expected++ }); chained = false; continue; }
    if (!frame || typeof frame !== 'object' || !Number.isInteger(frame.seq)) { frames.push({ kind: 'gap', reason: 'unreadable-log-line', seq: expected++ }); chained = false; continue; }
    if (frame.seq !== expected) frames.push({ kind: 'gap', reason: 'log-seq-break', seq: frame.seq, logGap: true });
    const { h, ...body } = frame;
    if (chained && (typeof h !== 'string' || h !== chainHash(head, body))) { frames.push({ kind: 'gap', reason: 'log-chain-break', seq: frame.seq, logGap: true }); chained = false; }
    if (typeof h === 'string') head = h;
    frames.push(frame);
    expected = frame.seq + 1;
  }
  return frames;
}

const digestOf = (snapshot, served) => snapshot?.available === true && Array.isArray(snapshot.models) ? snapshot.models.find(m => m.name === ollamaName(served))?.digest ?? null : null;
const listed = (snapshot, served) => snapshot?.available === true && Array.isArray(snapshot.models) && snapshot.models.some(m => m.name === ollamaName(served));
const uniqueSorted = list => [...new Set(list)].sort();

// from/to are log sequence numbers: the window holds frames with from < seq <= to.
// The default window is the whole log, which must then be closed. An explicit
// window's boundaries must be lines that exist in the log.
export function modelIdentity(frames, { from = 0, to = Infinity } = {}) {
  if (!Array.isArray(frames)) throw new Error('Tap log frames must be an array.');
  if (!Number.isInteger(from) || from < 0 || !(to === Infinity || (Number.isInteger(to) && to >= from))) throw new Error('A window needs integer sequence numbers with 0 <= from <= to.');
  const reasons = [];
  const numbered = frames.filter(f => Number.isInteger(f.seq));
  const upTo = numbered.filter(f => f.seq <= to);
  const inWindow = f => Number.isInteger(f.seq) && f.seq > from && f.seq <= to;
  const open = upTo.find(f => f.kind === 'open');
  if (!open || open.schema !== TAP_SCHEMA || open.seq !== 1) reasons.push('tap-not-open-before-window');
  if (upTo.filter(f => f.kind === 'open').length > 1) reasons.push('tap-reopened');
  if (to === Infinity && !frames.some(f => f.kind === 'close')) reasons.push('tap-not-closed');
  if (to !== Infinity && !numbered.some(f => f.seq === to && f.kind !== 'gap')) reasons.push('window-end-missing');
  if (from > 0 && !numbered.some(f => f.seq === from && f.kind !== 'gap')) reasons.push('window-start-missing');
  if (upTo.some(f => f.kind === 'overflow')) reasons.push('log-overflow');
  // A call the application abandoned before any of its answer arrived carried no model
  // output into the run: it is counted, not a gap. One abandoned mid-answer is a gap.
  const undelivered = f => f.kind === 'gap' && f.reason === 'client-closed' && f.delivered === 0;
  // A broken log anywhere puts every window in doubt: a writer who re-chains up to one
  // window's end still breaks the chain after it.
  for (const f of frames) if (f.kind === 'gap' && !undelivered(f) && (inWindow(f) || LOG_GAPS.has(f.reason))) reasons.push(f.reason);

  const calls = upTo.filter(f => f.kind === 'call' && inWindow(f));
  const allCalls = upTo.filter(f => f.kind === 'call');
  const results = upTo.filter(f => f.kind === 'result');
  // A result in the window whose call came before it: that call's tokens reached the
  // application inside the window, so the window cannot be read without it.
  for (const r of results.filter(inWindow)) {
    const call = allCalls.find(c => c.conn === r.conn && c.seq < r.seq);
    if (!call) reasons.push('result-without-call');
    else if (!inWindow(call)) reasons.push('call-started-before-window');
  }
  const snapshots = upTo.filter(f => f.kind === 'models');
  const first = calls[0]?.seq ?? Infinity;
  const startSnap = snapshots.filter(f => f.seq <= Math.max(from, 0) || (from === 0 && f.seq < first)).at(-1) ?? null;
  // The closing list must come after every call and every result in the window.
  const lastActivity = Math.max(from, ...upTo.filter(f => inWindow(f) && (f.kind === 'call' || f.kind === 'result')).map(f => f.seq));
  const endSnap = snapshots.filter(f => inWindow(f) && f.seq > lastActivity).at(-1) ?? null;
  // A list the operator asked for (ollamaTags) that failed leaves the weights unnamed.
  const listRequested = open?.ollamaTags !== false;
  if (calls.length && listRequested) for (const snap of [startSnap, endSnap]) reasons.push(...(!snap ? ['model-list-not-bracketing'] : snap.available !== true ? ['model-list-unavailable'] : []));

  const entries = new Map();
  let succeeded = 0, failed = 0, abandoned = 0;
  const replaced = [];
  for (const call of calls) {
    const result = results.find(r => r.conn === call.conn && r.seq > call.seq);
    if (!result) { if (upTo.some(g => undelivered(g) && g.conn === call.conn && g.seq > call.seq)) abandoned++; else reasons.push('call-without-result'); continue; }
    if (typeof result.gap === 'string') reasons.push(result.gap);
    if (!Number.isInteger(result.status) || result.status < 200 || result.status > 299) { failed++; continue; }
    succeeded++;
    const served = Array.isArray(result.served) ? result.served : [];
    const fingerprints = Array.isArray(result.fingerprints) ? result.fingerprints : [];
    const keys = served.length ? served.map(s => `served:${s}`) : [`requested:${call.requested ?? ''}`];
    for (const key of keys) {
      const e = entries.get(key) ?? { served: key.startsWith('served:') ? key.slice(7) : null, requested: [], fingerprints: [], apis: [], calls: 0, fingerprinted: 0 };
      e.calls++; if (call.requested) e.requested.push(call.requested); e.fingerprints.push(...fingerprints); e.apis.push(call.api); if (fingerprints.length) e.fingerprinted++;
      entries.set(key, e);
    }
  }

  const models = [...entries.values()].map(e => {
    let weightsDigest = null;
    if (e.served && listRequested && startSnap?.available === true && endSnap?.available === true) {
      // Every list from the one before the window to the closing one, marks included.
      const lists = [startSnap, ...snapshots.filter(f => inWindow(f) && f.seq < endSnap.seq), endSnap].filter(l => l.available === true);
      const digests = lists.map(l => digestOf(l, e.served));
      const present = digests.filter(Boolean);
      if (present.length === digests.length && new Set(present).size === 1) weightsDigest = present[0];
      else if (new Set(present).size > 1) { reasons.push('model-replaced-in-window'); replaced.push({ served: e.served, before: present[0], after: present.find(d => d !== present[0]) }); }
      else if (present.length) reasons.push('model-list-changed-in-window');
      else reasons.push('served-model-not-listed');
    }
    const fingerprints = uniqueSorted(e.fingerprints);
    // A fingerprint grades the model only when every call that model answered carried one.
    const strength = weightsDigest ? 'weights-digest' : fingerprints.length && e.served && e.fingerprinted === e.calls ? 'vendor-fingerprint' : e.served ? 'vendor-model-string' : e.requested.length ? 'requested-only' : 'none';
    if (strength === 'none') reasons.push('model-not-identified');
    return { served: e.served, requested: uniqueSorted(e.requested), fingerprints, weightsDigest, apis: uniqueSorted(e.apis), calls: e.calls, strength };
  }).sort((a, b) => String(a.served ?? `~${a.requested[0] ?? ''}`).localeCompare(String(b.served ?? `~${b.requested[0] ?? ''}`)));

  const uniqueReasons = uniqueSorted(reasons);
  const state = uniqueReasons.length ? 'partial' : !models.length ? 'not-observed' : models.length === 1 ? 'observed' : 'mixed';
  const tuple = m => m.strength === 'weights-digest' ? { served: m.served, weightsDigest: m.weightsDigest }
    : m.strength === 'vendor-fingerprint' ? { served: m.served, fingerprints: m.fingerprints }
    : m.strength === 'vendor-model-string' ? { served: m.served } : { requested: m.requested };
  const last = upTo.filter(f => typeof f.h === 'string').at(-1);
  return { schema: IDENTITY_SCHEMA, state, strength: weakest(models.map(m => m.strength)), models, key: models.length ? digest(models.map(tuple)) : null,
    calls: { total: calls.length, succeeded, failed, abandoned }, replaced, reasons: uniqueReasons, window: { from, to: to === Infinity ? null : to },
    tapSession: typeof open?.session === 'string' ? open.session : null, upstream: typeof open?.upstream === 'string' ? open.upstream : null,
    // hosted: every model reading is the vendor's own (model string, fingerprint); never weights.
    upstreamKind: upstreamKind(open?.upstream),
    head: last?.h ?? null, routing: 'declared-by-operator' };
}
