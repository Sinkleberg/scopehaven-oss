// Watch-first drafting: a profile drafted from what the target did in one watch run (watch.mjs), for a person to approve.
// The draft follows policy-import's draft (integrations/policy-import/draft.mjs): proposals only, each with one provenance
// entry, the turns not drafted listed with the reason, warnings, and a draftId over the canonical body. Where policy-import
// marks a whole draft "confirmed": false, every drafted line here carries "drafted": "observed" and "approved": false
// (lines.mjs), so the profile itself refuses to load until a person approves each line.
// For each write turn (a turn whose judged windows hold a committed insert, update, delete, send or access change), in order:
//   WF-<turn>-USE   its allowed-use twin: a required control repeating the turn, with an effect.count per expected
//                   effect, so an application that refuses everything cannot pass the ONLY check
//   WF-<turn>-ONLY  the turn again, with effect.only: the effects the watch saw, each with its observed count, and
//                   nothing else, over the sources that could decide it (authoritative windows complete on every write turn)
// The twin goes first: its effects settle before the ONLY window opens. After it, the same effect made again would be read
// by the settlement rule (src/http-settlement.mjs) as possibly the ONLY check's own late effect, which holds it undecided.
// A resource is pinned only when the turn's path names its last segment (the object the request named); a resource the
// application generated (a new row id) is left open. An actor is pinned when the observer named one. An observer names a
// principal it does not declare by a keyed digest ("unlisted:..."), which no draft can read back; when the turn's own actor
// is not among that observer's principals, the draft pins the turn actor's principalId and drafts the observer with it
// added (an inference, cited as one). A write attributed to anyone else (another declared principal, or an unlisted one
// while the turn's actor is declared) is not proposed: that turn is not drafted, and the report says why.
// Observers are kept as the operator declared them, never narrowed to what was seen: a snapshot cut down to the tables
// one run wrote would be blind to a collateral write anywhere else. The draft report lists what was seen (destinations
// and the declared paths they hit, tables written, audit actions, identities used), and an observer whose declared
// principals miss an identity it attributed is drafted with that identity added. Columns are not recorded by any
// observer (events carry a digest of the row, never its fields), so none are drafted.
// No model is called anywhere in this module: every line is a proposal computed from recorded events.
import { canonical, sha256 } from '../policy-import/matrix.mjs';
import { validateTargetFile } from '../../src/contracts.mjs';
import { PRESENCE_ONLY_SOURCES } from '../../src/effect-events.mjs';
import { knownNegativeTarget } from '../../src/known-negative.mjs';
import { custodyOf } from '../../src/custody.mjs';
import { validateWatch, watchId, verifyRecordId } from './watch.mjs';
import { admitDraftedLines, approveLines } from './lines.mjs';

export const WATCH_DRAFT_SCHEMA = 'scopehaven-watch-draft/1';
export const WRITE_OPERATIONS = Object.freeze(['insert', 'update', 'delete', 'send', 'access-change']);
const SEND_SOURCES = ['http-egress', 'smtp-capture', 'provider-feed'];
const AUDIT_SOURCES = ['sql-audit-table', 'http-audit-log', 'file-audit-log'];
// A profile file holds at most 20 targets (src/contracts.mjs validateTargetFile).
const TARGETS_PER_PROFILE = 20;
const ok2xx = status => Number.isInteger(status) && status >= 200 && status <= 299;
// A resource names the request's object only when the turn's path names it: its type and id as consecutive path segments
// (orders/B-1 in /api/orders/B-1/refunds), or its last segment alone when that is not a bare number (B-1 in an egress
// resource POST /v1/refunds/B-1). A generated row id that happens to equal a number in the path (refunds/1 beside
// /api/orders/1/refunds) is not pinned.
const segmentsOf = text => text.split('?')[0].split('/').filter(Boolean);
function pathNames(path, resource) {
  if (typeof resource !== 'string') return false;
  const turn = segmentsOf(path), parts = segmentsOf(resource.replace(/^[A-Z]+ /, '')), last = parts.at(-1);
  if (last === undefined || last === '*') return false;
  if (parts.length >= 2 && turn.some((seg, i) => seg === parts.at(-2) && turn[i + 1] === last)) return true;
  return !/^\d+$/.test(last) && turn.includes(last);
}

const UNLISTED = /^unlisted:[0-9a-f]{16}$/;
// The selector a committed event proposes, and the key events share when they are the same expected effect. actor: the
// principal the selector pins (the event's, or the one inferred for an unlisted digest), or null for none.
function selectorOf(event, turn, actor) {
  return { source: event.source, ...(actor !== null ? { actor } : {}), operation: event.operation, name: event.name,
    ...(pathNames(turn.path, event.resource) ? { resource: event.resource } : {}) };
}
const CUSTODY_RANK = { 'subject-writable': 0, 'observer-held': 1, independent: 2 };

/** Drafts a profile from a watch file and the record of its watch run. Returns { profile, report }: the profile with
 * every drafted line unapproved, and the draft report (scopehaven-watch-draft/1). Refuses a record that is edited or
 * from another watch file, and a draft with no line to propose. With more than one write turn, each is drafted in a target
 * of its own: in one run a later turn's write fits an earlier effect.only clause's absence half, and the settlement rule
 * then holds that clause undecided. */
export function draftFromWatch(watch, record) {
  validateWatch(watch);
  if (!verifyRecordId(record)) throw new Error('The watch record is missing or was edited without recomputing its recordId (a checksum, not a signature).');
  if (record.watchId !== watchId(watch)) throw new Error('The watch record is not from this watch file (its watchId differs).');
  if (record.turns.length !== watch.turns.length || record.turns.some((t, i) => t.id !== watch.turns[i].id)) throw new Error('The watch record\'s turns are not this watch file\'s.');
  const configs = watch.target.observers ?? [];
  const notDrafted = [], warnings = [], provenance = [];
  // A source decides an effect.only pass only from authoritative windows that were complete; one that was not, on any
  // write turn, is left out of every drafted clause and named.
  const writeEvents = turn => turn.windows.flatMap(w => w.events.filter(e => e.outcome === 'committed' && WRITE_OPERATIONS.includes(e.operation)));
  const writeTurns = record.turns.filter(t => writeEvents(t).length);
  const sourceState = new Map();
  for (const turn of writeTurns) for (const w of turn.windows) {
    const decides = w.scope?.evidence === 'authoritative' && !PRESENCE_ONLY_SOURCES.includes(w.source) && w.coverage === 'complete';
    const was = sourceState.get(w.source) ?? { decides: true, observers: new Set(), why: new Set(), windows: [] };
    was.observers.add(w.observer); was.windows.push(w);
    if (!decides) { was.decides = false; was.why.add(w.scope?.evidence !== 'authoritative' || PRESENCE_ONLY_SOURCES.includes(w.source) ? 'presence-only' : `coverage ${w.coverage}`); }
    sourceState.set(w.source, was);
  }
  const judged = [...sourceState].filter(([, s]) => s.decides).map(([source]) => source).sort();
  // Custody (src/custody.mjs), read from the recorded windows as a run reads them (a provider feed's declared key source
  // included): a source whose record the application can write can fail "nothing else happened" and never pass it.
  const custody = Object.fromEntries(judged.map(source => [source, sourceState.get(source).windows.map(w => custodyOf(w)).sort((a, b) => CUSTODY_RANK[a] - CUSTODY_RANK[b])[0]]));
  const writable = judged.filter(source => custody[source] === 'subject-writable');
  if (writable.length) warnings.push(`the drafted effect.only clauses read ${writable.join(', ')}, a record the application can write: they can fail on it, never pass on it (custody). A pass needs every source that decides it to be independent, such as an egress recorder on the request path; narrow "sources" to those to get a pass that ignores writes only the application's own record shows`);
  for (const [source, s] of sourceState) if (!s.decides) warnings.push(`source ${source} (${[...s.observers].join(', ')}) is left out of every drafted effect.only clause (${[...s.why].join(', ')} in the watch run): a write only it records is not judged; give an authoritative observer with complete coverage to judge it`);

  // A keyed digest names the same undeclared principal in every turn of a run. One that appears in write turns sent as
  // different actors cannot be any one of them, so no turn that shows it is drafted (an inference never contradicts itself).
  const digestActors = new Map();
  for (const turn of writeTurns) for (const w of turn.windows) for (const e of w.events) if (e.actor !== null && UNLISTED.test(e.actor)) {
    const key = `${w.observer}\u0000${e.actor}`;
    digestActors.set(key, new Set([...(digestActors.get(key) ?? []), watch.target.actors[turn.actorId]?.principalId ?? null]));
  }
  const groups = [], required = [...(watch.requiredControlIds ?? [])], inferred = new Set();
  for (const turn of record.turns) {
    const where = { turn: turn.id, actorId: turn.actorId, method: turn.method, path: turn.path };
    const events = writeEvents(turn);
    if (!turn.response.complete || turn.response.status === null) { notDrafted.push({ ...where, reason: `response-incomplete: the turn's response was not complete (${turn.response.transport})` }); continue; }
    if (!events.length) {
      const watched = turn.windows.some(w => w.scope?.evidence === 'authoritative' && w.coverage !== 'failed');
      notDrafted.push({ ...where, reason: watched ? 'no-write-observed: no observer recorded a committed write in this turn\'s window' : 'no-complete-window: no authoritative observer reported this turn (every window failed or is presence-only), so a write may have gone unseen' });
      continue;
    }
    if (!ok2xx(turn.response.status)) {
      notDrafted.push({ ...where, reason: `write-with-refusal-status: the application answered ${turn.response.status} and committed a write; not proposed as expected behaviour` });
      warnings.push(`turn ${turn.id}: the application answered ${turn.response.status} and still committed ${events.length} write(s); review it by hand`);
      continue;
    }
    // Attribution is read over every committed write of the turn, from every source, judged or not: a write any observer
    // gives to someone else is never proposed. An unlisted digest is read as the turn's actor only when that observer does
    // not declare the actor and shows one undeclared principal in this turn.
    const principal = watch.target.actors[turn.actorId]?.principalId ?? null, mine = new Set();
    let otherPrincipal = principal === null;
    for (const w of turn.windows) {
      const declared = configs.find(c => c.id === w.observer)?.principals;
      const digests = new Set(w.events.filter(e => e.outcome === 'committed' && WRITE_OPERATIONS.includes(e.operation) && e.actor !== null && UNLISTED.test(e.actor)).map(e => e.actor));
      for (const e of w.events) {
        if (e.outcome !== 'committed' || !WRITE_OPERATIONS.includes(e.operation) || e.actor === null) continue;
        if (!UNLISTED.test(e.actor)) { if (e.actor !== principal) otherPrincipal = true; continue; }
        if (!Array.isArray(declared) || declared.includes(principal) || digests.size !== 1 || digestActors.get(`${w.observer}\u0000${e.actor}`)?.size !== 1) otherPrincipal = true;
        else mine.add(`${w.observer}\u0000${principal}`);
      }
    }
    if (otherPrincipal) {
      notDrafted.push({ ...where, reason: 'write-by-another-principal: an observer attributed a write in this turn to a principal other than the turn\'s actor; not proposed as expected behaviour' });
      warnings.push(`turn ${turn.id}: a write was attributed to someone other than ${turn.actorId}; review it by hand`);
      continue;
    }
    const counted = new Map();
    for (const w of turn.windows) for (const e of w.events) {
      if (e.outcome !== 'committed' || !WRITE_OPERATIONS.includes(e.operation) || !judged.includes(e.source)) continue;
      const select = selectorOf(e, turn, e.actor === null ? null : UNLISTED.test(e.actor) ? principal : e.actor), key = canonical(select);
      const entry = counted.get(key) ?? { select, count: 0, cites: [] };
      entry.count++; entry.cites.push({ observer: w.observer, seq: e.seq });
      counted.set(key, entry);
    }
    if (!counted.size) { notDrafted.push({ ...where, reason: 'no-deciding-source: every write this turn shows came from a source that cannot decide an effect.only pass' }); continue; }
    for (const key of mine) inferred.add(key);
    const expect = [...counted.values()].sort((a, b) => canonical(a.select).localeCompare(canonical(b.select)));
    const cites = expect.flatMap(e => e.cites);
    const observed = { record: record.recordId, turn: turn.id, status: turn.response.status, events: cites };
    const request = { actorId: turn.actorId, method: turn.method, path: turn.path, ...(Object.hasOwn(turn, 'body') ? { body: turn.body } : {}) };
    const only = { id: `WF-${turn.id}-ONLY`, title: `${turn.actorId} ${turn.method} ${turn.path} does only what the watch run saw (drafted)`, category: 'Collateral', severity: 'high', ...request,
      evidenceRequirement: 'backend', assertions: [{ kind: 'status.equals', expected: turn.response.status }],
      effects: [{ kind: 'effect.only', expect: expect.map(e => ({ select: { ...e.select }, count: e.count })), allow: [], sources: [...judged] }],
      drafted: 'observed', approved: false, observed };
    const use = { id: `WF-${turn.id}-USE`, title: `${turn.actorId} ${turn.method} ${turn.path} still works (allowed-use twin, drafted)`, category: 'Allowed use', severity: 'control', ...request,
      evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: turn.response.status }],
      effects: expect.map(e => ({ kind: 'effect.count', select: { ...e.select }, expected: e.count })), drafted: 'observed', approved: false, observed: structuredClone(observed) };
    groups.push({ turn: turn.id, lines: [use, only] });
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(turn.method)) warnings.push(`${use.id}: the twin sends ${turn.method} ${turn.path} before ${only.id} does; if the action consumes its object, point the twin at another object before approving it`);
    if (expect.some(e => !Object.hasOwn(e.select, 'actor'))) warnings.push(`${only.id}: some expected effects name no actor (their observer does not attribute one), so the clause counts them by name alone`);
    for (const line of [use, only]) provenance.push({ line: line.id, kind: 'check', turn: turn.id, basis: line === only ? 'effect.only over the effects observed in this turn' : 'allowed-use twin of the effect.only check', citations: cites });
  }

  // An observer that attributed a drafted write to an undeclared principal is drafted with the turn actor's principal added.
  const observers = configs.map(config => {
    const extra = [...inferred].filter(k => k.startsWith(`${config.id}\u0000`)).map(k => k.split('\u0000')[1]).sort();
    if (!extra.length) return config;
    provenance.push({ line: config.id, kind: 'observer', basis: `inferred: the observer attributed drafted writes to a principal it does not declare (a keyed digest), and each such turn was sent as ${extra.join(', ')}`, citations: [] });
    warnings.push(`observer ${config.id}: ${extra.join(', ')} added to its principals by inference from the turns' actors; confirm the application records that principal under that name`);
    return { ...config, principals: [...config.principals, ...extra], drafted: 'observed', approved: false, observed: { record: record.recordId, principalsAdded: extra, basis: 'inferred-from-turn-actor' } };
  });
  if (!groups.length) throw Object.assign(new Error(`Nothing to draft: ${notDrafted.map(n => `${n.turn} ${n.reason.split(':')[0]}`).join(', ')}.`), { notDrafted });
  if (groups.length > TARGETS_PER_PROFILE) throw new Error(`The watch has ${groups.length} write turns to draft; a profile holds ${TARGETS_PER_PROFILE} targets. Split the watch file.`);
  if (groups.length > 1) warnings.push(`${groups.length} write turns: each is drafted in a target of its own (${groups.map(g => `${watch.target.id.slice(0, 80 - g.turn.length - 1)}-${g.turn}`).join(', ')}), because in one run a later turn's write fits an earlier effect.only clause and the settlement rule holds that clause undecided; assess each target`);

  const first = watch.checks?.first ?? [], last = watch.checks?.last ?? [];
  // A hand-written check after the drafted lines that writes (a write method, or declared effects) would hold every drafted
  // effect.only clause undecided in the same way: the settlement rule reads its effect as possibly the clause's late one.
  for (const check of last) if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(check?.method) || Array.isArray(check?.effects)) warnings.push(`hand-written check ${check.id} comes after the drafted lines and can commit a write: a write there holds every drafted effect.only clause undecided; move it to "checks.first"`);
  // Split targets keep the validator's limits (an id of at most 80 characters, a name of at most 160): the base id is cut to
  // fit, and the ids must stay distinct.
  const splitId = turn => `${watch.target.id.slice(0, 80 - turn.length - 1)}-${turn}`;
  if (groups.length > 1 && new Set(groups.map(g => splitId(g.turn))).size !== groups.length) throw new Error('The split target ids would collide; give the watch target a shorter id.');
  const splitName = turn => `${watch.target.name.slice(0, 160 - ` (turn ${turn})`.length)} (turn ${turn})`;
  const targetOf = (group, single) => ({ ...watch.target, ...(single ? {} : { id: splitId(group.turn), name: splitName(group.turn) }), ...(configs.length ? { observers: structuredClone(observers) } : {}),
    requiredControlIds: [...new Set([...required, group.lines[0].id])], checks: [...structuredClone(first), ...group.lines, ...structuredClone(last)] });
  const profile = { schemaVersion: 1, targets: groups.length === 1 ? [targetOf(groups[0], true)] : groups.map(g => targetOf(g, false)) };
  // The product's own validator, on the profile as approval would make it, before anything is written; and the known-negative
  // self-test of the approved lines, reported (an effect.only clause is not planted by that mode, so a drafted ONLY check reads partial).
  const approved = admitDraftedLines(approveLines(profile, { approvedBy: 'draft validation' }).profile);
  const draftedIds = new Set(groups.flatMap(g => g.lines.map(c => c.id)));
  const selfTest = validateTargetFile(approved).flatMap(t => knownNegativeTarget(t).checks.filter(c => draftedIds.has(c.id)).map(c => ({ id: c.id, outcome: c.outcome })));
  const report = { schema: WATCH_DRAFT_SCHEMA, approved: false, recordId: record.recordId, watchId: record.watchId, targetId: watch.target.id, targets: profile.targets.map(t => t.id), application: watch.target.applicationId,
    judgedSources: judged.map(source => ({ source, custody: custody[source] })), inventory: inventoryOf(record, watch), provenance, notDrafted, warnings, selfTest,
    profileDigest: sha256(canonical(profile)),
    note: 'Every drafted line is a proposal computed from one watch run, with no model: it says what the application did, not what it should do. A person approves each line ("approved": true, "approvedBy") before the profile loads.' };
  return { profile, report: { ...report, draftId: sha256(canonical(report)) } };
}

/** What the watch run saw: destinations and the declared paths they hit, tables written, audit actions, identities used. */
export function inventoryOf(record, watch) {
  const add = (map, key, value) => map.set(key, new Set([...(map.get(key) ?? []), value]));
  const destinations = new Map(), tables = new Map(), actions = new Map(), principals = new Map();
  for (const turn of record.turns) for (const w of turn.windows) for (const e of w.events) {
    if (e.outcome !== 'committed') continue;
    if (SEND_SOURCES.includes(e.source) && e.operation === 'send') add(destinations, e.name, e.resource ?? '*');
    if (e.source === 'sql-snapshot') add(tables, e.name, e.operation);
    if (AUDIT_SOURCES.includes(e.source)) add(actions, e.name, e.operation);
    if (e.actor !== null) add(principals, e.actor, w.observer);
  }
  const listed = map => [...map].sort(([a], [b]) => a.localeCompare(b));
  return {
    destinations: listed(destinations).map(([host, rs]) => ({ host, resources: [...rs].sort(), note: [...rs].some(r => r.endsWith(' *')) ? 'a send on a path the observer does not declare reads "METHOD *": raw paths are never stored' : undefined })).map(d => d.note ? d : { host: d.host, resources: d.resources }),
    tables: listed(tables).map(([table, ops]) => ({ table, operations: [...ops].sort(), columns: 'not-recorded' })),
    auditActions: listed(actions).map(([action, ops]) => ({ action, operations: [...ops].sort() })),
    identities: { actorsUsed: [...new Set(watch.turns.map(t => t.actorId))].sort(), principalsSeen: listed(principals).map(([principal, obs]) => ({ principal: UNLISTED.test(principal) ? 'unlisted (a principal the observer does not declare)' : principal, observers: [...obs].sort() })) },
  };
}
