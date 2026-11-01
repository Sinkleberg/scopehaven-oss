// Positive-match pairing of absence selectors across one HTTP run (EFFECT-SELECTOR-SEMANTICS). Pure: no I/O.
//
// An absence clause (effect.none, or effect.count expecting 0) on a boundary check passes when its
// observers saw nothing that matches its selector. A selector's source, operation and name are
// vouched for by the observer's declared vocabulary: a name the observer does not log reads
// unobservable, never pass (effect-events.mjs windowSees). Its other pins, an actor, a resource
// or a trace id, are checked against nothing: a wrong actor or resource selects nothing, and
// "nothing happened" is then a reading of the typo, not of the application.
//
// Each such pin therefore needs a positive twin: an effect.exists or effect.count (expecting at
// least one) clause of an allowed-use control that was sent and matched a committed effect in this
// run, recorded by an observer that decided the absence.
//   - actor: the absence selector names the boundary check's own principal, and the twin is that
//     actor's own allowed action pinned to the same principal, carrying every other key of the
//     absence except its resource and trace id (source, operation, name) with the same value
//     (attribution of this principal, for this kind of effect, in this observer's format, is shown).
//     Its resource or trace id may differ.
//   - resource or trace id: the twin is the same selector but the actor (every other pinned key
//     with the same value, the twin pinning more keys if it likes), on an allowed-use control of
//     any actor: another actor's allowed twin on the foreign resource, or the actor's own allowed
//     request on a route that only its actions reach. A twin that pins an actor pins its own principal.
//     A resource is vouched for like a name, and needs no twin, only when every deciding observer
//     declares a resource vocabulary for the selector's exact name (scope.resources, effect-events.mjs)
//     that lists it, and every committed effect of that name (and the selector's source and operation,
//     when it gives them) in the deciding window carries a resource from that vocabulary; a resource
//     outside it, another name, or an unclassified committed effect of that name (with the
//     selector's source and operation, when it gives them) in the window still needs one.
// A selector that pins both needs both shown, by one control or two.
//
// Without a twin for a pin the absence reads inconclusive (selector-unpaired); with twins none of
// which matched in a deciding observer's window it reads inconclusive (selector-not-shown-to-match).
// Only a pass is withheld, and only in a boundary check: a fail stays a fail, and an allowed-use
// control is never paired. effect.only is not paired: its expected half must match by construction,
// and its absence half is scoped by the observers' vocabularies, not by a selector.
// Pairing shows non-vacuity (the selector selects in this observer's format), not relatedness (that
// the check's own request could cause the effect): a shown selector unrelated to its request still passes.
// Declared body fields (`fields`, src/body-fields.mjs) are a pin like a resource: a mistyped value selects
// nothing, so its twin carries the same fields (an actor twin need not). A forwarded send's upstream requirement
// (`upstream: "applied"`, src/effect-outcome.mjs) is one too: a setup in which every send reads a declared rejection
// would show nothing applied, so its twin is a control that matched an applied send (an actor twin need not carry it). A claim rule's refusal clause
// (src/http-claims.mjs, effect.none over its selector) is paired like a declared absence clause; its index
// in the check's decisions follows the declared effects. Twins are always declared effects of controls.
// The allowed-use guard (allowedUseGuards below, FIX-07) adds a third reason to this stage, allowed-use-not-declared, for an absence
// that pins nothing: effect.only included, and only in a boundary check that expects a success status and has no positive clause.
import { matches, custodyRunWindows } from './effect-events.mjs';
import { decidingWindows } from './custody.mjs';

export const PAIRING_SCHEMA = 'scopehaven-pairing/1';
export const PAIRING_REASONS = Object.freeze(['selector-unpaired', 'selector-not-shown-to-match', 'allowed-use-not-declared']);
export const PAIRING_BASIS = Object.freeze({
  'selector-unpaired': 'Pairing: no allowed-use control carries an effect.exists or effect.count clause that would show this selector\'s actor or resource (selector-unpaired), so a selector naming a wrong actor or resource would read the same.',
  'selector-not-shown-to-match': 'Pairing: the allowed-use control paired with this selector matched no committed effect in a window of an observer that decided this absence (selector-not-shown-to-match), so the selector was not shown to select anything.',
  'allowed-use-not-declared': 'Allowed use: no required allowed-use control of this check\'s actor passed a positive effect in this run, and the check declares no positive effect of its own (allowed-use-not-declared), so an application that did nothing would pass this absence the same way.',
});
// The field a clause or its assertion row carries for a finding.
export const pairingFields = d => d?.pairing ? { pairing: d.pairing } : {};
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const sameValue = (a, b) => JSON.stringify(a) === JSON.stringify(b);

// A forbidden absence clause: effect.none, or effect.count expecting no effect.
export const absenceClause = e => plain(e) && (e.kind === 'effect.none' || (e.kind === 'effect.count' && e.expected === 0));
// A positive clause: effect.exists, or effect.count expecting at least one effect.
export const positiveClause = e => plain(e) && (e.kind === 'effect.exists' || (e.kind === 'effect.count' && Number.isSafeInteger(e.expected) && e.expected >= 1));
// Pins the observer's vocabulary does not cover, each needing its own positive twin.
// upstream (src/effect-outcome.mjs): a destination whose every send reads a declared rejection would show nothing applied.
export const PINNED_KEYS = Object.freeze(['actor', 'resource', 'traceId', 'fields', 'upstream']);
export const pinsOf = select => plain(select) ? PINNED_KEYS.filter(key => Object.hasOwn(select, key)) : [];
export const needsPairing = select => pinsOf(select).length > 0;

// Does the control's positive selector show one pin of the absence selector (see the header)? principals: actor alias -> principalId.
export function showsPin(pin, absence, boundaryActorId, control, controlActorId, principals) {
  if (!plain(absence) || !plain(control) || !Object.hasOwn(absence, pin)) return false;
  // A twin that pins an actor pins its own principal.
  if (Object.hasOwn(control, 'actor') && control.actor !== principals[controlActorId]) return false;
  // An actor pin: the same principal, and every key of the absence but its resource and trace id with the same value.
  if (pin === 'actor') return absence.actor === principals[boundaryActorId] && Object.entries(absence).every(([key, value]) => key === 'resource' || key === 'traceId' || key === 'fields' || key === 'upstream' || (Object.hasOwn(control, key) && sameValue(control[key], value)));
  return Object.entries(absence).every(([key, value]) => key === 'actor' || (Object.hasOwn(control, key) && sameValue(control[key], value)));
}
// The twins of every absence clause that needs them, by boundary check:
// checkId -> [{ effect (index), select, pins: { [pin]: [{ checkId, effect }] } }].
export function selectorPairs(target) {
  const principals = Object.fromEntries(Object.entries(target.actors ?? {}).map(([alias, actor]) => [alias, actor?.principalId]));
  const applicable = (target.checks ?? []).filter(c => c?.applicability?.applies !== false);
  const controls = applicable.filter(c => c.severity === 'control' && Array.isArray(c.effects));
  const pairs = new Map();
  // The controls' positive clauses in profile order, and those naming each exact name: a twin of an absence clause with a name
  // must carry the same name (showsPin), so only those are tested. Same twins, same order.
  const positives = controls.flatMap(control => control.effects.map((e, k) => ({ control, e, k })).filter(({ e }) => positiveClause(e)));
  const byName = new Map();
  for (const p of positives) if (plain(p.e.select) && Object.hasOwn(p.e.select, 'name')) { const key = JSON.stringify(p.e.select.name); if (!byName.has(key)) byName.set(key, []); byName.get(key).push(p); }
  const candidatesFor = select => plain(select) && Object.hasOwn(select, 'name') ? byName.get(JSON.stringify(select.name)) ?? [] : positives;
  for (const check of applicable) {
    if (check.severity === 'control' || (!Array.isArray(check.effects) && !Array.isArray(check.claims))) continue;
    const entries = [];
    const twinsOf = select => Object.fromEntries(pinsOf(select).map(pin => [pin,
      candidatesFor(select).filter(({ control, e }) => showsPin(pin, select, check.actorId, e.select, control.actorId, principals)).map(({ control, k }) => ({ checkId: control.id, effect: k }))]));
    const effects = Array.isArray(check.effects) ? check.effects : [];
    effects.forEach((effect, index) => {
      if (!absenceClause(effect) || !needsPairing(effect.select)) return;
      entries.push({ effect: index, select: effect.select, pins: twinsOf(effect.select) });
    });
    // A claim's refusal reading is effect.none over its selector: paired the same way, whatever it reads.
    (Array.isArray(check.claims) ? check.claims : []).forEach((claim, i) => {
      if (plain(claim) && needsPairing(claim.select)) entries.push({ effect: effects.length + i, select: claim.select, pins: twinsOf(claim.select), claim: i });
    });
    if (entries.length) pairs.set(check.id, entries);
  }
  return pairs;
}
// The absence selector pins of a target with no twin at all (reported by check-config before any run).
// A claim rule's selector is reported by its claim number instead of an effect number.
export const unpairedSelectors = target => [...selectorPairs(target).entries()].flatMap(([checkId, entries]) => entries.flatMap(e => Object.entries(e.pins).filter(([, twins]) => !twins.length).map(([pin]) => ({ checkId, ...(e.claim === undefined ? { effect: e.effect + 1 } : { claim: e.claim + 1 }), pin, select: e.select }))));

// The allowed-use guard (FIX-07). Pairing covers an absence that pins an actor, a resource, a trace id, fields or an upstream
// outcome. An absence that pins none of them (effect.none, effect.count expecting 0, effect.only, or a claim rule's selector,
// whose refusal reading is effect.none) is vouched for by the observer's vocabulary, but nothing in the run then shows that the
// application did anything at all: an application that does nothing, or one that only says it acted, passes it. In a boundary
// check that declares no positive clause of its own (positiveClause: such a check fails when nothing happened), each such
// absence is guarded only by a required allowed-use control (requiredControlIds) of the same actor with a positive effect
// clause, which an application that does nothing fails, so every boundary row of the actor reads inconclusive
// (control-not-passed). Only a check whose status contract accepts a success (status.equals 200 to 299) is guarded: an
// application that does nothing answers success, so it cannot pass a check that expects a refusal or a redirect, whose pass
// rests on that refusal and on the identity rules for refusals (a credentialed actor's refusal counts only beside a passed
// surface control). Its guards: checkId -> [{ effect (index in the check's decisions, a claim's after the declared effects),
// claim?, guards: [control id], withheld }]. A guard counts only when one of its declared positive clauses passed at the pairing
// stage (settled and attributed, as pairingFindings reads it on both sides): a guard that failed, on a coverage gap too, leaves the
// absence's pass inconclusive, so identity option B (restsOn, src/http-rests-on.mjs), which can release a boundary row from a
// required control that failed only on a gap, never releases this one (PR382-REVIEW finding 1). withheld: a required control of
// the same actor was not sent (notSent: the ids of the run's not-sent checks); it shows no served record, so option B never releases
// the actor's rows from it, and both the connector and the validator, which reads a not-sent row's declaration nowhere, read that
// the same way. Otherwise the absence's pass reads inconclusive (allowed-use-not-declared, pairingFindings below).
export const acceptsSuccess = check => (Array.isArray(check?.assertions) ? check.assertions : []).some(a => plain(a) && a.kind === 'status.equals' && Number.isInteger(a.expected) && a.expected >= 200 && a.expected <= 299);
export function allowedUseGuards(target, { notSent = [] } = {}) {
  const required = new Set(Array.isArray(target?.requiredControlIds) ? target.requiredControlIds : []), unsent = new Set(notSent);
  const applicable = (Array.isArray(target?.checks) ? target.checks : []).filter(c => plain(c) && c.applicability?.applies !== false);
  const positive = c => Array.isArray(c.effects) && c.effects.some(positiveClause);
  const guardsOf = actorId => applicable.filter(c => c.severity === 'control' && required.has(c.id) && c.actorId === actorId && positive(c)).map(c => c.id);
  const withheldFor = actorId => applicable.some(c => c.severity === 'control' && required.has(c.id) && c.actorId === actorId && unsent.has(c.id));
  const guarded = new Map();
  for (const check of applicable) {
    if (check.severity === 'control' || positive(check) || !acceptsSuccess(check)) continue;
    const effects = Array.isArray(check.effects) ? check.effects : [], guards = guardsOf(check.actorId), withheld = withheldFor(check.actorId);
    const entries = [...effects.flatMap((e, i) => (absenceClause(e) && !needsPairing(e.select)) || (plain(e) && e.kind === 'effect.only') ? [{ effect: i, guards, withheld }] : []),
      ...(Array.isArray(check.claims) ? check.claims : []).flatMap((c, i) => plain(c) && !needsPairing(c.select) ? [{ effect: effects.length + i, claim: i, guards, withheld }] : [])];
    if (entries.length) guarded.set(check.id, entries);
  }
  return guarded;
}
// The unguarded absences of a target before any run (check-config): [{ checkId, effect } | { checkId, claim }], numbered from 1.
export const unguardedAbsences = target => [...allowedUseGuards(target).entries()].flatMap(([checkId, entries]) => entries.filter(e => !e.guards.length)
  .map(e => (e.claim === undefined ? { checkId, effect: e.effect + 1 } : { checkId, claim: e.claim + 1 })));

// Is this resource pin vouched for by every window that decided the absence? Each must declare a vocabulary for the
// selector's exact name that lists the resource (for a prefix, an entry starting with it), and be closed for it: every
// committed effect in the window that fits the selector without its resource (same source, operation and name) carries
// a resource from that name's vocabulary. Otherwise the pin needs a twin.
const vouchedResource = (deciding, select) => typeof select.name === 'string' && deciding.length > 0 && deciding.every(w => {
  const vocabulary = plain(w.scope?.resources) && Object.hasOwn(w.scope.resources, select.name) && Array.isArray(w.scope.resources[select.name]) ? w.scope.resources[select.name] : null;
  if (!vocabulary || !Array.isArray(w.events)) return false;
  const listed = typeof select.resource === 'string' ? vocabulary.includes(select.resource) : typeof select.resource?.prefix === 'string' && vocabulary.some(r => r.startsWith(select.resource.prefix));
  const fits = e => e.outcome === 'committed' && e.name === select.name && (select.source === undefined || e.source === select.source) && (select.operation === undefined || e.operation === select.operation);
  return listed && w.events.every(e => !fits(e) || vocabulary.includes(e.resource));
});
// rows: every row that has an effect window, in run order: [{ id, actorId, role, effects: decisions, windows }].
// pairs: selectorPairs(target). Returns, per row and clause, a reason or null. A clause is judged only when it
// passed; a twin's match must be recorded by an observer that decided this clause's absence.
// guards: allowedUseGuards(target); without it (an earlier caller) no clause is guarded and none reads allowed-use-not-declared.
export function pairingFindings(rows, pairs, guards = new Map()) {
  custodyRunWindows(rows, [], [], 'pairingFindings');
  const byId = new Map(rows.map(row => [row.id, row]));
  // A guard control showed the application acting: one of its declared positive clauses passed at this stage.
  const guardPassed = id => (byId.get(id)?.effects ?? []).some(d => d?.claim === undefined && positiveClause(d) && d.verdict === 'pass');
  // Per twin (control, clause): the observers whose window holds a committed match of its selector, computed once.
  const matchedBy = new Map();
  const matchedObservers = (checkId, k) => {
    const key = `${checkId}\n${k}`;
    if (!matchedBy.has(key)) {
      const control = byId.get(checkId), select = control?.effects?.[k]?.select;
      matchedBy.set(key, new Set(Boolean(control) && plain(select) ? control.windows.filter(w => Array.isArray(w.events) && w.events.some(e => matches(e, { ...select, outcome: 'committed' }))).map(w => w.instanceId) : []));
    }
    return matchedBy.get(key);
  };
  return rows.map(row => row.effects.map((effect, index) => {
    if (row.role === 'control' || effect.verdict !== 'pass') return null;
    // The allowed-use guard (allowedUseGuards): an unpinned absence of a guarded check passes only beside a guard control whose
    // positive clause passed, or with a required control of its actor left unsent; the connector and the validator alike.
    if (!needsPairing(effect.select) && (absenceClause(effect) || effect.kind === 'effect.only')) {
      const guard = (guards.get(row.id) ?? []).find(e => e.effect === index);
      return guard && !guard.withheld && !guard.guards.some(guardPassed) ? 'allowed-use-not-declared' : null;
    }
    if (!absenceClause(effect) || !needsPairing(effect.select)) return null;
    const deciding = decidingWindows(row.windows, { kind: effect.kind, select: effect.select, verdict: 'pass' }), deciders = new Set(deciding.map(w => w.instanceId));
    const entry = (pairs.get(row.id) ?? []).find(e => e.effect === index);
    // A twin counts only when its control was sent with an effect window (one of the rows): a control that was not sent
    // (capture-unavailable) shows nothing, and the validator, which pairs from the run's own rows, never sees it as a twin,
    // so the connector and the validator both read selector-unpaired when every twin of a pin was not sent.
    const twins = Object.entries(entry?.pins ?? {}).filter(([pin]) => !(pin === 'resource' && vouchedResource(deciding, effect.select))).map(([, list]) => list.filter(t => byId.has(t.checkId)));
    if (!entry || twins.some(list => !list.length)) return 'selector-unpaired';
    const shown = twins.every(list => list.some(({ checkId, effect: k }) => [...matchedObservers(checkId, k)].some(id => deciders.has(id))));
    return shown ? null : 'selector-not-shown-to-match';
  }));
}
// Apply one row's findings to its decided clauses under the check's role. Only a pass is withheld.
export function applyPairing(decisions, findings, role = 'boundary') {
  return decisions.map((d, i) => {
    const reason = findings?.[i] ?? null;
    if (reason === null || role === 'control' || d.verdict !== 'pass') return d;
    if (!PAIRING_REASONS.includes(reason)) throw new Error('pairing-reason');
    return { ...d, verdict: 'inconclusive', basis: `${d.basis} ${PAIRING_BASIS[reason]}`, pairing: reason };
  });
}
