// Drafted lines in a target profile: what a person must approve before anything runs.
// Watch-first (draft.mjs) writes a profile whose proposed lines (a check, an observer, an actor) carry
//   drafted      where the line came from: "observed" (watch-first, from what the target did in a watch run)
//   approved     false until a person approves the line; then true
//   approvedBy   the label of the person who approved it (1 to 120 characters), required once approved is true
//   observed     the line's provenance: the watch record and turn it was drafted from, and the events it cites
// admitDraftedLines runs before the product's own validator (src/registry.mjs loadProfiles), so every command that
// loads a profile (check-config, assess, gate, the dashboard) refuses a profile with any unapproved drafted line, and
// reads an approved one as the plain line it proposes: the markers are removed, so an approved profile has the
// same profile hash as the same lines written by hand. approvedBy is a label the caller supplies: it authenticates
// no one. The provenance stays in the drafted file and its draft report, never in a run.
// Pure: no I/O.
export const DRAFTED_SOURCES = Object.freeze(['observed']);
export const MARKER_KEYS = Object.freeze(['drafted', 'approved', 'approvedBy', 'observed']);
const LABEL = /^[^\u0000-\u001f\u007f]{1,120}$/;
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const marked = value => plain(value) && MARKER_KEYS.some(key => Object.hasOwn(value, key));

export class DraftedLineError extends Error {
  constructor(code, lines) {
    const list = lines.slice(0, 20).join('; ') + (lines.length > 20 ? `; and ${lines.length - 20} more` : '');
    super(code === 'drafted-line-unapproved'
      ? `The profile has ${lines.length} drafted line(s) no one has approved (proposals drafted from a watch run): ${list}. Review each one, then set "approved": true and "approvedBy", or delete it (and its id from "requiredControlIds").`
      : `The profile has drafted-line markers it cannot read (${code}): ${list}.`);
    this.name = 'DraftedLineError'; this.code = code; this.lines = lines;
  }
}

// Where drafted lines may stand: a check, an observer, an actor. Anything else carrying a marker is refused.
function* places(input) {
  const targets = plain(input) && Array.isArray(input.targets) ? input.targets : [];
  for (const [t, target] of targets.entries()) {
    const name = `target ${plain(target) && typeof target.id === 'string' ? JSON.stringify(target.id) : t + 1}`;
    if (!plain(target)) continue;
    for (const [i, check] of (Array.isArray(target.checks) ? target.checks : []).entries()) yield { at: `${name} check ${plain(check) && typeof check.id === 'string' ? JSON.stringify(check.id) : i + 1}`, line: check, set: v => { target.checks[i] = v; } };
    for (const [i, observer] of (Array.isArray(target.observers) ? target.observers : []).entries()) yield { at: `${name} observer ${plain(observer) && typeof observer.id === 'string' ? JSON.stringify(observer.id) : i + 1}`, line: observer, set: v => { target.observers[i] = v; } };
    if (plain(target.actors)) for (const alias of Object.keys(target.actors)) yield { at: `${name} actor ${JSON.stringify(alias)}`, line: target.actors[alias], set: v => { target.actors[alias] = v; } };
  }
}
// Markers are read at the top level of a line only. A line's own fields are left to the validator: a check's request
// body is the application's data (a body may well say "approved": true), and every other field is checked strictly there.
// The document root and a target are not lines, so a marker on either is refused.
function markers(input) {
  const out = [];
  if (marked(input)) out.push({ misplaced: 'profile' });
  for (const [t, target] of (plain(input) && Array.isArray(input.targets) ? input.targets : []).entries()) if (marked(target)) out.push({ misplaced: `target ${plain(target) && typeof target.id === 'string' ? JSON.stringify(target.id) : t + 1}` });
  for (const place of places(input)) if (marked(place.line)) out.push(place);
  return out;
}

/** True when the document carries any drafted-line marker. */
export const hasDraftedLines = input => markers(input).length > 0;

/** The document as the validator should read it: unchanged (the same object) when nothing is drafted; otherwise a copy
 * with every approved line's markers removed. Refuses an unapproved line, a marker on the document or a target, an
 * unknown source, an approval without approvedBy, and approvedBy on a line not approved. */
export function admitDraftedLines(input) {
  const found = markers(input);
  if (!found.length) return input;
  const misplaced = found.filter(m => m.misplaced).map(m => m.misplaced);
  if (misplaced.length) throw new DraftedLineError('drafted-marker-misplaced', misplaced);
  const copy = structuredClone(input);
  const unreadable = [], unapproved = [];
  for (const place of places(copy)) {
    const line = place.line;
    if (!marked(line)) continue;
    if (!DRAFTED_SOURCES.includes(line.drafted)) { unreadable.push(`${place.at} (drafted must be one of ${DRAFTED_SOURCES.join(', ')})`); continue; }
    if (line.approved !== true && line.approved !== false) { unreadable.push(`${place.at} (approved must be true or false)`); continue; }
    if (line.approved === false) { if (Object.hasOwn(line, 'approvedBy')) unreadable.push(`${place.at} (approvedBy on a line not approved)`); else unapproved.push(place.at); continue; }
    if (typeof line.approvedBy !== 'string' || !LABEL.test(line.approvedBy) || !line.approvedBy.trim()) { unreadable.push(`${place.at} (an approved line needs approvedBy, 1 to 120 characters)`); continue; }
    if (Object.hasOwn(line, 'observed') && !plain(line.observed)) { unreadable.push(`${place.at} (observed must be an object)`); continue; }
  }
  if (unreadable.length) throw new DraftedLineError('drafted-marker-invalid', unreadable);
  if (unapproved.length) throw new DraftedLineError('drafted-line-unapproved', unapproved);
  for (const place of places(copy)) if (marked(place.line)) {
    const { drafted, approved, approvedBy, observed, ...rest } = place.line;
    place.set(rest);
  }
  return copy;
}

/** The drafted lines of a profile, as { at, id, kind, approved, approvedBy } (for listing and approval). */
export function draftedLines(input) {
  return [...places(input)].filter(p => marked(p.line)).map(p => ({ at: p.at, kind: p.at.split(' ').at(-2), id: p.at.split(' ').at(-1).replace(/^"|"$/g, ''), approved: p.line.approved === true, ...(p.line.approvedBy ? { approvedBy: p.line.approvedBy } : {}) }));
}

/** A copy of the profile with the named drafted lines approved by `approvedBy` (every drafted line when `ids` is
 * "all"). A line named but not drafted, or not found, is refused, so a typo never reads as an approval. */
export function approveLines(input, { approvedBy, ids = 'all' } = {}) {
  if (typeof approvedBy !== 'string' || !LABEL.test(approvedBy) || !approvedBy.trim()) throw new Error('Name the person approving these lines (approvedBy, 1 to 120 characters).');
  const copy = structuredClone(input);
  const drafted = [...places(copy)].filter(p => marked(p.line));
  if (!drafted.length) throw new Error('The profile has no drafted lines to approve.');
  const wanted = ids === 'all' ? null : new Set(ids);
  if (wanted) for (const id of wanted) if (!drafted.some(p => p.at.endsWith(` ${JSON.stringify(id)}`))) throw new Error(`No drafted line ${JSON.stringify(id)} in this profile.`);
  let count = 0;
  for (const place of drafted) {
    if (wanted && ![...wanted].some(id => place.at.endsWith(` ${JSON.stringify(id)}`))) continue;
    place.set({ ...place.line, approved: true, approvedBy: approvedBy.trim() });
    count++;
  }
  return { profile: copy, approved: count };
}
