// Typed captures for HTTP checks (creator versus actor). Pure: no I/O.
//
// A check may capture values from its own response so that a later check can act
// on a resource another actor created, with no application-specific ids in core:
//   capture: { <name>: { pointer, type } }     on the creating check; its actor is the creator
//   {{name}}                                    in a later check's path (a whole path segment or a
//                                               whole query value) or in its body string values
//   precondition: [{ name, type, createdBy }]   on the later check, checked when the profile loads
// A capture name is captured once per profile, by an earlier applicable check.
//
// A captured value is a plain identifier (letters, digits, "_", ".", ":" or "-", at most
// 200 characters, never only dots) or, for "integer", a safe JSON integer. The capture
// records never hold it: rows record { name, type, createdBy, captureCheckId, valueDigest },
// where valueDigest is keyed with a per-run secret the run does not keep, so a capture
// and its uses can be matched within one run and the value cannot be read back from them.
// Observer evidence is separate and keeps what the application reports: an audit log's
// request path, a snapshot's row key or a sent request's resource can be the captured value
// itself (or an unkeyed digest of a line that contains it), as for any resource a check touches.
// A capture misses when the creating check's response is not complete JSON, its status
// assertion did not pass, or the pointer is absent or holds a value of another type.
// Every check that uses a missed capture is not sent and reads inconclusive.
import { digest } from './domain.mjs';

export const CAPTURE_TYPES = Object.freeze(['id', 'string', 'integer']);
export const CAPTURE_LIMITS = Object.freeze({ perCheck: 8, perProfile: 64, valueChars: 200, preconditions: 8, requestBytes: 8192 });
export const CAPTURE_OUTCOMES = Object.freeze(['captured', 'response-unavailable', 'status-not-matched', 'absent', 'invalid']);
export const CAPTURE_NAME = /^[A-Za-z][A-Za-z0-9_]{0,31}$/;
const PLACEHOLDER = /\{\{([A-Za-z][A-Za-z0-9_]{0,31})\}\}/g;
const WHOLE = /^\{\{([A-Za-z][A-Za-z0-9_]{0,31})\}\}$/;
const VALUE = /^[A-Za-z0-9_.:-]{1,200}$/;
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const bad = message => { throw new Error(message); };

// Names used in one string, in order; throws on a malformed placeholder ("{{" or "}}" left over).
function namesInText(text, where) {
  const names = [...text.matchAll(PLACEHOLDER)].map(m => m[1]);
  if (/\{\{|\}\}/.test(text.replace(PLACEHOLDER, ''))) bad(`${where} has a malformed {{name}} placeholder (a name is a letter, then up to 31 letters, digits or "_")`);
  return names;
}
// Names a path uses. A placeholder is a whole path segment or a whole query value, so a
// captured identifier can never form a "." or ".." segment or another query parameter.
function pathNames(path) {
  const [route, query = ''] = path.split(/\?(.*)/s);
  const names = [];
  for (const segment of route.split('/')) {
    const found = namesInText(segment, 'the path');
    if (found.length && !WHOLE.test(segment)) bad('a {{name}} placeholder in the path must be a whole path segment');
    names.push(...found);
  }
  for (const part of query ? query.split('&') : []) {
    const at = part.indexOf('='), key = at < 0 ? part : part.slice(0, at), value = at < 0 ? '' : part.slice(at + 1);
    if (namesInText(key, 'the path').length) bad('a {{name}} placeholder in the query must be a whole query value, never a parameter name');
    const found = namesInText(value, 'the path');
    if (found.length && !WHOLE.test(value)) bad('a {{name}} placeholder in the query must be a whole query value');
    names.push(...found);
  }
  return names;
}
// Names a body uses (string values only; a key never holds a placeholder), with each occurrence.
function bodyNames(value, out = []) {
  if (typeof value === 'string') out.push(...namesInText(value, 'the body'));
  else if (Array.isArray(value)) for (const item of value) bodyNames(item, out);
  else if (object(value)) for (const [key, item] of Object.entries(value)) {
    if (/\{\{|\}\}/.test(key)) bad('a {{name}} placeholder belongs in a body value, never in a key');
    bodyNames(item, out);
  }
  return out;
}
// Every occurrence a check makes, path first, then body.
export const placeholderOccurrences = check => [...pathNames(check.path), ...(check.body === undefined ? [] : bodyNames(check.body))];
// The distinct capture names a check uses, in first-use order.
export const captureUsesOf = check => [...new Set(placeholderOccurrences(check))];

// Static rules, applied once every check has been validated. identityControlIds and
// surfaceControlIds: the checks the identity proof re-sends in its brackets (they cannot use
// captures: a bracket would re-send the raw placeholder). parsePointer: the connector's own JSON
// pointer parser (it throws on a malformed pointer), so a capture pointer is refused when the
// profile loads, never after its creating request was sent.
// Throws an Error whose message names the problem; the caller adds where it is.
export function validateCaptureDeclarations(target, identityControlIds, within, parsePointer, surfaceControlIds = new Set()) {
  if (typeof parsePointer !== 'function') bad('capture pointers need the connector\'s JSON pointer parser');
  const captured = new Map();
  let total = 0;
  target.checks.forEach((check, index) => within(check, index, () => {
    const occurrences = placeholderOccurrences(check), uses = [...new Set(occurrences)];
    for (const name of uses) if (!captured.has(name)) bad(`"{{${name}}}" needs an earlier applicable check that captures "${name}"`);
    if (uses.length && identityControlIds.has(check.id)) bad('an identity control is re-sent by the identity proof, so it cannot use a captured value');
    if (uses.length && surfaceControlIds.has(check.id)) bad('a surface control (a required GET allowed-use control of a credentialed actor) is re-sent by the identity proof, so it cannot use a captured value');
    // A filled body stays within the connector's request limit.
    if (check.body !== undefined && occurrences.length && Buffer.byteLength(JSON.stringify(check.body)) + occurrences.length * CAPTURE_LIMITS.valueChars > CAPTURE_LIMITS.requestBytes) bad(`the body with every placeholder filled (up to ${CAPTURE_LIMITS.valueChars} characters each) could exceed ${CAPTURE_LIMITS.requestBytes} bytes`);
    if (Object.hasOwn(check, 'precondition')) {
      if (!Array.isArray(check.precondition) || check.precondition.length < 1 || check.precondition.length > CAPTURE_LIMITS.preconditions) bad(`"precondition" lists 1 to ${CAPTURE_LIMITS.preconditions} { name, type, createdBy }`);
      const seen = new Set();
      for (const p of check.precondition) {
        if (!object(p) || Object.keys(p).length !== 3 || !['name', 'type', 'createdBy'].every(key => Object.hasOwn(p, key))) bad('each "precondition" entry is { name, type, createdBy } and nothing else');
        if (typeof p.name !== 'string' || !CAPTURE_NAME.test(p.name) || seen.has(p.name)) bad('each "precondition" names a distinct capture'); seen.add(p.name);
        if (!uses.includes(p.name)) bad(`"precondition" names "${p.name}", which this check does not use`);
        const source = captured.get(p.name);
        if (p.type !== source.type) bad(`"precondition" expects "${p.name}" of type ${CAPTURE_TYPES.includes(p.type) ? p.type : 'unknown'}, but it is captured as ${source.type}`);
        if (p.createdBy !== source.createdBy) bad(`"precondition" expects "${p.name}" created by another actor than check "${source.checkId}" (its creator is that check's actor)`);
      }
    }
    if (Object.hasOwn(check, 'capture')) {
      if (!object(check.capture)) bad('"capture" is { <name>: { pointer, type } }');
      const entries = Object.entries(check.capture);
      if (entries.length < 1 || entries.length > CAPTURE_LIMITS.perCheck) bad(`"capture" names 1 to ${CAPTURE_LIMITS.perCheck} values`);
      if (check.applicability?.applies === false) bad('a check excluded by its applicability declaration is never sent, so it cannot capture');
      for (const [name, spec] of entries) {
        if (!CAPTURE_NAME.test(name)) bad('a capture name is a letter, then up to 31 letters, digits or "_"');
        if (captured.has(name)) bad(`"${name}" is captured once per profile`);
        if (!object(spec) || Object.keys(spec).length !== 2 || typeof spec.pointer !== 'string' || !CAPTURE_TYPES.includes(spec.type)) bad(`capture "${name}" is { pointer, type } with type ${CAPTURE_TYPES.join(', ')}`);
        try { parsePointer(spec.pointer); } catch { bad(`capture "${name}" needs a valid JSON pointer: "" or "/" followed by tokens, "~" only as ~0 or ~1, at most 512 characters, no __proto__, prototype or constructor token`); }
        captured.set(name, { type: spec.type, createdBy: check.actorId, checkId: check.id, pointer: spec.pointer });
        total++;
      }
    }
  }));
  if (total > CAPTURE_LIMITS.perProfile) bad(`a profile captures at most ${CAPTURE_LIMITS.perProfile} values`);
  return captured;
}

// Is a response value of the declared type and a plain identifier?
export function captureValueValid(value, type) {
  if (type === 'integer') return Number.isSafeInteger(value);
  const text = typeof value === 'string' ? value : type === 'id' && Number.isSafeInteger(value) && value >= 0 ? String(value) : null;
  return text !== null && text.length <= CAPTURE_LIMITS.valueChars && VALUE.test(text) && !/^\.+$/.test(text);
}
// The outcome of one capture, from the check's own observation and its status assertion.
// lookup(json, pointer) -> { present, value } reads the response (the caller owns pointer parsing).
export function captureOutcome({ observation, statusPassed, pointer, type, lookup }) {
  if (!(observation.complete === true && observation.jsonParsed === true && !observation.error)) return { outcome: 'response-unavailable' };
  if (!statusPassed) return { outcome: 'status-not-matched' };
  const found = lookup(observation.json, pointer);
  if (!found.present) return { outcome: 'absent' };
  if (!captureValueValid(found.value, type)) return { outcome: 'invalid' };
  return { outcome: 'captured', value: found.value };
}
// The digest a capture and each of its uses record; key is the run's own secret.
export const captureValueDigest = (key, name, value) => digest({ key, name, value });

// Fill a check's placeholders from captured values (name -> value). A body string that is
// exactly one placeholder takes the captured JSON value; any other string is interpolated.
export function fillCaptures(check, values) {
  const text = s => s.replace(PLACEHOLDER, (_, name) => String(values.get(name)));
  const fill = value => {
    if (typeof value === 'string') { const whole = WHOLE.exec(value); return whole ? values.get(whole[1]) : text(value); }
    if (Array.isArray(value)) return value.map(fill);
    if (object(value)) return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, fill(item)]));
    return value;
  };
  return { ...check, path: text(check.path), ...(check.body === undefined ? {} : { body: fill(check.body) }) };
}
