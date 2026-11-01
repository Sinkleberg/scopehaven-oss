// App action log configuration and mapping (pure; shared by src/contracts.mjs and integrations/observers/app-log.mjs).
//
// An app log is the application's own record of the actions it took: one JSON line per action, in a file the application
// appends to (an "email sent", a "ticket updated"). The application writes it, so it is never custody evidence: its windows
// are kept apart from every custody decision (src/effect-events.mjs custodyWindows) and sealed beside a check's windows as
// data.appLogWindows. With "use": "record" it decides nothing. With "use": "admission" it is read against the application only
// (src/app-log-verdicts.mjs): a committed action its own log records, by the check's own actor in the check's own window, that a
// clause forbids makes that clause fail (an admission). It never makes, extends or rescues a pass.
//
// A target declares at most one, under the target key "appLogs" (never in "observers"):
//   { "id": "actions", "use": "record",
//     "log": { "file": { "path": "/abs/actions.jsonl" } },
//     "fields": { "action": "/event", "outcome": "/result", "actor": "/actor", "target": "/to", "at": "/ts", "id": "/event_id" },
//     "outcomes": { "committed": ["ok"], "denied": ["refused"], "error": ["error"] },
//     "rules": [ { "action": "email.sent", "operation": "send", "vocabulary": "mail", "domains": [{ "domain": "customers.example" }] },
//                { "action": "refund.created", "operation": "send", "vocabulary": "egress", "name": "pay.example", "resource": "POST /v1/refunds" },
//                { "action": "order.updated", "operation": "update", "vocabulary": "named", "name": "orders" } ],
//     "ignore": [ { "action": "page.viewed" } ],
//     "logActors": { "<principal>": "<the log's actor value>" } }
// It works on fields an existing log already has (action, outcome, actor, target, time, an entry id): no application change.
//   fields    JSON pointers into each line; action and outcome are required, target when a rule reads mail
//   outcomes  the log's outcome words (strings or integers, type-strict) for committed, denied and error; any other is unknown
//   rules     one per mapped action. vocabulary "egress": a declared host and a literal resource in the egress recorder's form
//             ("POST /v1/refunds"); "mail": the target is a recipient address (or a list of them), named as the SMTP sink and
//             the provider feed name it (src/mail-address.mjs: the recipient domain, a declared address or "*"); "named": a
//             literal name and an optional resource, literal or read from the line ({ "from": "<pointer>" }); its observedAs may
//             name an application-store source (an audit table, a snapshot, an audit endpoint or log) or telemetry
//             Any rule may declare "fields", read only by admissions against field-pinned clauses, one entry per selector pointer:
//               { "const": <scalar> }   what the action itself implies (a "ticket_update.sent" action implies the template)
//               { "from": "<line pointer>", "values": { "<selector value>": [<log words>] } }   read from the line through a closed
//                 word map: a listed word (type-strict) captures its selector value (a string); any other word, a missing pointer
//                 or a non-scalar captures nothing there, so the field reads unknown and decides nothing
//   observedAs  the observer sources whose effects this action is the same effect as: a selector pinned to one of them is read
//             on the log (admissions) only where every rule naming its exact name lists that source
//   distinctFrom  the observer sources whose effects this action is never (an operator statement): an effect.only admission
//             judges an entry against the clause's readable selectors only when every selector the log cannot read is pinned to
//             a source every rule of the entry's exact name lists here (src/app-log-verdicts.mjs)
//   lines     "per-application" (optional, PR-1c item c): the operator's statement that the application writes this action's
//             line once per application (retries, resends and redeliveries add no line, or carry the same fields.key). Only
//             then is a countBy clause read on the log: lines that share a key value collapse to one application.
//   ignore    actions the log records that are never effects
//   logActors each principal and the one log value that names it, one to one; any other value reads "unlisted:<digest>". A
//             principal is a declared actor's, or the actor pin of a declared background source (a background job that runs no
//             check and holds no credential, PR-1c item d)
//   fields.key    (optional) the idempotency key the application sent: any JSON value of at most 1024 characters, kept only as a
//             digest keyed with a secret the run does not keep, so lines can be compared within the run and the key itself is
//             never stored; a longer one reads unreadable and leaves every countBy clause on that window unread
//   fields.trace  (optional; needs the target's correlation header) the correlation value the application received with the
//             request; its token (src/egress-rules.mjs correlationTokenOf) is kept, so an admission can tell the check's own
//             line from a background job's
//   backgroundAllows  [{ check, effect, allow, source }] (written by profile validation from an effect.only clause's
//             "allowBackground", src/contracts.mjs): the allow entries that are a background source's alone. Admissions never
//             let one excuse the check's own actor. Under "use": "admission" each source must pin its actor to a principal this
//             map names, and the log must declare fields.trace
// Every line must be a mapped action, an ignored action or mail to a declared observer's witness domain; anything else
// (an unknown action, an unmapped outcome word, an unusable target, an unparsable or oversized line) leaves the window partial.
import { OPERATIONS, SOURCES } from './effect-events.mjs';
import { smtpDomain } from './smtp-rules.mjs';
import { recipientOf, addressResource, mailboxOf } from './mail-address.mjs';
import { validateCaptured, validCaptureMap } from './body-fields.mjs';
import { createHmac, randomBytes } from 'node:crypto';
import { digest } from './domain.mjs';
import { egressHost, correlationTokenOf } from './egress-rules.mjs';

export const APP_LOG_SCHEMA = 'scopehaven-app-log/1';
export const APP_LOG_SOURCE = 'app-log';
export const APP_LOG_KIND = 'app-action-log';
// "record": read and sealed, deciding nothing. "admission": also read against the application (fails only). There is no use
// that passes on the log.
export const APP_LOG_USES = Object.freeze(['record', 'admission']);
export const APP_LOG_BOUNDS = Object.freeze({ appLogs: 1, names: 256, rules: 64, ignore: 256, words: 32, domains: 64, addresses: 64, recipients: 100, lineBytes: 65536, windowBytes: 4 * 1024 * 1024, eventsPerWindow: 5000, logActors: 50 });
export const appLogInstanceId = id => `app-log-${id}`;
const KEYS = ['id', 'use', 'log', 'fields', 'outcomes', 'rules', 'ignore', 'logActors', 'backgroundAllows'];
// Named so a profile that writes them is told why: the app-reported tier and its correlation are not in this version.
const LATER_KEYS = ['cause', 'job', 'jobs', 'witness', 'canaries', 'endpoint'];
const FIELD_KEYS = ['action', 'outcome', 'actor', 'target', 'at', 'id', 'key', 'trace'];
const OUTCOME_CLASSES = ['committed', 'denied', 'error'];
const RULE_KEYS = { egress: ['action', 'operation', 'vocabulary', 'name', 'resource', 'observedAs', 'distinctFrom', 'fields', 'lines'], mail: ['action', 'operation', 'vocabulary', 'domains', 'observedAs', 'distinctFrom', 'fields', 'lines'],
  named: ['action', 'operation', 'vocabulary', 'name', 'resource', 'observedAs', 'distinctFrom', 'fields', 'lines'] };
export const PER_APPLICATION = 'per-application';
// The observer sources a rule may declare it is never the effect of: every source but the app log itself and, for an egress or a
// mail rule, the sources that record exactly such a send (an HTTP send is always an egress recorder's kind of effect).
export const DISTINCT_SOURCES = Object.freeze(SOURCES.filter(source => source !== 'app-log'));
const NATIVE_SOURCES = { egress: ['http-egress'], mail: ['smtp-capture', 'provider-feed'], named: [] };
const OBSERVED_AS = { egress: ['http-egress'], mail: ['smtp-capture', 'provider-feed'], named: ['sql-snapshot', 'sql-audit-table', 'http-audit-log', 'file-audit-log', 'hold-proxy', 'otel-genai', 'mcp-jsonrpc'] };
// Declared field values per rule: at most this many, each a pointer a selector's fields pin and a scalar constant or a closed
// word map read from the line (at most FIELD_VALUES selector values, each with at most APP_LOG_BOUNDS.words log words).
const RULE_FIELDS = 8, FIELD_VALUES = 32;
const ID = /^[A-Za-z0-9_-]{1,48}$/;
const ADDRESS = /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[a-z0-9.-]{1,253}$/;
// The egress recorder's resource form (src/http-attribution.mjs EGRESS_RESOURCE): "<METHOD> <declared path>" or "<METHOD> *".
const EGRESS_RESOURCE = /^[A-Z]{3,7} (\*|\/[\x21-\x7e]{0,190})$/;
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const bounded = (value, max) => typeof value === 'string' && value.length >= 1 && value.length <= max && !/[\u0000-\u001f\u007f]/.test(value);
const pointerText = value => typeof value === 'string' && value.length <= 200 && (value === '' || value.startsWith('/')) && !/[\u0000-\u001f\u007f]/.test(value);
const word = value => bounded(value, 64) || (Number.isSafeInteger(value) && value >= -1e9 && value <= 1e9);
const wordKey = value => `${typeof value}:${value}`;
// A window's reason: its problem codes in order, as many whole codes as fit the 200-character reason limit.
export function appLogReason(problems) {
  let reason = '';
  for (const code of [...new Set(problems)].sort()) { const next = reason ? `${reason},${code}` : code; if (next.length > 200) break; reason = next; }
  return reason || null;
}

// Throws an Error with a profile-facing message. target: the whole target (its actors, observers, attribution and checks).
export function validateAppLogs(target) {
  const list = target?.appLogs;
  if (!Array.isArray(list) || list.length < 1 || list.length > APP_LOG_BOUNDS.appLogs) throw new Error('"appLogs" lists exactly one app log in this version');
  const principals = new Set(Object.values(object(target.actors) ? target.actors : {}).map(a => a?.principalId).filter(p => typeof p === 'string'));
  // A background job's principal: the actor pin of a declared background source (it runs no check and holds no credential).
  const backgroundSources = Array.isArray(target.attribution?.background) ? target.attribution.background : [];
  for (const s of backgroundSources) if (typeof s?.select?.actor === 'string') principals.add(s.select.actor);
  const checkPrincipals = new Set((Array.isArray(target.checks) ? target.checks : []).map(c => target.actors?.[c?.actorId]?.principalId).filter(p => typeof p === 'string'));
  const observers = Array.isArray(target.observers) ? target.observers : [];
  list.forEach(o => {
    if (!object(o)) throw new Error('each app log is an object');
    const later = LATER_KEYS.find(key => Object.hasOwn(o, key) || (object(o.log) && Object.hasOwn(o.log, key)));
    if (later !== undefined) throw new Error(`"${later}" is not supported for app logs in this version (the app-reported tier and its correlation come later)`);
    if (Object.keys(o).some(key => !KEYS.includes(key))) throw new Error(`an app log is { ${KEYS.join(', ')} } (ignore optional)`);
    if (typeof o.id !== 'string' || !ID.test(o.id)) throw new Error('an app log needs an "id" of 1-48 letters, digits, "_" or "-"');
    if (!APP_LOG_USES.includes(o.use)) throw new Error(`"use" must be declared and be one of ${APP_LOG_USES.join(', ')} ("record": the log is read and sealed, it decides nothing; "admission": it can also make a clause fail, never pass)`);
    if (!object(o.log) || Object.keys(o.log).join() !== 'file' || !object(o.log.file) || Object.keys(o.log.file).join() !== 'path') throw new Error('"log" is { "file": { "path" } } in this version');
    const path = o.log.file.path;
    if (typeof path !== 'string' || !path.startsWith('/') || path.length > 1024 || /[\u0000-\u001f\u007f]/.test(path)) throw new Error('the app log file "path" must be an absolute path without control characters');
    // A file one observer reads as the app's request log, or as a provider's signed record, is not also its action log.
    if (observers.some(x => x?.type === 'audit-file' && x.path === path)) throw new Error('the app log file is an audit-file observer\'s log: declare one reader per file');
    if (observers.some(x => x?.type === 'provider-feed' && x.feed?.file?.path === path)) throw new Error('the app log file is a provider feed\'s file: the feed must be the provider\'s record, never the app\'s');
    if (!object(o.fields) || Object.keys(o.fields).some(key => !FIELD_KEYS.includes(key)) || !Object.values(o.fields).every(pointerText)) throw new Error(`"fields" maps ${FIELD_KEYS.join(', ')} to JSON pointers ("" or starting with "/")`);
    if (o.fields.action === undefined || o.fields.outcome === undefined) throw new Error('"fields" names at least "action" and "outcome"');
    if (!object(o.outcomes) || Object.keys(o.outcomes).some(key => !OUTCOME_CLASSES.includes(key)) || !Array.isArray(o.outcomes.committed) || !o.outcomes.committed.length) throw new Error('"outcomes" lists the log\'s words for committed (required), denied and error');
    const words = new Set();
    for (const cls of OUTCOME_CLASSES) for (const w of o.outcomes[cls] ?? []) {
      if (!Array.isArray(o.outcomes[cls]) || o.outcomes[cls].length > APP_LOG_BOUNDS.words || !word(w) || words.has(wordKey(w))) throw new Error('each outcome word is a string of 1-64 characters or an integer, listed once');
      words.add(wordKey(w));
    }
    if (!Array.isArray(o.rules) || !o.rules.length || o.rules.length > APP_LOG_BOUNDS.rules) throw new Error(`"rules" lists 1 to ${APP_LOG_BOUNDS.rules} mapped actions`);
    const actions = new Set();
    o.rules.forEach((r, i) => {
      const at = `rule ${i + 1}`;
      // A string first: Object.hasOwn coerces its key, so ["mail"] would pass here and then match none of the === branches below,
      // loading the rule without its egress, mail or named checks (D-01's shape, #502).
      if (!object(r) || typeof r.vocabulary !== 'string' || !Object.hasOwn(RULE_KEYS, r.vocabulary)) throw new Error(`${at}: "vocabulary" is "egress", "mail" or "named"`);
      if (Object.keys(r).some(key => !RULE_KEYS[r.vocabulary].includes(key))) throw new Error(`${at}: a ${r.vocabulary} rule is { ${RULE_KEYS[r.vocabulary].join(', ')} }`);
      if (!bounded(r.action, 128) || actions.has(r.action)) throw new Error(`${at}: needs a unique "action" of 1-128 characters`);
      actions.add(r.action);
      if (!OPERATIONS.includes(r.operation)) throw new Error(`${at}: "operation" must be one of ${OPERATIONS.join(', ')}`);
      if (r.vocabulary !== 'named' && r.operation !== 'send') throw new Error(`${at}: an ${r.vocabulary} rule names a send`);
      if (r.observedAs !== undefined && !(Array.isArray(r.observedAs) && r.observedAs.length >= 1 && new Set(r.observedAs).size === r.observedAs.length && r.observedAs.every(s => OBSERVED_AS[r.vocabulary].includes(s)))) throw new Error(`${at}: "observedAs" lists the sources that also see this action (${OBSERVED_AS[r.vocabulary]?.join(', ')})`);
      if (r.fields !== undefined && !validRuleFields(r.fields, o.fields)) throw new Error(`${at}: "fields" maps 1 to ${RULE_FIELDS} selector pointers to { "const": <a string, number, boolean or null> } or { "from": "<line pointer>", "values": { "<selector value>": [<log words>] } } (1 to ${FIELD_VALUES} values, each word a string of 1-64 characters or an integer listed under one value only, the pointer none of the log's own fields), nothing secret-shaped`);
      if (r.lines !== undefined && r.lines !== PER_APPLICATION) throw new Error(`${at}: "lines" is "${PER_APPLICATION}" (the application writes this action's line once per application) or absent`);
      if (r.distinctFrom !== undefined && !(Array.isArray(r.distinctFrom) && r.distinctFrom.length >= 1 && new Set(r.distinctFrom).size === r.distinctFrom.length && r.distinctFrom.every(x => DISTINCT_SOURCES.includes(x)) && !r.distinctFrom.some(x => (r.observedAs ?? []).includes(x) || (NATIVE_SOURCES[r.vocabulary] ?? []).includes(x))))
        throw new Error(`${at}: "distinctFrom" lists observer sources whose effects this action never is (${DISTINCT_SOURCES.join(', ')}), each once, none of its "observedAs" and none that records its own kind of send (${r.vocabulary}: ${(NATIVE_SOURCES[r.vocabulary] ?? []).join(', ') || 'none'})`);
      if (r.vocabulary === 'egress') {
        if (!egressHost(r.name) || r.name.length > 128) throw new Error(`${at}: "name" is the destination host as the egress recorder names it, at most 128 characters`);
        if (typeof r.resource !== 'string' || !EGRESS_RESOURCE.test(r.resource) || r.resource.startsWith('CONNECT ')) throw new Error(`${at}: "resource" is "<METHOD> <declared path>" or "<METHOD> *", as the egress recorder names a send`);
        // An exact path is one every egress-recorder destination for this host declares, so the log names the send as the recorder
        // does (a background source's exact path is compared with it, src/app-log-verdicts.mjs).
        const path = r.resource.slice(r.resource.indexOf(' ') + 1), same = observers.filter(x => x?.type === 'egress-recorder').flatMap(x => Array.isArray(x.destinations) ? x.destinations : []).filter(d => d?.host === r.name);
        if (path !== '*' && same.length && !same.every(d => Array.isArray(d.paths) && d.paths.includes(path))) throw new Error(`${at}: "resource" names a path the egress recorder's destinations for ${r.name} do not declare; use one of their paths or "<METHOD> *"`);
      }
      if (r.vocabulary === 'named') {
        if (!bounded(r.name, 128)) throw new Error(`${at}: "name" is 1-128 characters`);
        if (r.resource !== undefined && !bounded(r.resource, 200) && !(object(r.resource) && Object.keys(r.resource).join() === 'from' && pointerText(r.resource.from) && r.resource.from !== '')) throw new Error(`${at}: "resource" is 1-200 characters, or { "from": "<pointer>" } read from the line`);
      }
      if (r.vocabulary === 'mail') {
        if (o.fields.target === undefined) throw new Error(`${at}: a mail rule reads its recipients from "fields.target"`);
        if (!Array.isArray(r.domains) || !r.domains.length || r.domains.length > APP_LOG_BOUNDS.domains) throw new Error(`${at}: "domains" lists 1 to ${APP_LOG_BOUNDS.domains} { domain, addresses? }`);
        const seen = new Set();
        for (const d of r.domains) {
          if (!object(d) || Object.keys(d).some(key => !['domain', 'addresses'].includes(key)) || !smtpDomain(d.domain) || d.domain.length > 128 || seen.has(d.domain)) throw new Error(`${at}: each domain is { domain, addresses? }, a lowercase domain name of at most 128 characters, listed once`);
          seen.add(d.domain);
          if (d.addresses !== undefined && !(Array.isArray(d.addresses) && d.addresses.length <= APP_LOG_BOUNDS.addresses && d.addresses.every(a => typeof a === 'string' && ADDRESS.test(a) && a.endsWith(`@${d.domain}`) && mailboxOf(a)?.address === a) && new Set(d.addresses).size === d.addresses.length)) throw new Error(`${at}: addresses are canonical recipients of their domain, listed once`);
        }
      }
    });
    // Every name the log can produce fits the record's bounds, and its declared fields one capture map the window's scope can hold.
    const names = new Set(o.rules.flatMap(namesOf));
    if (names.size > APP_LOG_BOUNDS.names) throw new Error(`the rules name at most ${APP_LOG_BOUNDS.names} distinct names (hosts, mail domains and named effects)`);
    const capture = appLogCapture(o);
    if (capture !== null && !validCaptureMap(capture)) throw new Error('the rules\' "fields" name at most 16 pointers per name and 64 in all');
    // A field read from the line captures a string. A clause that pins it with a non-string equals or in operand could read "no" on
    // the log where the recorder reads the same send as a match: refused, so the log and custody never disagree by type.
    const wordMapped = o.rules.flatMap(r => Object.entries(r.fields ?? {}).filter(([, v]) => fromLine(v)).flatMap(([pointer]) => namesOf(r).map(name => ({ name, pointer }))));
    if (wordMapped.length) for (const [check, select] of clauseSelectors(target)) for (const f of Array.isArray(select.fields) ? select.fields : []) {
      const operand = f?.equals !== undefined ? [f.equals] : Array.isArray(f?.in) ? f.in : [];
      if (!operand.some(x => typeof x !== 'string')) continue;
      const hit = wordMapped.find(m => m.pointer === f.pointer && nameCovers(select.name, m.name));
      if (hit) throw new Error(`check ${check} pins ${f.pointer} with a non-string value, and the app log reads ${f.pointer} on ${hit.name} from the line as a string: write the pin as a string, or map that field as a constant`);
    }
    if (o.ignore !== undefined && !(Array.isArray(o.ignore) && o.ignore.length <= APP_LOG_BOUNDS.ignore && o.ignore.every(x => object(x) && Object.keys(x).join() === 'action' && bounded(x.action, 128) && !actions.has(x.action)) && new Set(o.ignore.map(x => x.action)).size === o.ignore.length)) throw new Error('"ignore" lists { action } entries, each once and never a mapped action');
    // Who acted: a principal names one log value and a log value one principal, so the log can never be read as two actors.
    if (!object(o.logActors) || !Object.keys(o.logActors).length || Object.keys(o.logActors).length > APP_LOG_BOUNDS.logActors) throw new Error('"logActors" maps declared principals to the log\'s actor values');
    const values = new Set();
    for (const [principal, value] of Object.entries(o.logActors)) {
      if (!principals.has(principal)) throw new Error('"logActors" keys are principals of declared actors (their principalId) or the actor pin of a declared background source');
      if (!word(value) || values.has(wordKey(value))) throw new Error('"logActors" is one to one: each log value names one principal');
      values.add(wordKey(value));
    }
    if (o.fields.actor === undefined) throw new Error('"fields.actor" is required: the log is read by who acted');
    if (![...Object.keys(o.logActors)].some(p => checkPrincipals.has(p))) throw new Error('"logActors" names no principal of an actor that runs a check');
    // The correlation value the application received is read only where the target sends one (src/egress-rules.mjs).
    if (o.fields.trace !== undefined && typeof target.correlation?.header !== 'string') throw new Error('"fields.trace" needs the target\'s "correlation" header: it reads the value the application received with each check');
    if (o.backgroundAllows !== undefined) validateBackgroundAllows(o, target, backgroundSources);
    // A background source that names a check's own principal leaves nothing to tell the check's actions from its own.
    const background = Array.isArray(target.attribution?.background) ? target.attribution.background : [];
    if (background.some(s => typeof s?.select?.actor === 'string' && checkPrincipals.has(s.select.actor))) throw new Error('a background source names the principal of an actor that runs a check: an app log cannot tell their actions apart');
  });
}

const typed = value => ({ type: value === null ? 'null' : typeof value, value });
const namesOf = r => r.vocabulary === 'mail' ? r.domains.map(d => d.domain) : [r.name];
const constant = v => object(v) && Object.keys(v).join() === 'const';
const fromLine = v => object(v) && Object.keys(v).sort().join() === 'from,values';
// An effect.only "allowBackground" source, read at the custody tier as an allow: its select without the actor pin, exactly the
// shape-only allow an operator would write (src/contracts.mjs appends it to the clause's allow).
export const backgroundAllowSelect = source => Object.fromEntries(Object.entries(source.select).filter(([key]) => key !== 'actor'));
const BACKGROUND_ALLOWS = 64;
// appLogs[0].backgroundAllows: [{ check, effect, allow, source }], each an allow entry of an effect.only clause that is exactly a
// declared background source's shape. Under "use": "admission" the source pins its actor to a principal the actor map names
// (the log can tell the job's lines from the check's), and the log declares fields.trace (the check's own line carries its token).
function validateBackgroundAllows(o, target, sources) {
  const list = o.backgroundAllows;
  if (!Array.isArray(list) || list.length > BACKGROUND_ALLOWS) throw new Error(`"backgroundAllows" lists at most ${BACKGROUND_ALLOWS} { check, effect, allow, source }`);
  const seen = new Set(), checks = Array.isArray(target.checks) ? target.checks : [];
  for (const m of list) {
    if (!object(m) || Object.keys(m).sort().join() !== 'allow,check,effect,source' || typeof m.check !== 'string' || !Number.isSafeInteger(m.effect) || !Number.isSafeInteger(m.allow) || typeof m.source !== 'string') throw new Error('each "backgroundAllows" entry is { check, effect, allow, source }');
    const key = `${m.check}\n${m.effect}\n${m.allow}`;
    const clause = checks.find(c => c?.id === m.check)?.effects?.[m.effect], source = sources.find(s => s?.id === m.source);
    if (seen.has(key) || !object(clause) || clause.kind !== 'effect.only' || !Array.isArray(clause.allow) || m.allow < 0 || m.allow >= clause.allow.length || !object(source)
      || digest(clause.allow[m.allow]) !== digest(backgroundAllowSelect(source))) throw new Error(`"backgroundAllows": check ${m.check} effect ${m.effect + 1} allow ${m.allow + 1} is not background source ${m.source}'s shape`);
    seen.add(key);
    // A clause's marks are the tail of its allow list, in order (as normalization appends them): a hand-edited profile cannot point
    // a mark at an allow entry the author wrote.
    const forClause = list.filter(x => object(x) && x.check === m.check && x.effect === m.effect).map(x => x.allow);
    if (forClause.some((a, i) => a !== clause.allow.length - forClause.length + i)) throw new Error(`"backgroundAllows": check ${m.check} effect ${m.effect + 1}: the marks are the last ${forClause.length} allow entries, in order`);
    if (o.use === 'admission') {
      if (typeof source.select.actor !== 'string' || !Object.hasOwn(o.logActors, source.select.actor)) throw new Error(`"allowBackground" ${m.source}: under "use": "admission" the background source pins its "actor" to a principal "logActors" names, so the log can tell its lines from the check's`);
      if (o.fields.trace === undefined) throw new Error(`"allowBackground" ${m.source}: under "use": "admission" the log declares "fields.trace", so the check's own line is told apart by its correlation token`);
    }
  }
}
// Every selector a check's clauses and claim rules name, as [checkId, selector].
function clauseSelectors(target) {
  const out = [];
  for (const c of Array.isArray(target?.checks) ? target.checks : []) {
    const add = s => { if (object(s)) out.push([c?.id, s]); };
    for (const e of Array.isArray(c?.effects) ? c.effects : []) {
      if (!object(e)) continue;
      add(e.select);
      for (const item of Array.isArray(e.expect) ? e.expect : []) add(object(item) && object(item.select) ? item.select : item);
      for (const item of Array.isArray(e.allow) ? e.allow : []) add(item);
    }
    for (const claim of Array.isArray(c?.claims) ? c.claims : []) add(claim?.select);
  }
  return out;
}
// Could a selector's name rule (exact, { prefix } or absent) name this effect name?
const nameCovers = (rule, name) => rule === undefined || rule === name || (object(rule) && typeof rule.prefix === 'string' && name.startsWith(rule.prefix));
// A rule's declared constants as a captured record (src/body-fields.mjs), or null when it declares none.
function ruleCaptured(fields) {
  const entries = Object.entries(fields ?? {}).filter(([, v]) => constant(v));
  return entries.length ? { status: 'captured', values: Object.fromEntries(entries.map(([pointer, v]) => [pointer, typed(v.const)])) } : null;
}
// The values a rule's field may capture at each selector pointer: its constant, or the selector values of its word map.
const ruleFieldValues = fields => Object.fromEntries(Object.entries(fields ?? {}).map(([pointer, v]) => [pointer, constant(v) ? [v.const] : Object.keys(v.values)]));
// logFields: the log's own pointers (action, outcome, actor, ...); a field is never read from one of them.
function validRuleFields(fields, logFields) {
  if (!object(fields) || !Object.keys(fields).length || Object.keys(fields).length > RULE_FIELDS) return false;
  if (!Object.values(fields).every(v => constant(v) || fromLine(v))) return false;
  for (const v of Object.values(fields).filter(fromLine)) {
    if (!pointerText(v.from) || v.from === '' || Object.values(logFields).includes(v.from)) return false;
    if (!object(v.values) || !Object.keys(v.values).length || Object.keys(v.values).length > FIELD_VALUES) return false;
    const words = new Set();
    for (const list of Object.values(v.values)) {
      if (!Array.isArray(list) || !list.length || list.length > APP_LOG_BOUNDS.words) return false;
      for (const w of list) { if (!word(w) || words.has(wordKey(w))) return false; words.add(wordKey(w)); }
    }
  }
  // Every value a field can capture is a valid captured scalar, nothing secret-shaped (one record per value, as a line would make).
  try { for (const [pointer, values] of Object.entries(ruleFieldValues(fields))) for (const value of values) validateCaptured({ status: 'captured', values: { [pointer]: typed(value) } }); return true; } catch { return false; }
}
// The capture map of an app log's scope: each name's declared field pointers (the union over the rules that name it), or null.
function appLogCapture(o) {
  const map = new Map();
  for (const r of o.rules) if (r.fields !== undefined) for (const name of namesOf(r)) map.set(name, [...new Set([...(map.get(name) ?? []), ...Object.keys(r.fields)])].sort());
  return map.size ? Object.fromEntries(map) : null;
}
const sorted = list => [...list].sort((a, b) => a < b ? -1 : a > b ? 1 : 0);
// What admissions read beyond the projection (src/app-log-verdicts.mjs), part of each run's appLogs record:
//   values    each name's capturable values per selector pointer (the union over its rules): a sealed captured value outside
//             them is refused
//   distinct  each name's sources every rule producing it lists in distinctFrom (only names with at least one)
//   exact     the names every rule of which is an egress rule with an exact resource ("<METHOD> /path"): only for these is a
//             background source's exact resource pin kept when admissions set background entries aside
//   perApplication  the names every rule of which declares "lines": "per-application" (countBy clauses are read only on these)
//   trace     whether the log declares fields.trace
//   backgroundAllows  the appLogs[0].backgroundAllows list, ordered by check, effect and allow
export function appLogReads(o) {
  // Maps throughout: a name or pointer is data, never a property of an object (a rule may be named "__proto__").
  const values = new Map(), distinct = new Map(), exact = new Map(), perApplication = new Map();
  for (const r of o.rules) for (const name of namesOf(r)) {
    for (const [pointer, list] of Object.entries(ruleFieldValues(r.fields))) {
      if (!values.has(name)) values.set(name, new Map());
      const seen = values.get(name).get(pointer) ?? [];
      values.get(name).set(pointer, [...seen, ...list.filter(v => !seen.some(x => typed(x).type === typed(v).type && x === v))]);
    }
    const own = new Set(r.distinctFrom ?? []);
    distinct.set(name, distinct.has(name) ? new Set([...distinct.get(name)].filter(x => own.has(x))) : own);
    exact.set(name, (exact.get(name) ?? true) && r.vocabulary === 'egress' && !r.resource.endsWith(' *'));
    perApplication.set(name, (perApplication.get(name) ?? true) && r.lines === PER_APPLICATION);
  }
  const ordered = Object.fromEntries(sorted([...values.keys()]).map(name => [name, Object.fromEntries(sorted([...values.get(name).keys()]).map(p => [p, values.get(name).get(p)]))]));
  return { values: ordered, distinct: Object.fromEntries(sorted([...distinct].filter(([, set]) => set.size).map(([name]) => name)).map(name => [name, sorted(distinct.get(name))])),
    exact: sorted([...exact].filter(([, yes]) => yes).map(([name]) => name)), perApplication: sorted([...perApplication].filter(([, yes]) => yes).map(([name]) => name)),
    trace: o.fields.trace !== undefined, backgroundAllows: [...(o.backgroundAllows ?? [])].map(m => ({ check: m.check, effect: m.effect, allow: m.allow, source: m.source }))
      .sort((a, b) => a.check < b.check ? -1 : a.check > b.check ? 1 : a.effect - b.effect || a.allow - b.allow) };
}
// Which observer sources each name is the same effect as: the sources every rule that produces the name lists in observedAs.
// A selector pinned to a source is read on the log only for an exact name whose list holds that source.
export function appLogProjection(o) {
  const byName = new Map();
  for (const r of o.rules) for (const name of r.vocabulary === 'mail' ? r.domains.map(d => d.domain) : [r.name]) {
    const sources = new Set(r.observedAs ?? []);
    byName.set(name, byName.has(name) ? new Set([...byName.get(name)].filter(s => sources.has(s))) : sources);
  }
  return Object.fromEntries([...byName].filter(([, set]) => set.size).map(([name, set]) => [name, [...set].sort()]).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0));
}

// The normalized configuration the observer reads. target: the whole target (the declared observers' witness domains).
export function compileAppLog(o, target = {}) {
  const outcomeOf = new Map();
  for (const cls of OUTCOME_CLASSES) for (const w of o.outcomes[cls] ?? []) outcomeOf.set(wordKey(w), cls);
  // A field read from the line: its pointer, and each log word (typed key) to the selector value it captures.
  const reads = fields => Object.entries(fields ?? {}).filter(([, v]) => fromLine(v)).map(([pointer, v]) => ({ pointer, from: v.from,
    words: new Map(Object.entries(v.values).flatMap(([value, words]) => words.map(w => [wordKey(w), value]))) }));
  const rules = new Map(o.rules.map(r => [r.action, { ...r, domainSet: new Map((r.domains ?? []).map(d => [d.domain, d.addresses ?? []])), captured: ruleCaptured(r.fields), reads: reads(r.fields) }]));
  const actorOf = new Map(Object.entries(o.logActors).map(([principal, value]) => [wordKey(value), principal]));
  // An actor value the map does not name is kept only as a digest keyed with a secret this run does not keep.
  const actorKey = randomBytes(32);
  // An idempotency key is kept as a digest keyed with another secret the run does not keep: equal within the run, never stored.
  const keyKey = randomBytes(32), correlationHeader = typeof target.correlation?.header === 'string' ? target.correlation.header : null;
  // Mail to a declared observer's witness domain is that observer's witness, never one of the application's effects.
  const witnessDomains = new Set((Array.isArray(target.observers) ? target.observers : []).map(x => x?.witness?.domain).filter(d => typeof d === 'string'));
  return Object.freeze({ id: o.id, instanceId: appLogInstanceId(o.id), path: o.log.file.path, fields: o.fields, outcomeOf, rules, ignore: new Set((o.ignore ?? []).map(x => x.action)), actorOf, actorKey, keyKey, correlationHeader, witnessDomains, scope: appLogScope(o) });
}

// What an app log's windows can name: the operations and names of its rules. Presence-only always: the application writes
// it, so its silence never shows that something did not happen.
export function appLogScope(o) {
  const names = [...new Set(o.rules.flatMap(r => r.vocabulary === 'mail' ? r.domains.map(d => d.domain) : [r.name]))], capture = appLogCapture(o);
  return Object.freeze({ operations: [...new Set(o.rules.map(r => r.operation))], names, actorAttribution: 'principal', evidence: 'presence-only', ...(capture ? { capture } : {}) });
}

// The run record of one app log: what was declared, by digest (the file path stays local).
export const appLogMappingDigest = o => digest({ schema: APP_LOG_SCHEMA, fields: o.fields, outcomes: o.outcomes, rules: o.rules, ignore: o.ignore ?? [], logActors: o.logActors, ...(o.backgroundAllows ? { backgroundAllows: o.backgroundAllows } : {}) });

const pointer = (root, path) => {
  let value = root;
  for (const token of path === '' ? [] : path.slice(1).split('/').map(t => t.replaceAll('~1', '/').replaceAll('~0', '~'))) {
    if (['__proto__', 'prototype', 'constructor'].includes(token) || value === null || typeof value !== 'object' || !Object.hasOwn(value, token)) return undefined;
    value = value[token];
  }
  return value;
};

// One line of the log, read under the configuration: { kind, effects, problems }.
//   kind     'rule' (a mapped action), 'ignored', 'witness' (mail to a declared witness domain), or a problem kind
//   entryId  for a rule, its entry id (fields.id) as a typed key, or null
//   effects  for a rule, one { actor, operation, name, resource, outcome, at } per recipient (mail) or one (otherwise)
//   problems the codes that leave the window partial
// Pure: the same line always reads the same way.
export function readAppLogLine(line, cfg) {
  let entry;
  try { if (Buffer.byteLength(line) > APP_LOG_BOUNDS.lineBytes) throw new Error(); entry = JSON.parse(line); } catch { return { kind: 'unreadable', effects: [], problems: ['app-log-unreadable-line'] }; }
  if (!object(entry)) return { kind: 'unreadable', effects: [], problems: ['app-log-unreadable-line'] };
  const action = pointer(entry, cfg.fields.action);
  if (typeof action !== 'string') return { kind: 'unreadable', effects: [], problems: ['app-log-unreadable-line'] };
  if (cfg.ignore.has(action)) return { kind: 'ignored', effects: [], problems: [] };
  const rule = cfg.rules.get(action);
  if (!rule) return { kind: 'unknown', effects: [], problems: ['app-log-unknown-action'] };
  const problems = [];
  const rawOutcome = pointer(entry, cfg.fields.outcome);
  const cls = word(rawOutcome) ? cfg.outcomeOf.get(wordKey(rawOutcome)) : undefined;
  if (cls === undefined) problems.push('app-log-outcome-unmapped');
  const outcome = cls ?? 'unknown';
  const rawActor = pointer(entry, cfg.fields.actor);
  const unlisted = value => `unlisted:${createHmac('sha256', cfg.actorKey).update(value).digest('hex').slice(0, 16)}`;
  const actor = rawActor === undefined || rawActor === null ? null : word(rawActor) ? cfg.actorOf.get(wordKey(rawActor)) ?? unlisted(wordKey(rawActor)) : unlisted(`json:${JSON.stringify(rawActor)}`);
  let at = null;
  if (cfg.fields.at !== undefined) {
    const raw = pointer(entry, cfg.fields.at);
    if (typeof raw === 'string' && raw.length <= 64 && !Number.isNaN(Date.parse(raw))) at = new Date(Date.parse(raw)).toISOString();
    else problems.push('app-log-time-unreadable');
  }
  // The entry id, when the log has one: a repeated id is a replayed or duplicated line (the observer reads that partial).
  const rawId = cfg.fields.id === undefined ? undefined : pointer(entry, cfg.fields.id);
  const entryId = rawId === undefined || rawId === null ? null : word(rawId) ? wordKey(rawId) : null;
  // Declared constants, and each field read from the line whose word the rule's word map lists (any other reads unknown).
  const values = { ...(rule.captured?.values ?? {}) };
  for (const f of rule.reads) {
    const raw = pointer(entry, f.from), value = word(raw) ? f.words.get(wordKey(raw)) : undefined;
    if (value !== undefined) values[f.pointer] = typed(value);
  }
  const captured = Object.keys(values).length ? { status: 'captured', values } : null;
  // The correlation token of the value the application received (fields.trace), and its idempotency key's digest (fields.key).
  const correlation = {};
  if (cfg.fields.trace !== undefined && cfg.correlationHeader !== null) {
    const token = correlationTokenOf(cfg.correlationHeader, [pointer(entry, cfg.fields.trace)]);
    if (token !== null) correlation.settlementToken = token;
  }
  // A key is any JSON value of at most 1024 characters (typed: the string "1" is not the number 1); a line with no key has none;
  // a longer or unparsable one reads key:unreadable, and no countBy clause is read on a window holding one.
  if (cfg.fields.key !== undefined) {
    const raw = pointer(entry, cfg.fields.key);
    if (raw !== undefined && raw !== null) {
      const text = JSON.stringify(raw);
      correlation.requestId = typeof text === 'string' && text.length <= 1024 ? `key:${createHmac('sha256', cfg.keyKey).update(text).digest('hex').slice(0, 16)}` : 'key:unreadable';
    }
  }
  const base = { actor, operation: rule.operation, outcome, at, ...(Object.keys(correlation).length ? { correlation } : {}), ...(captured ? { captured } : {}) };
  // A named rule's resource may be read from the line: a bounded single-line string, or null and a partial window.
  let resource = typeof rule.resource === 'string' ? rule.resource : null;
  if (object(rule.resource)) {
    const raw = pointer(entry, rule.resource.from);
    if (bounded(raw, 200)) resource = raw; else problems.push('app-log-resource-unusable');
  }
  if (rule.vocabulary !== 'mail') return { kind: 'rule', entryId, effects: [{ ...base, name: rule.name, resource }], problems };
  // Mail: every recipient is one send, named by its domain and a declared address or "*".
  const raw = pointer(entry, cfg.fields.target);
  const list = typeof raw === 'string' ? [raw] : Array.isArray(raw) && raw.length >= 1 && raw.length <= APP_LOG_BOUNDS.recipients && raw.every(x => typeof x === 'string') ? raw : null;
  if (!list) return { kind: 'rule', entryId, effects: [], problems: [...problems, 'app-log-target-unusable'] };
  const effects = [];
  let witness = 0;
  for (const text of list) {
    const rcpt = text.length <= 320 ? recipientOf(text) : null;
    if (!rcpt || rcpt.literal) { problems.push('app-log-target-unusable'); continue; }
    if (cfg.witnessDomains.has(rcpt.domain)) { witness++; continue; }
    if (!rcpt.mailbox || rcpt.sourceRoute) problems.push('app-log-target-unusable');
    const named = rcpt.mailbox ? addressResource(rcpt.mailbox, rule.domainSet.get(rcpt.domain) ?? []) : { resource: '*', ambiguous: false };
    if (named.ambiguous) problems.push('app-log-recipient-ambiguous');
    // A rule's fields describe its declared domains only: mail to another domain carries no captured record.
    const { captured: _captured, ...bare } = base;
    effects.push({ ...(rule.domainSet.has(rcpt.domain) ? base : bare), name: rcpt.domain.slice(0, 128), resource: named.resource });
  }
  if (witness && !effects.length && list.length === witness) return { kind: 'witness', entryId: null, effects: [], problems: [] };
  if (witness) problems.push('app-log-witness-mixed');
  return { kind: 'rule', entryId, effects, problems: [...new Set(problems)] };
}
