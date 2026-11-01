import { escape, scopeStatement, CUSTODY_RULE } from './report.mjs';
import { CONTROL_CUSTODY_LIMIT } from './custody.mjs';
import { allowedUse, allowedUseLabel } from './allowed-use.mjs';
import { CLAIM_TYPES } from './residual.mjs';

// Compact summary: target metadata, counts, statuses, check ids, limitations, identities and
// custody tags remain visible. It is not anonymized. Observed values, traces, assertion evidence,
// request and response bodies, check titles and human notes are never read here.
// Whole limitations only, never clipped mid-sentence: they are shown in order while they fit the budget.
// The limitation budget fits every shipped run's limitations whole (exports must state the synthetic scope and the
// unsupported behaviour); it only bounds absurd inputs.
export const SUMMARY_LIMITS = Object.freeze({ limitationChars: 6000, listedChecks: 12 });
const CUSTODY_GRADES = Object.freeze(['subject-writable', 'observer-held', 'independent']);
const STATES = [['pass', 'Passed'], ['fail', 'Failed'], ['inconclusive', 'Inconclusive'], ['error', 'Errors'], ['not_applicable', 'Not applicable']];
const short = value => typeof value === 'string' && value ? value.slice(0, 16) : 'not recorded';
const listed = (rows, max) => `${rows.slice(0, max).map(row => escape(row.id)).join(', ')}${rows.length > max ? ` and ${rows.length - max} more` : ''}`;

// custody: optional [{ source, custody }] from a ledger entry's anchors (integrations/ledger).
// An invalid entry prevents an aggregate grade; its unrecognized strings are never printed.
function custodyLine(input) {
  if (input !== undefined && !Array.isArray(input)) return 'Ledger anchor custody: unrecognized input; no aggregate grade is reported.';
  // Each entry's fields are read once, so an accessor cannot pass validation as one grade and print as another.
  const custody = input === undefined ? undefined : Array.from(input, entry => (entry && typeof entry === 'object' ? { source: entry.source, custody: entry.custody } : entry));
  const known = Array.isArray(custody) ? custody.filter(entry => typeof entry?.source === 'string' && entry.source.trim() && CUSTODY_GRADES.includes(entry.custody)) : [];
  const invalid = (custody?.length ?? 0) - known.length;
  if (invalid) return `Ledger anchor custody: ${invalid} of ${custody.length} caller-supplied anchor${custody.length === 1 ? '' : 's'} ${invalid === 1 ? 'is' : 'are'} unrecognized or malformed; no aggregate grade is reported.`;
  if (!known.length) return 'Ledger anchor custody: not supplied.';
  const weakest = CUSTODY_GRADES.find(grade => known.some(entry => entry.custody === grade));
  return `Ledger anchor custody: ${weakest} (weakest of ${known.length} caller-supplied anchor${known.length === 1 ? '' : 's'}: ${known.map(entry => `${entry.source} ${entry.custody}`).join(', ')}).`;
}

// Clause custody comes from the run, separately from caller-supplied ledger anchors.
// Only custody tags are read from assertions; assertion names, actual values and evidence stay out.
function recordCustody(results) {
  const tags = results.flatMap(row => (Array.isArray(row.assertions) ? row.assertions : [])
    .filter(assertion => assertion && typeof assertion === 'object' && Object.hasOwn(assertion, 'custody')).map(assertion => assertion.custody));
  if (!tags.length) return 'Observed-effect clause custody: not recorded for this run.';
  const groups = [...CUSTODY_GRADES.map(grade => [grade, tags.filter(tag => tag === grade).length]),
    ['no observer decided', tags.filter(tag => tag === null || tag === undefined).length],
    ['unrecognized', tags.filter(tag => tag !== null && tag !== undefined && !CUSTODY_GRADES.includes(tag)).length]];
  const held = results.flatMap(row => (Array.isArray(row.assertions) ? row.assertions : [])).filter(assertion => assertion && typeof assertion === 'object' && Object.hasOwn(assertion, 'custodyReason')).length;
  return `Observed-effect clause custody: ${groups.filter(([, count]) => count).map(([grade, count]) => `${count} ${grade}`).join(', ')}. ${held} clause verdict${held === 1 ? '' : 's'} read inconclusive because only records the application can write decided ${held === 1 ? 'it' : 'them'}. Custody says who can write a record, not whether it is accurate.`;
}

// residual: optional { claimCounts, residual } computed from the run by the exporter (src/residual.mjs residualDocument), which reads
// the traces this page never reads. Only counts, check and observer ids, channel ids and reason codes are printed from it: never an
// assertion name. Without it the page says where the residual is.
const ids = list => (Array.isArray(list) ? list.filter(id => typeof id === 'string') : []);
// A reason is printed only when it is code-shaped (a hand-edited run could carry free text in a reason field): anything else
// prints as unrecognized.
const REASON_CODE = /^[a-z0-9][A-Za-z0-9:._-]{0,127}$/;
const codes = list => (Array.isArray(list) ? list.map(code => (typeof code === 'string' && REASON_CODE.test(code) ? code : 'unrecognized')) : []);
const idOf = value => (typeof value === 'string' ? value : 'an unnamed entry');
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
function residualLines(input) {
  if (input === undefined) return ['Residual: not supplied with this page; it is in the full report and in ./scopehaven export --format residual.'];
  const r = input?.residual, counts = input?.claimCounts;
  // Only a whole residual is read: a missing part must never print as a positive line ("pairing held", "ran in full").
  if (!record(r) || !record(counts) || !Object.hasOwn(r, 'channels') || !Array.isArray(r.inconclusive) || !record(r.controls) || !Array.isArray(r.observers)) return ['Residual: unrecognized input; nothing is reported from it.'];
  const lines = [`Claims: ${CLAIM_TYPES.map(type => `${Number.isSafeInteger(counts[type]) ? counts[type] : 0} ${type}`).join(', ')}.`];
  const channels = r.channels;
  if (channels && channels.declared === false) lines.push('Channels undeclared: each absence pass rests only on the observers that decided it.');
  else if (channels && channels.declared === true) lines.push(Array.isArray(channels.unobserved) && channels.unobserved.length || Array.isArray(channels.unaccounted) && channels.unaccounted.length || Array.isArray(channels.unlisted) && channels.unlisted.length || Array.isArray(channels.controls) && channels.controls.length || typeof channels.gap === 'string'
    ? `Declared channels not shown: ${[...(Array.isArray(channels.unobserved) ? channels.unobserved : []).map(c => `${idOf(c?.id)} not observed in ${ids(c?.rows).length} check${ids(c?.rows).length === 1 ? '' : 's'}`), ...(Array.isArray(channels.unaccounted) ? channels.unaccounted : []).map(c => `${idOf(c?.id)} carried an unaccounted effect in ${ids(c?.rows).length} check${ids(c?.rows).length === 1 ? '' : 's'}`), ...(Array.isArray(channels.unlisted) ? channels.unlisted : []).map(u => `observer ${idOf(u?.observer)}, which no channel lists, recorded an effect in ${ids(u?.rows).length} check${ids(u?.rows).length === 1 ? '' : 's'}`), ...(Array.isArray(channels.controls) && channels.controls.length ? [`${channels.controls.length} allowed-use control${channels.controls.length === 1 ? '' : 's'} whose absence they do not support`] : []), ...(typeof channels.gap === 'string' ? ['channels-undeclared for every absence pass (the declaration, the target or the run\'s confinement)'] : [])].join('; ')}.`
    : 'Every declared channel was observed in each absence pass\'s window.');
  const unsettled = Array.isArray(r.inconclusive) ? r.inconclusive : [];
  lines.push(unsettled.length ? `Read inconclusive: ${unsettled.slice(0, SUMMARY_LIMITS.listedChecks).map(e => `${idOf(e?.id)} (${[...new Set(codes(e?.reasons))].join(', ')})`).join(', ')}${unsettled.length > SUMMARY_LIMITS.listedChecks ? ` and ${unsettled.length - SUMMARY_LIMITS.listedChecks} more` : ''}.` : 'No check reads inconclusive.');
  const c = r.controls ?? {}, unpaired = ids(c.notPassed).length + ids(c.unpairedPasses?.checks).length + (Array.isArray(c.unpairedSelectors) ? c.unpairedSelectors.length : 0);
  lines.push(unpaired ? `Allowed-use pairing not held: ${ids(c.notPassed).length} required control${ids(c.notPassed).length === 1 ? '' : 's'} not passed, ${ids(c.unpairedPasses?.checks).length} pass${ids(c.unpairedPasses?.checks).length === 1 ? '' : 'es'} with no same-route control, ${Array.isArray(c.unpairedSelectors) ? c.unpairedSelectors.length : 0} absence selector${(c.unpairedSelectors?.length ?? 0) === 1 ? '' : 's'} with no allowed-use twin.` : 'Allowed-use pairing held.');
  const observers = Array.isArray(r.observers) ? r.observers : [];
  lines.push(observers.length ? `Observers not running or incomplete in some window: ${observers.map(o => `${idOf(o?.type)} ${idOf(o?.id)}`).join(', ')}.` : r.observersDeclared === null ? 'Observers are not read for this evidence origin.' : r.observersDeclared ? 'Every declared observer ran in full in each window.' : 'No observers declared.');
  return lines;
}

export function renderSummary(run, { custody, residual } = {}) {
  const results = Array.isArray(run.results) ? run.results : [];
  const count = state => results.filter(row => row.status === state).length;
  const notTested = results.filter(row => row.status === 'not_applicable'), unsettled = results.filter(row => row.status === 'inconclusive' || row.status === 'error');
  const limitations = (Array.isArray(run.limitations) ? run.limitations : []).filter(line => typeof line === 'string');
  const shown = [];
  let used = 0;
  for (const line of limitations) {
    if (used + line.length > SUMMARY_LIMITS.limitationChars) break;
    shown.push(line); used += line.length;
  }
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Scopehaven summary ${escape(run.id)}</title><style>body{font:14px/1.45 system-ui;margin:32px auto;max-width:760px;padding:0 20px;color:#132c40}h1{font-size:22px;margin:0 0 4px}h2{font-size:15px;margin:16px 0 4px}p,ul{margin:4px 0}table{border-collapse:collapse;width:100%;margin:8px 0}td,th{padding:4px 6px;text-align:left;border-bottom:1px solid #dfe8ed}code{font-size:12px;overflow-wrap:anywhere}small{color:#536875}@page{size:letter;margin:12mm}@media print{body{margin:0;max-width:none;padding:0;font-size:10pt}}</style>`
    + `<h1>Scopehaven summary</h1><p>${escape(run.targetName ?? run.targetId ?? 'Unnamed target')} · ${escape(run.createdAt ?? 'date not recorded')}</p>`
    + `<p><strong>${escape(scopeStatement(run))}</strong></p>`
    + `<table><thead><tr><th>Checks listed</th>${STATES.map(([, label]) => `<th>${label}</th>`).join('')}</tr></thead><tbody><tr><td>${results.length}</td>${STATES.map(([state]) => `<td>${count(state)}</td>`).join('')}</tr></tbody></table>`
    + `<p>${escape(allowedUseLabel(allowedUse(run)))}</p>`
    + `<h2>What was not tested</h2><ul>${shown.map(line => `<li>${escape(line)}</li>`).join('')}`
    + `${limitations.length > shown.length ? `<li>${limitations.length - shown.length} ${shown.length ? 'further ' : ''}limitation${limitations.length - shown.length === 1 ? ' is' : 's are'} listed in the full report.</li>` : ''}`
    + `${notTested.length ? `<li>Not applicable to this target: ${listed(notTested, SUMMARY_LIMITS.listedChecks)}.</li>` : ''}`
    + `${unsettled.length ? `<li>Not settled (inconclusive or error): ${listed(unsettled, SUMMARY_LIMITS.listedChecks)}.</li>` : ''}`
    + `${!limitations.length && !notTested.length && !unsettled.length ? '<li>No limitation was recorded with this run.</li>' : ''}</ul>`
    + `<h2>Custody</h2><p>${escape(recordCustody(results))}</p><p>${escape(CUSTODY_RULE)}</p>${results.some(row => row.severity === 'control') ? `<p>${escape(CONTROL_CUSTODY_LIMIT)}</p>` : ''}<p>${escape(custodyLine(custody))}</p>`
    + `<h2>Residual</h2>${residualLines(residual).map(line => `<p>${escape(line)}</p>`).join('')}`
    + `<h2>Verify</h2><p>Run ${escape(run.id)}. Evidence integrity sha256 ${escape(run.integrity?.sha256 ?? 'not recorded')}. Suite ${escape(short(run.suiteHash))}, policy ${escape(short(run.policyHash))}, evaluator ${escape(short(run.evaluatorHash))}.</p>`
    + `<p>Signature: this page is covered only when a scopehaven-attest/1 envelope comes with it. Check it with <code>node integrations/attest/cli.mjs verify --key KEY.pub.pem --envelope ENVELOPE.dsse.json --dir DIR</code> or <code>python3 verify_envelope.py</code> with the same arguments. A valid signature shows that the key holder produced these exact bytes, not that the results are correct.</p>`
    + `<p><small>These are observed checks, not a safety certification. Target metadata, scope, limitations and check ids remain visible; this summary is not anonymized. Check details, evidence and remediation are in the full report.</small></p></html>`;
}
