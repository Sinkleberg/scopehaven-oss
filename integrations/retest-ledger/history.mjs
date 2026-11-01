// Retest history (scopehaven-retest-history/1): for each finding on a customer's applications, what happened to it across
// the runs in a verified evidence ledger. Built only from a ledger that verified with every run's signed file, the run files
// themselves, and the operator's declarations. A finding's computed state comes from the runs alone, through core's own
// compareRuns; declarations add fix claims, twins, a class code and an open reason, each labelled as declared, and never
// turn a run's verdict into another one.
//
// Finding identity is the SARIF fingerprint scopehavenCheck/v1 (src/sarif.mjs): digest({ applicationId, suiteId, checkId }),
// so a finding keeps its id across runs, builds, re-exports and SARIF uploads, and two applications never share one.
//
// States, in the order a finding can move through them:
//   found               a run of the ledger failed the check (status fail).
//   fix-claimed         the operator declared a fix in a build; nothing has verified it yet.
//   FIXED_VERIFIED      a later run passed the check, compared with the last run that failed it by core's compareRuns: the pair
//                       is compatible (same suite, policy, fixture, evaluator, application, profile and evidence origin), every
//                       required allowed-use control passed with a proven identity, no row that passed before failed, the row's
//                       transition is one of core's repair transitions (so a fail resting only on the app's own log, a declared
//                       absent field or a provider's later outcome is never credited), and every declared twin passed.
//   NO_VERIFIED_REPAIR  after a fix claim, or after a later run stopped failing the check, a run did not verify a repair; the
//                       event says why (still failing, incompatible pair, controls or twins not passing, a new failure, or a
//                       transition core reads as unverified).
//   regressed           the check failed again in a run after it was FIXED_VERIFIED. A fail counts whatever the pair: a fail is
//                       never weaker evidence than a pass.
// A finding is open unless its state is FIXED_VERIFIED.
//
// What it does not show: that a check covers the behaviour it names, that a fix holds outside the runs in the ledger, or anything
// about runs the ledger does not hold. The per-finding FIXED_VERIFIED is a row-level reading: it does not require every other row
// of the run to be decided, which core's run-level retestVerdict does; each event carries that run-level verdict beside it.
import { digest } from '../../src/domain.mjs';
import { compareRuns, retestVerdict } from '../../src/runner.mjs';
import { LEDGER_VERSION, isPaymentsRun } from '../ledger/verify.mjs';
import { resolutionBlocker } from '../tickets/tickets.mjs';

export const HISTORY_VERSION = 'scopehaven-retest-history/1';
export const DECLARATIONS_VERSION = 'scopehaven-retest-declarations/1';
export const STATES = Object.freeze(['found', 'fix-claimed', 'FIXED_VERIFIED', 'NO_VERIFIED_REPAIR', 'regressed']);
export const IDENTITY_RULE = 'finding = scopehavenCheck/v1 = sha256 of the stable JSON of { applicationId, suiteId, checkId }, as src/sarif.mjs fingerprints a result';
export const MEANING = 'What happened to each finding across the runs of one verified evidence ledger, read with core\'s compareRuns. '
  + 'Computed states come from the signed runs only; fix claims, twins, classes and open reasons are the operator\'s declarations. '
  + 'Not a statement that the application is safe, that a check covers the behaviour it names, or that a fix holds outside these runs.';
// The transitions core credits as a repair (compareRuns scopes); anything else is not a verified fix.
const REPAIR_TRANSITIONS = Object.freeze(['fixed', 'contract-restored', 'local-control-restored']);
const TEXT = /^[\p{L}\p{N} .,:;()'/_+#@&-]{1,200}$/u;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const CLASS = /^[A-Z][0-9]{1,2}$/;
const BUILD_LIMIT = 300;

export const findingId = ({ applicationId, suiteId, checkId }) => digest({ applicationId, suiteId: suiteId ?? null, checkId });
const refused = detail => Object.assign(new Error(`retest-history-refused: ${detail}`), { code: 'retest-history-refused' });
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
const only = (value, keys, what) => { for (const key of Object.keys(value)) if (!keys.includes(key)) throw refused(`${what} has an unknown field ${JSON.stringify(key).slice(0, 40)}`); };
// Plain text with no link in it (no scheme separator, no www. prefix), so nothing an operator writes renders as one downstream.
const text = (value, what) => { if (typeof value !== 'string' || !TEXT.test(value) || /:\/\/|(^|\s)www\./i.test(value)) throw refused(`${what} must be 1 to 200 plain characters (letters, digits, spaces and . , : ; ( ) ' / _ + # @ & -), with no link`); return value; };

// The operator's declarations, validated. Unknown fields, duplicate findings and free text outside a plain character set are refused,
// so nothing an operator writes can carry markup or a claim-shaped field into the signed history.
export function readDeclarations(value) {
  if (!plain(value) || value.schema !== DECLARATIONS_VERSION) throw refused(`declarations must be a ${DECLARATIONS_VERSION} object`);
  only(value, ['schema', 'customer', 'findings'], 'declarations');
  const customer = text(value.customer, 'customer');
  if (!Array.isArray(value.findings) || value.findings.length > 10000) throw refused('declarations.findings must be a list of at most 10000');
  const findings = new Map();
  for (const [i, f] of value.findings.entries()) {
    const at = `declarations.findings[${i}]`;
    if (!plain(f)) throw refused(`${at} must be an object`);
    only(f, ['applicationId', 'suiteId', 'checkId', 'class', 'twins', 'fixClaims', 'openReason'], at);
    for (const key of ['applicationId', 'suiteId', 'checkId']) if (typeof f[key] !== 'string' || !ID.test(f[key])) throw refused(`${at}.${key} must be an identifier`);
    if (f.class !== undefined && (typeof f.class !== 'string' || !CLASS.test(f.class))) throw refused(`${at}.class must be a class code such as A4`);
    const twins = f.twins ?? [];
    if (!Array.isArray(twins) || twins.length > 32 || !twins.every(t => typeof t === 'string' && ID.test(t)) || new Set(twins).size !== twins.length || twins.includes(f.checkId)) throw refused(`${at}.twins must be distinct check ids other than the finding's own`);
    const claims = f.fixClaims ?? [];
    if (!Array.isArray(claims) || claims.length > 100) throw refused(`${at}.fixClaims must be a list`);
    const builds = claims.map((c, j) => {
      if (!plain(c)) throw refused(`${at}.fixClaims[${j}] must be an object`);
      only(c, ['build'], `${at}.fixClaims[${j}]`);
      if (typeof c.build !== 'string' || !c.build.length || c.build.length > BUILD_LIMIT || /[\u0000-\u001f\u007f]/.test(c.build)) throw refused(`${at}.fixClaims[${j}].build must be a build string`);
      return c.build;
    });
    if (new Set(builds).size !== builds.length) throw refused(`${at}.fixClaims repeats a build`);
    const openReason = f.openReason === undefined ? null : text(f.openReason, `${at}.openReason`);
    const id = findingId(f);
    if (findings.has(id)) throw refused(`${at} repeats a finding`);
    findings.set(id, { class: f.class ?? null, twins, fixClaims: builds, openReason });
  }
  return { customer, findings };
}

// Every non-payments run of the verified ledger paired with its signed run file. runFiles: an array of parsed run exports (attest's
// savedRun core plus its coreSha256). Each ledger run must have exactly one file whose core digest is the one the signed entry
// records, so the history reads the same run the ledger and its envelope vouch for.
function bindRuns(verified, runFiles) {
  if (!verified || verified.ledger !== LEDGER_VERSION || verified.verdict !== 'verified' || !Array.isArray(verified.entries)) throw refused('history is built only from a verified ledger');
  if (verified.unsignedTail !== 0) throw refused('the ledger has entries no checkpoint covers');
  const byDigest = new Map();
  for (const file of runFiles) {
    if (byDigest.has(file.coreSha256)) throw refused(`two run files carry the same run core (${file.core.id})`);
    byDigest.set(file.coreSha256, file.core);
  }
  const bound = [];
  let payments = 0;
  for (const entry of verified.entries) for (const run of entry.runs) {
    if (isPaymentsRun(run)) { payments++; continue; }
    const core = byDigest.get(run.coreSha256);
    if (!core || core.id !== run.id) throw refused(`no run file for ledger run ${run.id} (entry ${entry.index})`);
    if (JSON.stringify(core.results.map(r => [r.id, r.status])) !== JSON.stringify(run.verdicts)) throw refused(`the run file for ${run.id} differs from the ledger's verdicts`);
    bound.push({ entry: entry.index, recordedAt: entry.recordedAt, run: core });
  }
  if (verified.verdictsCheckedAgainstRunFiles !== verified.runs) throw refused('every run in the ledger must have been checked against its signed run file (verify with --run-files)');
  return { bound, payments };
}

// The custody reasons core gave on a row's undecided assertions (src/http-effects.mjs custody rule), so a pass the app's own records
// cannot support says why.
const custodyOf = row => [...new Set((Array.isArray(row.assertions) ? row.assertions : []).filter(a => a?.status === 'inconclusive' && typeof a.custodyReason === 'string').map(a => `custody ${a.custody ?? 'unknown'}: ${a.custodyReason}`))];
const statusOf = (run, checkId) => run.results.find(r => r.id === checkId)?.status ?? null;

// The history. verified: verifyLedger's result (with runFiles). runFiles: [{ core, coreSha256 }]. declarations: readDeclarations' value.
export function retestHistory(verified, runFiles, declarations) {
  const { bound, payments } = bindRuns(verified, runFiles);
  const declared = declarations?.findings ?? new Map();
  const records = new Map(), comparisons = new Map();
  const compare = (baseline, candidate) => {
    const key = `${baseline.id} ${candidate.id}`;
    if (!comparisons.has(key)) {
      let comparison;
      try { comparison = compareRuns(baseline, candidate); } catch { comparison = null; }
      comparisons.set(key, comparison);
    }
    return comparisons.get(key);
  };
  const at = ({ entry, recordedAt, run }) => ({ entry, runId: run.id, recordedAt, build: typeof run.build === 'string' ? run.build : null });
  const move = (record, state, where, extra = {}) => { record.state = state; record.events.push({ state, source: 'run', ...at(where), ...extra }); };

  // The builds seen so far per application and suite: a claim names a build, and is consumed by the first run of it.
  const seenBuilds = new Map(), scopeKey = run => JSON.stringify([run.applicationId, run.suiteId ?? null]);
  // Runs of one application and suite must appear in the ledger in the order they were made (each run's signed createdAt), so a
  // backfill or an envelope that lists runs out of order can never let an older pass close a finding a newer run failed.
  const lastTime = new Map();
  for (const where of bound) {
    const { run } = where;
    if (!Array.isArray(run.results)) continue;
    const time = typeof run.createdAt === 'string' ? Date.parse(run.createdAt) : NaN;
    if (!Number.isFinite(time)) throw refused(`ledger run ${run.id} has no readable createdAt`);
    if (time < (lastTime.get(scopeKey(run)) ?? -Infinity)) throw refused(`ledger run ${run.id} (entry ${where.entry}) was made before an earlier entry's run of the same application and suite; runs must be appended in the order they were made`);
    lastTime.set(scopeKey(run), time);
    if (!seenBuilds.has(scopeKey(run))) seenBuilds.set(scopeKey(run), new Set());
    seenBuilds.get(scopeKey(run)).add(run.build);
    // Fix claims are placed at the first run of the claimed build, before that run is read. A claim on a finding already
    // FIXED_VERIFIED is consumed with no event: nothing is left to claim.
    for (const record of records.values()) {
      if (record.applicationId !== run.applicationId || record.suiteId !== (run.suiteId ?? null) || !record.pendingClaims.includes(run.build)) continue;
      record.pendingClaims = record.pendingClaims.filter(b => b !== run.build);
      if (record.state === 'FIXED_VERIFIED') continue;
      if (record.state !== 'regressed') record.state = 'fix-claimed';
      record.events.push({ state: 'fix-claimed', source: 'declared', ...at(where), reason: 'The operator declared a fix in this build.' });
      record.claimOpen = true;
    }
    for (const row of run.results) {
      const id = findingId({ applicationId: run.applicationId, suiteId: run.suiteId, checkId: row.id });
      let record = records.get(id);
      if (!record) {
        if (row.status !== 'fail') continue;
        const d = declared.get(id);
        record = { finding: id, applicationId: run.applicationId, suiteId: run.suiteId ?? null, checkId: row.id, class: d?.class ?? null, twins: d?.twins ?? [],
          state: null, events: [], regressions: 0, reopenedFix: false, lastFail: null, lastStatus: 'fail', pendingClaims: [...(d?.fixClaims ?? [])], claimOpen: false, openReason: d?.openReason ?? null };
        records.set(id, record);
        // A claim on a build already run (this one included) before the check was seen failing names no later build: ignored.
        record.pendingClaims = record.pendingClaims.filter(b => !seenBuilds.get(scopeKey(run)).has(b));
        record.lastFail = where;
        move(record, 'found', where, { reason: 'The check failed in this run.' });
        continue;
      }
      const wasFailing = record.lastStatus === 'fail';
      record.lastStatus = row.status;
      if (row.status === 'fail') {
        // A fail after a verified fix is a regression, also when a later run had already reopened that fix (inconclusive or absent).
        // The regression answers any open claim too, so a later fail is not read as "still failing in the claimed build".
        if (record.state === 'FIXED_VERIFIED' || record.reopenedFix) { move(record, 'regressed', where, { reason: 'The check failed again after a verified fix.' }); record.regressions++; record.reopenedFix = false; record.claimOpen = false; }
        else if (record.claimOpen) { move(record, 'NO_VERIFIED_REPAIR', where, { reason: 'Still failing in the claimed build.' }); record.claimOpen = false; }
        record.lastFail = where;
        continue;
      }
      // A verified fix stays verified only while later runs pass the check: any other status reopens it.
      if (record.state === 'FIXED_VERIFIED') { if (row.status !== 'pass') { move(record, 'NO_VERIFIED_REPAIR', where, { reason: `No verified repair: a later run read the check as ${row.status}, not pass.` }); record.reopenedFix = true; } continue; }
      // The check did not fail: did this run verify a repair against the last run that failed it?
      const baseline = record.lastFail.run, comparison = compare(baseline, run);
      const transition = comparison?.rows?.find(r => r.id === row.id);
      const twinsFailing = record.twins.filter(t => statusOf(run, t) !== 'pass');
      const why = !comparison ? 'core could not compare the two runs'
        : !(Date.parse(run.createdAt) > Date.parse(baseline.createdAt)) ? 'the run was not made after the run that failed'
        : !comparison.compatible ? `the runs are not comparable (${comparison.reasons.slice(0, 3).join(' ').replace(/\.$/, '') || 'core gave no reason'})`
        : !comparison.controlsPass ? 'the required allowed-use controls did not all pass'
        : comparison.summary.newFailures ? 'a check that passed before now fails'
        : resolutionBlocker(comparison, transition) ? resolutionBlocker(comparison, transition)
        : !REPAIR_TRANSITIONS.includes(transition?.transition) ? `core reads the row as ${transition?.transition ?? 'missing'} (${[transition?.transitionReason, `status ${row.status}`, ...custodyOf(row)].filter(Boolean).join('; ')})`
        : twinsFailing.length ? `declared twin ${twinsFailing.join(', ')} did not pass`
        : null;
      const extra = { baselineRunId: baseline.id, runLevelVerdict: comparison ? retestVerdict(comparison) : 'INCONCLUSIVE', transition: transition?.transition ?? null };
      // A run that moved the check off fail, or the first run after a claim, is recorded; later undecided runs repeat nothing.
      if (why === null) { move(record, 'FIXED_VERIFIED', where, { ...extra, reason: `Passed against run ${baseline.id}, with the allowed-use controls${record.twins.length ? ' and declared twins' : ''} passing.` }); record.claimOpen = false; record.reopenedFix = false; }
      else if (wasFailing || record.claimOpen) { move(record, 'NO_VERIFIED_REPAIR', where, { ...extra, reason: `No verified repair: ${why}.` }); record.claimOpen = false; }
    }
    // A verified fix whose check this run of the same application and suite does not carry is no longer shown: reopened.
    const ids = new Set(run.results.map(r => r.id));
    for (const record of records.values()) if (record.state === 'FIXED_VERIFIED' && record.applicationId === run.applicationId && record.suiteId === (run.suiteId ?? null) && !ids.has(record.checkId)) {
      move(record, 'NO_VERIFIED_REPAIR', where, { reason: 'No verified repair: a later run of this application and suite does not carry the check.' });
      record.lastStatus = null; record.reopenedFix = true;
    }
  }
  // Claims for builds no run in the ledger has: the event is recorded, and the finding reads fix-claimed unless a run made it
  // FIXED_VERIFIED or regressed, which a declaration never replaces.
  for (const record of records.values()) for (const build of record.pendingClaims) if (record.state !== 'FIXED_VERIFIED') {
    if (record.state !== 'regressed') record.state = 'fix-claimed';
    record.events.push({ state: 'fix-claimed', source: 'declared', entry: null, runId: null, recordedAt: null, build, reason: 'The operator declared a fix in this build; no run of it is in the ledger yet.' });
  }
  // Code-point order, so the bytes never depend on the machine's locale.
  const order = (a, b) => a < b ? -1 : a > b ? 1 : 0;
  const findings = [...records.values()].sort((a, b) => order(String(a.applicationId), String(b.applicationId)) || order(a.suiteId ?? '', b.suiteId ?? '') || order(a.checkId, b.checkId))
    .map(r => ({ finding: r.finding, applicationId: r.applicationId, suiteId: r.suiteId, checkId: r.checkId, class: r.class, state: r.state, open: r.state !== 'FIXED_VERIFIED',
      openReason: r.state === 'FIXED_VERIFIED' ? null : r.openReason, twins: r.twins, regressions: r.regressions, events: r.events }));
  const counts = { findings: findings.length, open: findings.filter(f => f.open).length, openWithoutReason: findings.filter(f => f.open && !f.openReason).length,
    ...Object.fromEntries(STATES.map(s => [s, findings.filter(f => f.state === s).length])), regressedEver: findings.filter(f => f.regressions > 0).length };
  const declaredUnseen = [...declared.keys()].filter(id => !records.has(id)).length;
  const head = verified.checkpoints.at(-1);
  return { schema: HISTORY_VERSION, customer: declarations?.customer ?? null, ledger: { log: verified.log, size: verified.covered, root: head.rootHash, signedAt: head.signedAt },
    identityRule: IDENTITY_RULE, meaning: MEANING, witness: 'none', runs: bound.length, paymentsRunsSkipped: payments, declaredFindingsNotSeen: declaredUnseen, findings, counts };
}
