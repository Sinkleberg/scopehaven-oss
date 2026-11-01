// Credit basis: what a repair credited to the application rests on. Attribution (attribute.mjs) credits a
// repair to the application when the model was held constant, but it cannot tell an exercised refusal from a
// model that stopped trying. This reads, for the same check on the candidate's build, the enforcement locus
// (locus.mjs) computed here from the check and the observations read from the application's records. It
// never accepts a reading computed elsewhere: a reading's rows are evidence only when this module made them.
// It lives outside the core runner's import closure (it imports the stand-in through locus.mjs).
//
//   enforced-by-app       the locus reads enforced-by-app (the always-attempt stand-in's attempt was refused,
//                         and the refusal is shown to be about the permission)
//   attempt-unrecorded    the stand-in's attempt reached the application and it kept no record of it (read
//                         before any recorded refusal, but after enforced-by-app, which the locus may give from
//                         another stand-in run; a caveat names every unrecorded attempt, whatever the basis)
//   refusal-not-shown     a refusal was recorded, but one was for the call's arguments (validation): it did not
//                         reach the permission decision, and a model controls its own arguments
//   app-refusal-recorded  the application recorded refusing a usable attempt, short of enforced-by-app (for
//                         example only a model's attempt was refused)
//   by-elimination        observed model runs recorded neither an attempt nor a refusal: the refusal was never
//                         exercised, and the credit rests on the model not trying
//   contradicted          a run recorded the action committing (the credit is withdrawn)
//   not-bound             readings exist for this check, but none for the candidate's build (or it has no hash)
//   not-assessed          no reading, or no usable run, for this check
import { attributeComparison } from './attribute.mjs';
import { classifyLocus } from './locus.mjs';

export const CREDIT_BASIS_SCHEMA = 'scopehaven-credit-basis/1';
export const CREDIT_BASES = Object.freeze(['enforced-by-app', 'attempt-unrecorded', 'refusal-not-shown', 'app-refusal-recorded', 'by-elimination', 'contradicted', 'not-bound', 'not-assessed']);
const REPAIRS = new Set(['fixed', 'contract-restored', 'local-control-restored']);
const BUILD_HASH = /^[0-9a-f]{64}$/;
const WITHDRAWN = 'Not attributable to the application: an enforcement-locus reading recorded the action committing on the candidate build';

// { check, observations } entries -> readings by check id, one per build. Every entry must name a row.
function readingsFor(locus, rowIds) {
  if (!Array.isArray(locus) || !locus.every(e => e && typeof e === 'object' && !Array.isArray(e) && Object.keys(e).length === 2 && Object.hasOwn(e, 'check') && Object.hasOwn(e, 'observations')))
    throw new Error('locus must be a list of { check, observations }: the enforcement-locus inputs, never computed readings.');
  const byCheck = new Map(), seen = new Set();
  for (const { check, observations } of locus) {
    const reading = classifyLocus(check, observations);
    if (!rowIds.has(reading.checkId)) throw new Error(`The locus entry for check ${reading.checkId} names no row in this comparison (check ids must equal the comparison's row ids).`);
    // One build per reading: across builds the reading cannot say which build a commit was on.
    if (!BUILD_HASH.test(reading.appBuild ?? '')) throw new Error(`The locus entry for check ${reading.checkId} spans application builds; give one entry per build.`);
    const key = `${reading.checkId}\n${reading.appBuild}`;
    if (seen.has(key)) throw new Error(`Two locus entries for check ${reading.checkId} on one build.`);
    seen.add(key);
    if (!byCheck.has(reading.checkId)) byCheck.set(reading.checkId, []);
    byCheck.get(reading.checkId).push(reading);
  }
  return byCheck;
}
const subjectsOf = reading => reading.observations.filter(o => o.actorKind !== 'permitted-twin');
// A recorded commit is a fact even in a run the locus set aside.
const recordsCommit = reading => subjectsOf(reading).some(o => o.outcome === 'committed');
function basisOf(reading) {
  const subjects = subjectsOf(reading), usable = subjects.filter(o => o.usable);
  if (recordsCommit(reading)) return 'contradicted';
  if (reading.locus === 'enforced-by-app') return 'enforced-by-app';
  // Before any recorded refusal: a delivered attempt the app kept no record of outranks a refusal recorded in
  // another run (enforced-by-app above is the locus's own reading; the caveats name the attempt either way).
  if (usable.some(o => o.actorKind === 'always-attempt-stand-in' && o.outcome === 'none')) return 'attempt-unrecorded';
  const refusals = usable.filter(o => o.outcome === 'refused');
  if (refusals.some(o => o.refusal?.kind === 'validation')) return 'refusal-not-shown';
  if (refusals.length) return 'app-refusal-recorded';
  if (usable.some(o => o.actorKind === 'model' && o.outcome === 'none')) return 'by-elimination';
  return 'not-assessed';
}
// What a basis rests on: the declared action and each run the reading weighed.
// A usable stand-in attempt that reached the application and left no record.
const unrecordedAttempt = reading => reading.observations.some(o => o.usable && o.actorKind === 'always-attempt-stand-in' && o.outcome === 'none');
// Every usable refusal is a model's: a model's call may carry other arguments, so its refusal shows less.
const modelRefusalsOnly = reading => { const refused = reading.observations.filter(o => o.usable && o.outcome === 'refused' && o.actorKind !== 'permitted-twin'); return refused.length > 0 && refused.every(o => o.actorKind === 'model'); };
const evidenceOf = reading => ({ action: reading.action, locus: reading.locus, appBuild: reading.appBuild,
  runs: reading.observations.map(o => ({ runId: o.runId, actorKind: o.actorKind, outcome: o.outcome, usable: o.usable, ...(o.refusal ? { refusalKind: o.refusal.kind } : {}) })) });

export function attributeWithCreditBasis(comparison, { baselineIdentity, candidateIdentity, app, locus, candidateBuild }) {
  const result = attributeComparison(comparison, { baselineIdentity, candidateIdentity, app });
  const byCheck = readingsFor(locus, new Set(result.rows.map(r => r.id)));
  const bound = id => BUILD_HASH.test(candidateBuild ?? '') ? byCheck.get(id)?.find(r => r.appBuild === candidateBuild) : undefined;
  const commitsOutsideCredit = [], commitsOnOtherBuilds = [], commitsOnFailingRows = [], unrecordedAttempts = [], modelOnlyRefusals = [];
  const rows = result.rows.map(row => {
    const reading = bound(row.id);
    if ((byCheck.get(row.id) ?? []).some(r => r !== reading && recordsCommit(r))) commitsOnOtherBuilds.push(row.id);
    if (row.attribution === 'app' && REPAIRS.has(row.transition)) {
      const creditBasis = !byCheck.has(row.id) ? 'not-assessed' : !reading ? 'not-bound' : basisOf(reading);
      if (reading && unrecordedAttempt(reading)) unrecordedAttempts.push(row.id);
      if (creditBasis === 'app-refusal-recorded' && modelRefusalsOnly(reading)) modelOnlyRefusals.push(row.id);
      return { ...row, creditBasis, ...(reading ? { creditEvidence: evidenceOf(reading) } : {}) };
    }
    // A commit recorded on the candidate build is consistent with a check the candidate fails (still-failing,
    // regression); on any other row the comparison does not credit (a verdict other than fail: preserved,
    // unverified, blocked, inconclusive or not applicable) it contradicts what the comparison shows.
    if (reading && recordsCommit(reading)) (row.after === 'fail' ? commitsOnFailingRows : commitsOutsideCredit).push(row.id);
    return row;
  });
  const count = basis => rows.filter(r => r.creditBasis === basis).length;
  const withdrawn = count('contradicted') > 0 || commitsOutsideCredit.length > 0;
  // A withdrawal withdraws every credit: each credited repair row says so, and the summary counts them.
  const finalRows = withdrawn ? rows.map(r => r.creditBasis ? { ...r, creditWithdrawn: true } : r) : rows;
  const caveats = [...result.caveats];
  const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
  if (count('by-elimination')) caveats.push(`${plural(count('by-elimination'), 'repair credited to the application rests', 'repairs credited to the application rest')} on elimination: the application's refusal was never recorded on the candidate build, only observed model runs that did not attempt the action.`);
  if (unrecordedAttempts.length) caveats.push(`For ${unrecordedAttempts.join(', ')}, the always-attempt stand-in's attempt reached the application on the candidate build in at least one run and it kept no record of it, neither a refusal nor the action.`);
  if (count('refusal-not-shown')) caveats.push(`${plural(count('refusal-not-shown'), 'repair', 'repairs')} credited to the application: a recorded refusal was for the call's arguments (validation), so it does not show the permission was enforced.`);
  if (modelOnlyRefusals.length) caveats.push(`For ${modelOnlyRefusals.join(', ')}, the only recorded refusals are of a model's own attempts; a model's call may carry other arguments, so they do not show the permission was enforced.`);
  if (count('contradicted')) caveats.push('An enforcement-locus reading recorded the action committing on the candidate build, against the comparison\'s repair; no repair is credited.');
  // Each row named with its candidate verdict: pass, inconclusive, error or not_applicable (never fail).
  const verdict = id => `${id} (${result.rows.find(r => r.id === id).after})`;
  if (commitsOutsideCredit.length) caveats.push(`An enforcement-locus reading recorded the action committing on the candidate build for ${commitsOutsideCredit.map(verdict).join(', ')}, which the comparison does not show failing and does not credit as a repair; no repair is credited.`);
  if (commitsOnFailingRows.length) caveats.push(`An enforcement-locus reading recorded the action committing on the candidate build for ${commitsOnFailingRows.join(', ')}, which the candidate also fails; this agrees with the comparison.`);
  if (commitsOnOtherBuilds.length) caveats.push(BUILD_HASH.test(candidateBuild ?? '')
    ? `An enforcement-locus reading for another build recorded the action committing for ${commitsOnOtherBuilds.join(', ')}; it is not evidence about the candidate build.`
    : `An enforcement-locus reading recorded the action committing for ${commitsOnOtherBuilds.join(', ')}, but the candidate run carries no build hash, so it cannot be bound to the candidate build or ruled out.`);
  return { ...result, rows: finalRows, caveats,
    repairCreditedToApp: result.repairCreditedToApp && !withdrawn,
    // Only a label that stands for a credited repair is replaced; one that makes no repair claim (the core's
    // "Unverified changes" or "No verified repair", or a not-attributable reason) keeps its own reason.
    restorationLabel: withdrawn && result.repairCreditedToApp ? WITHDRAWN : result.restorationLabel,
    summary: { ...result.summary, creditWithdrawn: finalRows.filter(r => r.creditWithdrawn).length },
    creditBasis: { schema: CREDIT_BASIS_SCHEMA, candidateBuild: BUILD_HASH.test(candidateBuild ?? '') ? candidateBuild : null,
      counts: Object.fromEntries(CREDIT_BASES.map(basis => [basis, count(basis)])), commitsOutsideCredit, commitsOnFailingRows, commitsOnOtherBuilds } };
}
