// Attribution: whose change is a verdict change? The core comparison
// (src/runner.mjs compareRuns) is taken as it is; this adds, per row, whether a
// flip can be credited to the application or has to be put down to the model.
//
//   app               the model was held constant and the build changed
//   model             the model changed and a build hash shows the app did not
//   confounded        both changed, or the app is unchanged only by declaration
//   unexplained       neither changed; run-to-run variation, not a fix
//   model-unverified  the model was not observed (or not comparably) in one or both runs
//
// A failing check that passes after a model change is not a repair. The core's
// label survives only when every row that moved is credited to the application.
import { STRENGTHS, weakest } from './identity.mjs';

export const ATTRIBUTION_SCHEMA = 'scopehaven-model-attribution/2';
// Repairs the core verified. blocked-by-controls moved but was not verified (controls failed).
const REPAIRS = new Set(['fixed', 'contract-restored', 'local-control-restored']);
const FLIPS = new Set([...REPAIRS, 'blocked-by-controls', 'regression']);
const COMPARABLE = new Set(['observed']);
const atLeast = (s, floor) => STRENGTHS.indexOf(s) >= STRENGTHS.indexOf(floor);

// Two windows of one tap session that overlap are the same evidence, never two runs.
function sameEvidence(a, b) {
  if (!a?.tapSession || a.tapSession !== b?.tapSession) return false;
  const lo = w => w?.from ?? 0, hi = w => (w?.to ?? Infinity);
  return lo(a.window) < hi(b.window) && lo(b.window) < hi(a.window);
}

// same | different | silent-change | unverifiable, at the weakest strength used.
export function compareModelIdentities(baseline, candidate) {
  const reasons = [];
  for (const [side, id] of [['baseline', baseline], ['candidate', candidate]]) {
    if (!id || typeof id !== 'object' || !Array.isArray(id.models)) reasons.push(`${side}-identity-missing`);
    // A model entry that is not an object, or an "observed" identity that does not name exactly one
    // model, is malformed: never read as the first model alone.
    else if (id.models.some(m => m === null || typeof m !== 'object' || Array.isArray(m)) || (id.state === 'observed' && id.models.length !== 1)) reasons.push(`${side}-identity-malformed`);
    else if (id.state === 'mixed') reasons.push('mixed-models');
    else if (!COMPARABLE.has(id.state)) reasons.push(`${side}-model-${id.state}`);
    else if (id.models.some(m => !m.served)) reasons.push(`${side}-served-model-not-reported`);
  }
  if (!reasons.length && sameEvidence(baseline, candidate)) reasons.push('same-tap-window');
  // A whole window served by several models says nothing about which model served
  // which step; compare per-check windows instead.
  if (reasons.length) return { relation: 'unverifiable', strength: 'none', reasons: [...new Set(reasons)], changes: [] };
  const [ma] = baseline.models, [mb] = candidate.models;
  const changes = [];
  // Weights on both sides: the digest decides, whatever the name is spelled ("x" and "x:latest").
  if (ma.weightsDigest && mb.weightsDigest) {
    if (ma.weightsDigest !== mb.weightsDigest) changes.push(ma.served === mb.served || ollamaAlias(ma.served, mb.served)
      ? { kind: 'weights-digest', served: mb.served, before: ma.weightsDigest, after: mb.weightsDigest }
      : { kind: 'served-models', removed: [ma.served], added: [mb.served] });
    if (!changes.length) return { relation: 'same', strength: 'weights-digest', reasons: [], changes: [], ...(baseline.upstream !== candidate.upstream ? { notes: ['upstream changed; the weights digests match'] } : {}) };
    return { relation: changes[0].kind === 'weights-digest' ? 'silent-change' : 'different', strength: 'weights-digest', reasons: [], changes };
  }
  // Below weights, a different server is a different model source.
  if (baseline.upstream !== candidate.upstream) return { relation: 'different', strength: weakest([ma.strength, mb.strength]), reasons: [], changes: [{ kind: 'upstream', before: baseline.upstream ?? null, after: candidate.upstream ?? null }] };
  if (ma.served !== mb.served) return { relation: 'different', strength: weakest([ma.strength, mb.strength]), reasons: [], changes: [{ kind: 'served-models', removed: [ma.served], added: [mb.served] }] };
  if (ma.fingerprints?.length && mb.fingerprints?.length) {
    const fa = [...ma.fingerprints].sort(), fb = [...mb.fingerprints].sort();
    if (fa.join('\n') !== fb.join('\n')) return { relation: 'silent-change', strength: 'vendor-fingerprint', reasons: [], changes: [{ kind: 'fingerprint', served: ma.served, before: fa, after: fb }] };
    return { relation: 'same', strength: 'vendor-fingerprint', reasons: [], changes: [] };
  }
  return { relation: 'same', strength: 'vendor-model-string', reasons: [], changes: [] };
}
const ollamaAlias = (a, b) => typeof a === 'string' && typeof b === 'string' && (a.includes(':') ? a : `${a}:latest`) === (b.includes(':') ? b : `${b}:latest`);

// Whether the application changed between two runs, and on what evidence:
//   build-hash      both runs carry a hash of the app build (targetBuildHash)
//   declared-label  only an operator-declared build label or the config hash derived from it
//   unknown         nothing usable; counts as changed
// Null or empty fields are unknown, never equal.
export function appChangedBetween(baselineRun, candidateRun) {
  const known = k => typeof baselineRun?.[k] === 'string' && baselineRun[k].length > 0 && typeof candidateRun?.[k] === 'string' && candidateRun[k].length > 0;
  if (known('targetBuildHash')) {
    const changed = baselineRun.targetBuildHash !== candidateRun.targetBuildHash;
    return { changed, evidence: 'build-hash', basis: `${changed ? 'differs' : 'same'}:targetBuildHash` };
  }
  const labels = ['build', 'targetConfigHash'].filter(known);
  if (labels.length) {
    const differ = labels.filter(k => baselineRun[k] !== candidateRun[k]);
    return { changed: differ.length > 0, evidence: 'declared-label', basis: differ.length ? `differs:${differ.join(',')}` : `same:${labels.join(',')}` };
  }
  return { changed: true, evidence: 'unknown', basis: 'build-identity-unknown' };
}

const WHY = Object.freeze({
  model: 'the model changed and a build hash shows the application did not',
  confounded: 'the model changed and the application may have changed too',
  unexplained: 'neither the model nor the build changed (run-to-run variation)',
  'model-unverified': 'the model was not observed comparably in both runs',
});
const FILE_READ = 'a model identity was read from a tap log file that any process running as its user can rewrite';

export function attributeComparison(comparison, { baselineIdentity, candidateIdentity, app }) {
  if (!comparison || typeof comparison !== 'object' || !Array.isArray(comparison.rows) || typeof comparison.compatible !== 'boolean' || typeof comparison.restorationLabel !== 'string') throw new Error('Expected a core compareRuns result.');
  if (!app || typeof app.changed !== 'boolean') throw new Error('Expected app: { changed, evidence, basis } (see appChangedBetween).');
  // compareRuns already attributes runs that carry modelIdentity; attributing its result again would
  // take the attributed label for the core's and credit twice.
  if (comparison.modelAttribution?.state === 'recorded') throw new Error('Expected a core compareRuns result that is not already attributed.');
  const model = compareModelIdentities(baselineIdentity, candidateIdentity);
  const modelMoved = model.relation === 'different' || model.relation === 'silent-change';
  // An identity the HTTP connector read from a tap log file (custody 'tap-file') can be rewritten and re-chained by
  // any process running as the log's user, the application's included. It still shows which model the file reports,
  // but a model it shows held constant never credits a repair: its verdict changes read model-unverified.
  const fileHeld = !modelMoved && model.relation !== 'unverifiable' && [baselineIdentity, candidateIdentity].some(id => id?.custody === 'tap-file');
  // The model alone takes the blame only when a build hash shows the app did not change.
  const appHeld = app.changed === false && app.evidence === 'build-hash';
  // An incompatible pair has no verdict change to credit to anyone.
  const flipCause = !comparison.compatible ? null
    : model.relation === 'unverifiable' || fileHeld ? 'model-unverified'
    : modelMoved ? (appHeld ? 'model' : 'confounded')
    : app.changed ? 'app' : 'unexplained';
  const summary = { app: 0, model: 0, confounded: 0, unexplained: 0, 'model-unverified': 0, heldAcrossModelChange: 0, failedAcrossModelChange: 0 };
  const rows = comparison.rows.map(row => {
    let attribution;
    const moved = FLIPS.has(row.transition) || (row.transition === 'unverified' && row.before !== row.after);
    if (!comparison.compatible || row.transition === 'incompatible') attribution = 'incompatible';
    else if (moved) { attribution = flipCause; summary[attribution]++; }
    else if (row.transition === 'preserved' && modelMoved) { attribution = 'held-across-model-change'; summary.heldAcrossModelChange++; }
    else if (row.transition === 'still-failing' && modelMoved) { attribution = 'failed-across-model-change'; summary.failedAcrossModelChange++; }
    else attribution = 'no-change';
    return { id: row.id, title: row.title, before: row.before, after: row.after, transition: row.transition, attribution };
  });
  const flips = rows.filter(r => !['incompatible', 'no-change', 'held-across-model-change', 'failed-across-model-change'].includes(r.attribution));
  const repaired = rows.filter(r => REPAIRS.has(r.transition));
  const allApp = flips.every(r => r.attribution === 'app');
  const vendorOnly = model.relation === 'same' && !atLeast(model.strength, 'weights-digest');
  const restorationLabel = !comparison.compatible ? comparison.restorationLabel
    : !allApp ? `Not attributable to the application: ${fileHeld ? FILE_READ : WHY[flipCause]}`
    : vendorOnly && flips.length ? `${comparison.restorationLabel} (model held constant only by the vendor's ${model.strength === 'vendor-fingerprint' ? 'model string and fingerprint' : 'model string'}; a same-named vendor update would not be seen)`
    : comparison.restorationLabel;
  const caveats = [];
  if (model.relation === 'same' && !atLeast(model.strength, 'weights-digest')) caveats.push(`The model was held constant only by the vendor's ${model.strength === 'vendor-fingerprint' ? 'model string and fingerprint' : 'model string'}; weights not verified.`);
  if (app.evidence === 'declared-label' && app.changed === false) caveats.push('The application is unchanged only by its declared build label.');
  if (fileHeld) caveats.push('The model was shown held constant only by a tap log file (custody tap-file) that any process running as its user can rewrite; no verdict change is credited to the application on it.');
  return { schema: ATTRIBUTION_SCHEMA, baselineId: comparison.baselineId ?? null, candidateId: comparison.candidateId ?? null, compatible: comparison.compatible, controlsPass: comparison.controlsPass ?? null,
    model, app, flipCause, repairCreditedToApp: comparison.compatible && comparison.controlsPass !== false && repaired.length > 0 && repaired.every(r => r.attribution === 'app'),
    restorationLabel, coreRestorationLabel: comparison.restorationLabel, summary, caveats, rows,
    scope: 'Model identity comes from a model tap the operator routed the application through. A vendor model string or fingerprint is the vendor\'s reading; only a local server\'s weights digest names weights. The build is the build hash when both runs carry one, else the declared label.' };
}
