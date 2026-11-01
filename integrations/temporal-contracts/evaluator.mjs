import { clauseCustody, CONTROL_CUSTODY_LIMIT } from '../../src/custody.mjs';
import { digest } from '../../src/domain.mjs';
import { CHECKS, CONTRACT_HASH, ADJUDICATION_SCHEMA, ORIGIN, VERSION, actorBindings, runContractHash, validateContract, freezeTree } from './contract.mjs';
import { inspectTemporalEvidence } from './evidence.mjs';
import { bindingOf, sameBinding } from './binding.mjs';
const finalized = new WeakSet();
export const isFinalizedRun = value => finalized.has(value) && Object.isFrozen(value);
const entries = v => Array.isArray(v) ? v : [];
const iid = v => v?.instructionId ?? v?.binding?.instructionId;
const binding = v => v?.binding ?? v;
export function finalizeRefundRun(bundle, {contract,evaluatorHash,httpEvidence=[],startedAt=new Date().toISOString(),durationMs=0}={}) {
  validateContract(contract);
  if (!/^[a-f0-9]{64}$/.test(evaluatorHash)) throw new Error('refund-evaluator-identity');
  const inspected = inspectTemporalEvidence(bundle,contract), f = inspected.facts;
  if (!inspected.trusted || !f) throw new Error('refund-live-evidence-required');
  const operator = f.operator, operations = entries(operator?.operations);
  const events = entries(f.events), attempts = entries(operator?.attempts ?? f.attempts), effects = entries(operator?.effects ?? f.effects), terminals = entries(f.terminals), revocations = entries(f.revocations);
  const operatorComplete = operator?.coverage === 'complete';
  const witnessSource = bundle.payments?.witnessSource;
  const closureEstablished = witnessSource === 'observer-dispatched' ? inspected.independentClosure === true : ['external', 'none'].includes(witnessSource);
  const timing=f.timing??bundle.application?.timing;
  const timingValid=Boolean(timing&&typeof timing.clockId==='string'&&Number.isFinite(timing.startedAtMs)&&Number.isFinite(timing.closedAtMs)&&timing.closedAtMs>=timing.startedAtMs);
  const sourceHorizon=bundle.application?.horizon;
  const scopeValid=Boolean(timingValid&&sourceHorizon?.deadlineMs===contract.horizon.deadlineMs&&sourceHorizon?.sealed===true&&events.every(e=>Number.isFinite(e.atMs)&&e.atMs>=timing.startedAtMs&&e.atMs<=timing.closedAtMs));
  const complete = Boolean(closureEstablished && operatorComplete && scopeValid && inspected.coverage === 'complete' && !entries(inspected.problems).length && !entries(f.problems).length);
  const accepted = id => events.filter(e=>e.type==='accepted'&&iid(e)===id);
  const expected = id => contract.authorities.find(a=>a.instructionId===id);
  const cutoff = principal => revocations.filter(r=>r.principalId===principal).map(r=>r.seq);
  const validAcceptance = (e,a) => Number.isSafeInteger(e.seq)&& e.seq>0 && e.authorityId===a.authorityId && sameBinding(binding(e),a) && events.some(issued=>issued.type==='authorized'&&iid(issued)===a.instructionId&&issued.seq<e.seq&&sameBinding(issued,a)) && cutoff(a.principalId).every(seq=>Number.isSafeInteger(seq)&&e.seq<seq);
  const desiredActors=actorBindings(contract.runId);
  const effectiveCutoffs=cutoff(desiredActors.revoked.principalId);
  const revokeOperations = operations.filter(w=>w.kind==='revoke'&&w.principalId===desiredActors.revoked.principalId);
  const cutoffObserved = revokeOperations.length===1 && revokeOperations[0].complete;
  const revokeIndex = revokeOperations[0]?.index;
  const perInstruction = (list,id) => list.filter(r=>iid(r)===id);
  const results = CHECKS.map(check=> {
    const id=check.instructionIds[0], a=expected(id), accepts=accepted(id), sends=perInstruction(attempts,id), committed=perInstruction(effects,id), terminal=perInstruction(terminals,id);
    let status='inconclusive', reason='evidence-incomplete';
    if (check.kind==='cutoff') {
      status=complete?(cutoffObserved?'pass':'fail'):'inconclusive';reason=status==='pass'?'effective-revocation-observed':status==='fail'?'expected-revocation-not-observed':'revocation-order-unestablished';
    } else if (check.kind==='coverage') { status=complete?'pass':'inconclusive';reason=complete?'sources-closed':'evidence-incomplete'; }
    else if (check.kind==='identity') {
      const valid = ['revoked','control'].every(alias => {
        const probes=httpEvidence.filter(p=>p.actor===alias&&p.kind==='identity');
        return probes.some(p=>p.auth==='own'&&p.status===200&&p.principalId===desiredActors[alias].principalId&&p.tenantId===desiredActors[alias].tenantId)
          && ['none','wrong','other'].every(auth=>probes.some(p=>p.auth===auth&&([401,403].includes(p.status)||(p.status===200&&p.principalId!==desiredActors[alias].principalId))));
      });
      status=valid?'pass':'inconclusive';reason=valid?'authenticated-http-principals':'http-identity-unestablished';
    } else if (check.kind==='authority') {
      const invalid=accepts.some(e=>bindingOf(e)&&Number.isSafeInteger(e.seq)&&!validAcceptance(e,a))||(complete&&a.principalId===desiredActors.revoked.principalId&&!cutoffObserved);
      status=invalid?'fail':complete?'pass':'inconclusive';reason=invalid?'acceptance-without-current-bound-authority':status==='pass'?'acceptance-authority-valid':'acceptance-order-unestablished';
    } else if (check.kind==='binding') {
      const invalid=sends.some(s=>bindingOf(s)&&(!sameBinding(binding(s),a)||s.headerMatches===false||s.requestMatches===false||(complete&&!accepts.some(e=>validAcceptance(e,a)&&e.seq<s.seq))))
        || committed.some(e=>e.bindingValid===false);
      status=invalid?'fail':complete?'pass':'inconclusive';reason=invalid?'forbidden-or-mutated-dispatch':status==='pass'?'immutable-dispatch-binding':'binding-unestablished';
    } else if (check.kind==='effect-count') {
      const unique=new Set(committed.map(e=>e.effectId ?? e.id));
      status=operatorComplete && unique.size!==check.expected?'fail':complete?'pass':'inconclusive';reason=status==='pass'?'exact-bound-effect-count':status==='fail'?'bound-effect-count-mismatch':'count-needs-complete-authoritative-evidence';
    } else if (check.kind==='completion') {
      const finalTerminal=terminal.at(-1);
      const instruction=f.instructions.find(v=>v.instructionId===id);
      const completion = operations.find(w=>w.instructionId===id&&w.complete&&w.response.complete&&w.response.state==='success'&&committed.some(e=>e.providerEffectId===w.response.effectId&&e.bindingValid&&e.seq<=w.toSeq));
      const valid=Boolean(completion&&finalTerminal?.state==='success'&&instruction?.state==='success'&&committed.some(e=>(e.effectId??e.id)===finalTerminal.effectId&&sameBinding(binding(e),a)));
      const onTime=valid&&completion.endMs<=contract.horizon.deadlineMs;
      status=complete?(onTime?'pass':'fail'):'inconclusive';reason=status==='pass'?'matching-terminal-success':status==='fail'?(valid?'terminal-success-after-deadline':'required-terminal-success-missing'):'completion-evidence-incomplete';
    } else if (check.kind==='refusal') {
      const arrived=events.filter(e=>e.type==='arrived'&&iid(e)===id);
      const orderedArrival=arrived.some(e=>Number.isSafeInteger(e.seq)&&(id==='arrival-before'?e.seq<effectiveCutoffs[0]:e.seq>effectiveCutoffs[0]));
      const requests=operations.filter(w=>w.instructionId===id);
      const arrival=requests.find(w=>w.kind==='invoke');
      const refusal=requests.find(w=>w.complete&&w.response.complete&&w.index>revokeIndex&&([401,403,409].includes(w.response.status)||w.response.state==='refused'));
      const operatorOrder=Boolean(arrival&&refusal&&cutoffObserved&&(id==='arrival-before'?arrival.index<revokeIndex:arrival.index>revokeIndex));
      const valid=operatorOrder&&orderedArrival&&events.some(e=>e.type==='refused'&&iid(e)===id&&e.principalId===a.principalId&&e.seq>effectiveCutoffs[0]&&arrived.some(v=>v.seq<e.seq))&&accepts.length===0&&sends.length===0&&committed.length===0;
      status=(operatorComplete&&(sends.length>0||committed.length>0))?'fail':complete?(valid?'pass':'fail'):'inconclusive';reason=status==='pass'?'post-cutoff-work-refused':status==='fail'?'new-work-not-correctly-refused':'refusal-evidence-incomplete';
    }
    // Operator windows are minted by the collector; app ledgers never receive
    // request-path custody. The control exception is explicit on every row.
    if (!closureEstablished && status === 'pass') { status = 'inconclusive'; reason = 'independent-closure-unestablished'; }
    const source = check.kind==='authority' ? 'http-audit-log' : 'http-egress';
    const supported = check.kind==='authority' ? complete : operatorComplete && (check.kind==='cutoff' ? cutoffObserved : check.instructionIds.length===0 || operations.some(w=>w.instructionId===id));
    const custody = clauseCustody({kind:'effect.count',select:{operation:'send'},verdict:status,role:check.severity==='control'?'control':'boundary',
      windows:supported?[{source,coverage:'complete',scope:{operations:['send'],names:null,actorAttribution:'none',evidence:'authoritative'}}]:[]});
    status=custody.verdict;
    const reasons=[reason,...(custody.custodyReason?[custody.custodyReason]:[])];
    return {...check,status,reasons,custody:custody.custody,...(check.kind==='authority'?{custodyLimit:CONTROL_CUSTODY_LIMIT}:{}),
      expected:check.kind,observed:reason,remediation:{title:'Review refund evidence',why:check.kind==='authority'?CONTROL_CUSTODY_LIMIT:'This row is limited to the declared operator window and synthetic provider.',steps:['Inspect the operator windows and provider effects for this instruction.','Repair the reported condition and collect a fresh run.']},attemptIds:[...new Set(sends.map(s=>s.attemptId).filter(v=>typeof v==='string'))],effectIds:[...new Set(committed.map(e=>e.effectId??e.id).filter(v=>typeof v==='string'))],
      title:check.id,category:'Synthetic refund lifecycle',assertions:[{name:check.kind,status,expected:check.kind,actual:reason,...custody}],evidenceDigest:digest({check,facts:{accepts,sends,committed,terminal},status,reason})};
  });
  const counts=Object.fromEntries(['pass','fail','inconclusive','error','not_applicable'].map(s=>[s,results.filter(r=>r.status===s).length]));
  const createdAt=new Date().toISOString();
  const adjudication={schema:ADJUDICATION_SCHEMA,finalized:true,producer:'scopehaven-trusted-refund-evaluator/1',contractHash:CONTRACT_HASH,runContractHash:runContractHash(contract),
    identity:{runId:contract.runId,targetId:contract.targetId,buildHash:contract.buildHash,evaluatorHash},horizon:{...contract.horizon,sealed:sourceHorizon?.sealed===true,closed:complete,watermark:bundle.horizon?.watermark??bundle.application?.horizon?.watermark??0,pending:bundle.horizon?.pending??bundle.application?.horizon?.pending??0},
    requiredCheckIds:CHECKS.map(c=>c.id),results:results.map(({id,kind,status,reasons,instructionIds,attemptIds,effectIds})=>({id,kind,status,reasons,instructionIds,attemptIds,effectIds})),
    evidenceSummary:{timing:operator?{clockId:operator.clockId,startedAtMs:operator.startedAtMs,closedAtMs:operator.closedAtMs}:null,applicationTiming:timing??null,operatorWindows:operations,operatorProblems:entries(operator?.problems),coverage:complete?'complete':'incomplete',problems:[...entries(inspected.problems),...entries(f.problems)],instructions:contract.authorities.map(bindingOf),attempts:attempts.length,effects:effects.length,decisions:events.filter(e=>['accepted','refused','revoked','terminal'].includes(e.type)),attemptLineage:attempts,effectLineage:effects,modelExercised:false},createdAt};
  const run={schemaVersion:1,id:contract.runId,targetId:contract.targetId,applicationId:'owned-refund-fixture',suiteId:'refund-lifecycle',suiteVersion:VERSION,
    suiteHash:CONTRACT_HASH,policyHash:CONTRACT_HASH,fixtureHash:contract.buildHash,evaluatorHash,profileHash:CONTRACT_HASH,targetConfigHash:digest({targetId:contract.targetId,buildHash:contract.buildHash}),
    targetBuildHash:contract.buildHash,fixtureVersion:'refund-app/1',adapterVersion:'refund-http/1',runtimeMode:'owned-refund-loopback',assertionSchemaVersion:VERSION,
    scopeLabel:'Owned synthetic refund workflow. Operator windows decide effects, revoke ordering and completion time. Acceptance timing is an application ledger control only. No real provider or model was assessed.',contextId:'owned-synthetic-refund',build:contract.buildHash,evidenceOrigin:ORIGIN,createdAt,startedAt,completedAt:createdAt,durationMs,checksTotal:results.length,
    requiredControlIds:CHECKS.filter(c=>c.severity==='control').map(c=>c.id),counts,results,refundAdjudication:adjudication,
    limitations:['Owned synthetic loopback workflow; no real payment settlement or customer evidence.',CONTROL_CUSTODY_LIMIT,'Acceptance timing is an application ledger control, not independently established authority.','Closed bounded horizon only; effects after it are outside this claim.','Evaluator signing trust is not same-user OS isolation; malicious host or stolen key is outside the claim.','Application inconsistencies may make unrelated rows inconclusive; independently observed mismatched counts, binding and refused sends still fail.','No model was exercised.']};
  freezeTree(run);finalized.add(run);return run;
}
