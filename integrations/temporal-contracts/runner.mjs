import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { assertRuntime } from '../../src/runtime.mjs';
import { observeHttp } from '../../src/http-connector.mjs';
import { createPaymentsDouble } from '../observers/payments-double.mjs';
import { freePorts } from '../observers/fixtures/free-port.mjs';
import { startRefundFixture, refundBuildHash } from './fixtures/refund-app.mjs';
import { createTemporalCollector } from './evidence.mjs';
import { createRefundContract, refundSuite, actorBindings, REFUND_VARIANTS } from './contract.mjs';
import { finalizeRefundRun } from './evaluator.mjs';
import { refundIdentity } from './identity.mjs';
let loadedIdentity;
async function checkedIdentity() {
  const identity = await refundIdentity();
  loadedIdentity ??= identity;
  if(identity.evaluatorHash !== loadedIdentity.evaluatorHash) throw new Error('refund-source-restart-required');
  return identity;
}
import { REFUND_TARGETS, refundTarget } from './targets.mjs';
export { REFUND_TARGETS, refundTarget };
export async function currentRefundSuite(targetId) {
  const target=refundTarget(targetId);if(!target)throw new Error('refund-target-unknown');
  const identity=await checkedIdentity();
  return refundSuite({targetId,buildHash:refundBuildHash(target.variant),evaluatorHash:identity.evaluatorHash});
}
async function paymentDouble(runId) {
  // Retry only a port allocation collision, before any application execution.
  for(let i=0;i<5;i++) {
    const [port]=await freePorts(1);
    const payments=createPaymentsDouble({instanceId:`payments-${runId}`,port,routing:'base-url',destinations:[{host:'api.payments.test'}],routes:[{prefix:'/pay/',host:'api.payments.test'},{prefix:'/w/',host:'witness.scopehaven.invalid'}],
      witness:{actorId:'control',method:'GET',path:'/ping',host:'witness.scopehaven.invalid'},witnessWaitMs:0,quietMs:100,
      provider:{host:'api.payments.test',seed:[{id:`ch_${runId.replaceAll('-','_')}`,amount:10000,currency:'cad',paymentMethod:'pm_original'}]}});
    try {await payments.start();return payments;}catch(error){await payments.stop();if(error.code!=='EADDRINUSE'||i===4)throw error;}
  }
}
export async function runRefundAssessment(targetId,{afterExecute,beforeActiveControl,fixtureFactory=startRefundFixture}={}) {
  assertRuntime();
  const target=refundTarget(targetId);if(!target)throw new Error('refund-target-unknown');
  const runId=randomUUID(),startedAt=new Date().toISOString(),start=performance.now(),identity=await checkedIdentity();
  if(identity.evaluatorHash!==loadedIdentity.evaluatorHash)throw new Error('refund-source-restart-required');
  const payments=await paymentDouble(runId);let fixture;
  try {
    fixture=await fixtureFactory({runId,targetId,payments,variant:target.variant,identityContext:actorBindings(runId)});
    if(fixture.buildHash!==refundBuildHash(target.variant))throw new Error('refund-target-build-changed');
    const contract=createRefundContract({runId,targetId,buildHash:fixture.buildHash,actors:fixture.actors});
    const collector=createTemporalCollector({fixture,payments,contract});await collector.begin();
    for(const authority of contract.authorities)await fixture.authorize(authority);
    const httpEvidence=[];
    for(const alias of ['revoked','control']) {
      const actor=fixture.actors[alias],other=fixture.actors[alias==='revoked'?'control':'revoked'];
      for(const auth of ['own','none','wrong','other']) {
        const response=await observeHttp(fixture.origin,{method:'GET',path:'/identity'}, {credential:auth==='own'?actor.credential:auth==='other'?other.credential:auth==='wrong'?'wrong-synthetic-token':undefined});
        httpEvidence.push({kind:'identity',actor:alias,auth,status:response.status,principalId:response.json?.principalId,tenantId:response.json?.tenantId,expectedPrincipal:actor.principalId,expectedTenant:actor.tenantId});
      }
    }
    const invoke=async(instructionId,alias,extra={})=> {
      const response=await collector.observeOperation({kind:'invoke',instructionId,principalId:fixture.actors[alias].principalId,input:extra},
        ()=>observeHttp(fixture.origin,{method:'POST',path:'/refund',body:{instructionId,...extra}},{credential:fixture.actors[alias].credential}));
      httpEvidence.push({kind:'refund',instructionId,actor:alias,status:response.status,complete:response.complete});return response;
    };
    await invoke('retry','revoked',{key:'retry-key',loseResponse:true});
    await invoke('retry','revoked',{key:'retry-key'});
    await invoke('retry','revoked',{key:'changed-retry-key'});
    await invoke('retry','revoked');
    await invoke('identical-a','control',{key:'separate-a'});
    await invoke('identical-b','control',{key:'separate-b'});
    await invoke('pre-cutoff','revoked',{key:'pre-key',hold:'after-acceptance'});
    await invoke('arrival-before','revoked',{key:'arrival-key',hold:'before-acceptance'});
    await collector.observeOperation({kind:'revoke',principalId:fixture.actors.revoked.principalId},()=>fixture.revoke(fixture.actors.revoked.principalId));
    await collector.observeOperation({kind:'release',instructionId:'pre-cutoff',principalId:fixture.actors.revoked.principalId},()=>fixture.release('pre-cutoff'));
    await collector.observeOperation({kind:'release',instructionId:'arrival-before',principalId:fixture.actors.revoked.principalId},()=>fixture.release('arrival-before'));
    await invoke('pre-cutoff','revoked',{key:'pre-key'});
    await invoke('revoked-new','revoked',{key:'revoked-key'});
    if(beforeActiveControl)await beforeActiveControl({fixture,payments,contract,httpEvidence});
    await invoke('active-control','control',{key:'active-key'});
    await invoke('mutable','control',{key:'mutable-key'});
    for(const changed of [{principalId:fixture.actors.revoked.principalId},{tenantId:'other-tenant'},{chargeId:'ch_other'},{amount:101},{currency:'usd'},{destination:'pm_other'}])await invoke('mutable','control',{key:'mutable-key',...changed});
    // A legitimate credential from a different principal must also fail immutable binding.
    await invoke('mutable','revoked',{key:'mutable-key'});
    if(afterExecute)await afterExecute({fixture,payments,collector,contract,httpEvidence});
    const bundle=await collector.finish();
    const after=await refundIdentity();if(after.evaluatorHash!==identity.evaluatorHash)throw new Error('refund-evaluator-source-changed');
    return finalizeRefundRun(bundle,{contract,evaluatorHash:identity.evaluatorHash,httpEvidence,startedAt,durationMs:performance.now()-start});
  } finally {if(fixture)await fixture.close();await payments.stop();}
}
