import test from 'node:test';
import assert from 'node:assert/strict';
import { createRefundContract, validateContract, CHECKS, CONTRACT_HASH, actorBindings, refundSuite, runContractHash } from './contract.mjs';
const config={runId:'test-run',targetId:'refund-clean',buildHash:'a'.repeat(64),actors:actorBindings('test-run')};
test('trusted authority content cannot change beneath reusable suite identity',()=>{
  const contract=createRefundContract(config);validateContract(contract);
  for(const mutation of [{principalId:'wrong'},{tenantId:'wrong'},{chargeId:'ch_other'},{amount:101},{currency:'usd'},{destination:'pm_other'},{authorityId:'unapproved'}]){
    const changed=structuredClone(contract);Object.assign(changed.authorities[0],mutation);assert.throws(()=>validateContract(changed),/authority/);
  }
  assert.throws(()=>createRefundContract({...config,actors:{...actorBindings('test-run'),revoked:{principalId:'wrong',tenantId:'tenant-revoked'}}}),/unexpected-actor/);
});
test('exported check definitions cannot mutate future contract meaning or hash',()=>{
  const suite=refundSuite({...config,evaluatorHash:'b'.repeat(64)}),hash=CONTRACT_HASH;
  assert.throws(()=>{suite.checks.find(c=>c.id==='identical-b-effects').instructionIds[0]='identical-a';},TypeError);
  assert.throws(()=>{CHECKS.find(c=>c.id==='identical-b-effects').instructionIds[0]='identical-a';},TypeError);
  assert.throws(()=>suite.checks.pop(),TypeError);
  assert.equal(CONTRACT_HASH,hash);assert.equal(createRefundContract(config).requiredChecks.find(c=>c.id==='identical-b-effects').instructionIds[0],'identical-b');
});
test('run-specific full contract identity differs for new independent authority IDs',()=>{
  assert.notEqual(runContractHash(config),runContractHash({...config,runId:'fresh-run'}));
  assert.notEqual(runContractHash(config),runContractHash({...config,buildHash:'c'.repeat(64)}));
});
