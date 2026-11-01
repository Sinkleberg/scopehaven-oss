import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { refundIdentity, IDENTITY_FILES } from './identity.mjs';
test('refund source identity includes and responds to coverage and canonical gate policy mutations',async()=>{
  const original=await refundIdentity();
  for(const path of ['../observers/sink-ledger.mjs','../regression-gate/gate.mjs','persistence.mjs','contract.mjs','binding.mjs','evidence.mjs','targets.mjs','../../src/custody.mjs','../../src/effect-lineage.mjs']){
    assert.ok(IDENTITY_FILES.includes(path),path);
    const changed=await refundIdentity({readSource:async name=>(await readFile(new URL(name,import.meta.url),'utf8'))+(name===path?'\n// synthetic identity mutation':'')});
    assert.notEqual(changed.evaluatorHash,original.evaluatorHash,path);
    assert.equal(changed.httpEvaluatorHash,original.httpEvaluatorHash,'injected source mutation leaves the already loaded HTTP identity fixed');
  }
});
