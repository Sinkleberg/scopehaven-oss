import { readFile } from 'node:fs/promises';
import { digest } from '../../src/domain.mjs';
import { HTTP_EVALUATOR_HASH } from '../../src/http-connector.mjs';
// Identity covers the full executable policy/evidence/writer closure. It is a new
// evaluator family: historical HTTP evidence is never relabeled as refund evidence.
export const IDENTITY_FILES = Object.freeze(['contract.mjs','targets.mjs','evaluator.mjs','runner.mjs','identity.mjs','persistence.mjs','evidence.mjs','binding.mjs','fixtures/refund-app.mjs','../observers/payments-double.mjs','../observers/sink-ledger.mjs','../regression-gate/gate.mjs','../../src/registry.mjs','../../src/store.mjs','../../src/http.mjs','../../src/runtime.mjs','../../src/custody.mjs','../../src/effect-lineage.mjs']);
export async function refundIdentity({readSource=path=>readFile(new URL(path,import.meta.url),'utf8')}={}) {
  const sources=await Promise.all(IDENTITY_FILES.map(async path=>[path,digest(await readSource(path))]));
  return {evaluatorHash:digest({schema:'scopehaven-refund-evaluator-identity/1',httpEvaluatorHash:HTTP_EVALUATOR_HASH,sources:Object.fromEntries(sources)}),sources:Object.fromEntries(sources),httpEvaluatorHash:HTTP_EVALUATOR_HASH};
}
