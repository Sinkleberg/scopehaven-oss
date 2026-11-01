import { REFUND_VARIANTS } from './contract.mjs';
export const REFUND_TARGETS = Object.freeze(REFUND_VARIANTS.map(variant=>({id:`refund-${variant}`,variant,name:`Refund lifecycle · ${variant}`,kind:'owned-refund-contract',evidenceOrigin:'owned-refund-loopback-http',description:'Owned synthetic HTTP refund acceptance, immutable continuation, effects and completion; no real provider/model.'})));
export const refundTarget = id => REFUND_TARGETS.find(t=>t.id===id);
