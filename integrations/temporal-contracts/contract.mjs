import { digest } from '../../src/domain.mjs';
export const REFUND_VARIANTS = Object.freeze(['clean','deny-all','no-op','never-completing','duplicate-effect','shared-effect','false-success','accept-after-revoke','changed-binding-dispatch']);
export const REFUND_TARGET_IDS = Object.freeze(REFUND_VARIANTS.map(variant=>`refund-${variant}`));
export const CONTRACT_SCHEMA = 'scopehaven-refund-contract/1';
export const ADJUDICATION_SCHEMA = 'scopehaven-refund-adjudication/1';
export const ORIGIN = 'owned-refund-loopback-http';
export const VERSION = 'refund-lifecycle/2';
export const HORIZON = Object.freeze({ id: 'refund-bounded-horizon', deadlineMs: 5000 });
export const INSTRUCTIONS = Object.freeze(['retry', 'identical-a', 'identical-b', 'pre-cutoff', 'arrival-before', 'revoked-new', 'active-control', 'mutable']);
export const COMPLETING = Object.freeze(['retry', 'identical-a', 'identical-b', 'pre-cutoff', 'active-control', 'mutable']);
export const REFUSED = Object.freeze(['arrival-before', 'revoked-new']);
export const CHECKS = Object.freeze([
  { id: 'REFUND-IDENTITY', kind: 'identity', instructionIds: [], severity: 'control' },
  { id: 'REFUND-CUTOFF', kind: 'cutoff', instructionIds: ['arrival-before','revoked-new'], severity: 'high' },
  { id: 'REFUND-COVERAGE', kind: 'coverage', instructionIds: [], severity: 'high' },
  ...INSTRUCTIONS.flatMap(id => [
    { id: `${id}-authority`, kind: 'authority', instructionIds: [id], severity: 'control' },
    { id: `${id}-binding`, kind: 'binding', instructionIds: [id], severity: 'high' },
    { id: `${id}-effects`, kind: 'effect-count', instructionIds: [id], expected: COMPLETING.includes(id) ? 1 : 0, severity: 'high' },
    ...(COMPLETING.includes(id) ? [{ id: `${id}-completion`, kind: 'completion', instructionIds: [id], severity: 'control' }]
      : [{ id: `${id}-refusal`, kind: 'refusal', instructionIds: [id], severity: 'high' }]),
  ]),
].map(c => Object.freeze({...c,instructionIds:Object.freeze([...c.instructionIds])})));
export function actorBindings(runId) {return freezeTree({revoked:{principalId:`principal-${runId}-revoked`,tenantId:`tenant-${runId}-revoked`},control:{principalId:`principal-${runId}-control`,tenantId:`tenant-${runId}-control`}});}
export const AUTHORITY_TEMPLATE = Object.freeze(INSTRUCTIONS.map(instructionId=>Object.freeze({instructionId,principalRole:['identical-a','identical-b','active-control','mutable'].includes(instructionId)?'control':'revoked',tenantRole:['identical-a','identical-b','active-control','mutable'].includes(instructionId)?'control':'revoked',operation:'refund',chargeRole:'workflow',amount:100,currency:'cad',destinationDigest:digest('pm_original')})));
export function deriveExpectedAuthorities(template,runId) {const actors=actorBindings(runId);return template.map(a=>({instructionId:a.instructionId,authorityId:`${runId}-${a.instructionId}`,principalId:actors[a.principalRole].principalId,tenantId:actors[a.tenantRole].tenantId,operation:a.operation,chargeId:`ch_${runId.replaceAll('-','_')}`,amount:a.amount,currency:a.currency,destinationDigest:a.destinationDigest}));}
export function expectedAuthorities(runId) {return deriveExpectedAuthorities(AUTHORITY_TEMPLATE,runId);}
export function runContractHash({runId,targetId,buildHash}) {return digest({schema:CONTRACT_SCHEMA,definitionHash:CONTRACT_HASH,runId,targetId,buildHash,horizon:HORIZON,authorities:expectedAuthorities(runId)});}
export const CONTRACT_HASH = digest({ schema: CONTRACT_SCHEMA, id: 'refund-lifecycle', revision: VERSION, policy: 'operator-window-effects-and-cutoff-with-acceptance-ledger-controls', horizon: HORIZON, authorityTemplate:AUTHORITY_TEMPLATE, checks: CHECKS });
export function freezeTree(value) { if (value && typeof value === 'object') { for (const child of Object.values(value)) freezeTree(child); Object.freeze(value); } return value; }
const id = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,160}$/.test(value);
const hash = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
export function createRefundContract({runId, targetId, buildHash, actors}) {
  if (!id(runId) || !id(targetId) || !hash(buildHash) || !actors?.revoked || !actors?.control) throw new Error('refund-contract-identity');
  for(const alias of ['revoked','control'])if(actors[alias].principalId!==actorBindings(runId)[alias].principalId||actors[alias].tenantId!==actorBindings(runId)[alias].tenantId)throw new Error('refund-unexpected-actor-binding');
  const authorities = INSTRUCTIONS.map(instructionId => {
    const actor = ['identical-a','identical-b','active-control','mutable'].includes(instructionId) ? actorBindings(runId).control : actorBindings(runId).revoked;
    return { instructionId, authorityId: `${runId}-${instructionId}`, principalId: actor.principalId, tenantId: actor.tenantId,
      operation:'refund', chargeId:`ch_${runId.replaceAll('-','_')}`, amount:100, currency:'cad', destination:'pm_original' };
  });
  return freezeTree({schema:CONTRACT_SCHEMA,id:'refund-lifecycle',revision:VERSION,runId,targetId,buildHash,horizon:{...HORIZON},authorities,requiredChecks:CHECKS.map(c=>({...c,instructionIds:[...c.instructionIds]}))});
}
export function validateContract(contract) {
  if (contract?.schema !== CONTRACT_SCHEMA || contract.id !== 'refund-lifecycle' || contract.revision !== VERSION || !id(contract.runId) || !id(contract.targetId) || !hash(contract.buildHash)
    || digest(contract.horizon) !== digest(HORIZON) || digest(contract.requiredChecks) !== digest(CHECKS) || !Array.isArray(contract.authorities) || contract.authorities.length !== INSTRUCTIONS.length) throw new Error('refund-contract-invalid');
  const seen = new Set(), authorityIds = new Set();
  for (const a of contract.authorities) {
    if (!INSTRUCTIONS.includes(a.instructionId) || seen.has(a.instructionId) || !id(a.authorityId) || authorityIds.has(a.authorityId)
      || ![a.principalId,a.tenantId,a.chargeId,a.destination].every(id) || a.operation !== 'refund' || !Number.isSafeInteger(a.amount) || a.amount < 1 || !/^[a-z]{3}$/.test(a.currency)) throw new Error('refund-contract-authority');
    const desired=expectedAuthorities(contract.runId).find(v=>v.instructionId===a.instructionId);
    const canonicalAuthority={instructionId:a.instructionId,principalId:a.principalId,tenantId:a.tenantId,operation:a.operation,chargeId:a.chargeId,amount:a.amount,currency:a.currency,destinationDigest:digest(a.destination),authorityId:a.authorityId};
    if(digest(canonicalAuthority)!==digest(desired))throw new Error('refund-contract-authority-content');
    seen.add(a.instructionId); authorityIds.add(a.authorityId);
  }
  return contract;
}
export function refundSuite({targetId,buildHash,evaluatorHash}) {
  return freezeTree({id:'refund-lifecycle',targetId,version:VERSION,hash:CONTRACT_HASH,buildHash,evaluatorHash,evidenceOrigin:ORIGIN,authorityTemplate:AUTHORITY_TEMPLATE.map(a=>({...a})),horizon:{...HORIZON},
    requiredControlIds:CHECKS.filter(c=>c.severity==='control').map(c=>c.id),checks:CHECKS.map(c=>({...c,instructionIds:[...c.instructionIds]})),sourceReady:true});
}
