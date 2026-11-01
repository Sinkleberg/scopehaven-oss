// Runs every forgery mode against the custody rules and reports one row each.
// Owned synthetic data on this machine; nothing here is saved as evidence.
import { FORGERY_MODES, runForgingSubject, naiveVerdict } from './forging-subject.mjs';
import { subjectIntegrityVerdict, CUSTODY_BY_SOURCE } from './custody.mjs';

// Windows in the real shape observers produce: scope carries evidence and
// actorAttribution, and coverage is its own field (integrations/observers/*).
//
// The subject's own audit table: a profile may declare it authoritative, and by
// custody it is still subject-writable.
export const SUBJECT_LOG_WINDOW = Object.freeze({ source: 'sql-audit-table', instanceId: 'sqlite-audit-1', coverage: 'complete',
  scope: Object.freeze({ operations: ['update', 'tool-call'], names: ['refunds.approved', 'refund-approve'], actorAttribution: 'principal', evidence: 'authoritative' }), events: [] });
// The operator's gate in the request path: the one shipped source outside the
// subject. This mirrors the REAL gate observer (integrations/sequences/gate.mjs
// :92): it sees tool-calls only, its name vocabulary is its rule ids plus
// 'ungated', and it never attributes a principal. So an independent window can
// decide the absence of a GATED TOOL CALL, and nothing else, today.
export const GATE_RULE = 'refund-approve';
export const INDEPENDENT_WINDOW = Object.freeze({ source: 'hold-proxy', instanceId: 'hold-gate-1', coverage: 'complete',
  scope: Object.freeze({ operations: ['tool-call'], names: [GATE_RULE, 'ungated'], actorAttribution: 'none', evidence: 'authoritative' }), events: [] });
// A gate that named the principal. No shipped gate does; kept to show what
// clearing principal-unverified would require.
export const INDEPENDENT_PRINCIPAL_WINDOW = Object.freeze({ ...INDEPENDENT_WINDOW, instanceId: 'hold-gate-principal',
  scope: Object.freeze({ ...INDEPENDENT_WINDOW.scope, actorAttribution: 'principal' }) });
// The effect an independent window can actually decide: a gated tool call.
export const SELECT = Object.freeze({ operation: 'tool-call', name: GATE_RULE });
// The database-shaped effect the subject's own audit log reports. A gate window
// cannot see this one.
export const DB_SELECT = Object.freeze({ operation: 'update', name: 'refunds.approved' });

export function runEvidSubjectCases({ support = [SUBJECT_LOG_WINDOW], select = SELECT } = {}) {
  return FORGERY_MODES.map(mode => {
    const run = runForgingSubject(mode);
    const naive = naiveVerdict(run);
    const decided = subjectIntegrityVerdict({
      proposed: naive,
      support,
      select,
      chain: run.missing ? null : { entries: run.entries, anchor: run.anchor },
      missing: run.missing,
    });
    return Object.freeze({ mode, naive, verdict: decided.verdict, reasons: decided.reasons,
      custody: support.map(w => CUSTODY_BY_SOURCE[w.source] ?? 'subject-writable') });
  });
}

// The acceptance summary: no tampering mode may end in a pass.
export function evidSubjectSummary(rows) {
  return Object.freeze({
    passes: rows.filter(r => r.verdict === 'pass').map(r => r.mode),
    tamperedPasses: rows.filter(r => r.verdict === 'pass' && !['honest', 'missing-observation'].includes(r.mode)).map(r => r.mode),
    naivePasses: rows.filter(r => r.naive === 'pass').map(r => r.mode),
  });
}
