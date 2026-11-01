// The grant-versus-use report in plain English (Markdown), for the findings memo: the headline sentences, the coverage
// caveat, a per-actor table, then what was used without a grant, what another principal did inside an actor's check, each
// actor's sets, the incomplete records and what the report cannot say. It renders a report from grant-use.mjs and reads
// nothing else.
import { GROUPS } from './grant-use.mjs';

const NOUN = { destination: ['destination', 'destinations'], table: ['table', 'tables'], action: ['action', 'actions'] };
const plural = (n, [one, many]) => `${n} ${n === 1 ? one : many}`;
const list = items => items.length <= 1 ? items.join('') : `${items.slice(0, -1).join(', ')} and ${items.at(-1)}`;
const short = id => String(id).slice(0, 8);
const code = text => `\`${String(text).replace(/`/g, "'")}\``;
const cell = text => String(text).replace(/\|/g, '\\|').replace(/\n/g, ' ');
const capital = text => `${text[0].toUpperCase()}${text.slice(1)}`;
const total = (counts, groups) => groups.reduce((n, g) => n + (counts?.[g] ?? 0), 0);
const was = n => (n === 1 ? 'was' : 'were');
const RECORD = { 'check-window': 'check window', 'gap-window': 'gap between checks', 'barrier-window': 'barrier after a check', 'sequence-window': 'sequence window', 'http-response': 'HTTP response' };
const KIND = { 'host-undeclared': 'a host no destination declares', 'path-undeclared': 'a path its destination does not declare', 'domain-undeclared': 'a mail domain no sink declares',
  'table-undeclared': 'an undeclared table', 'action-undeclared': 'an undeclared action', 'tool-ungated': 'a tool call no gate rule names', 'tool-undeclared': 'an undeclared tool rule', 'operation-denied': 'an operation the stated contract denies this role' };
const REASON = { 'actor-not-in-runs': 'no run sent a request as this actor', 'actor-not-in-run': 'the run sent no request as this actor', 'collector-not-drained': 'a recorder did not drain at the run end',
  'check-unobserved': 'a check ran with no observer window', 'request-unobserved': 'a request ran outside every sequence window', 'missing-snapshot': 'a snapshot was missing',
  'presence-only': 'only presence-only telemetry could see it', 'no-observer-window': 'no observer window could see it', 'no-check-requests-it': 'no check of the suite requests it as this actor',
  'request-unanswered': 'its request got no complete response' };
const POSSIBLY = 'a record that names no path or no known principal, a declared background source, or a window several actors could have caused';
const BASIS = { 'application-records-only': "the application's own records", 'net-change-only': 'net change only', 'no-settle-declared': 'end marks taken with no declared settle' };
const where = u => `run ${short(u.run)}, ${u.checkId ? `${u.checkId} ${RECORD[u.record] ?? u.record}` : `${RECORD[u.record] ?? u.record} ${u.window}`}`;
const source = u => u.record === 'http-response' ? `HTTP ${u.httpStatus}, custody ${u.custody}` : `${u.source}, custody ${u.custody}`;
const reasonOf = key => REASON[key] ?? key;

// "6 destinations, 3 tables and 13 actions" over the given groups.
const counted = (counts, groups) => list(groups.map(g => plural(counts?.[g] ?? 0, NOUN[g])));
const numbers = (counts, groups) => list(groups.map(g => String(counts?.[g] ?? 0)));
const nonzero = (counts, groups) => groups.filter(g => (counts?.[g] ?? 0) > 0);

function headline(report) {
  const h = report.headline, present = GROUPS.filter(g => h.granted[g] > 0);
  if (!present.length) return `The declarations grant nothing ScopeHaven observes.${h.usedNotGranted ? ` ${plural(h.usedNotGranted, ['use was', 'uses were'])} not granted (below).` : ''}`;
  const runs = plural(h.runs, ['run', 'runs']);
  const out = [h.status === 'complete'
    ? `Granted ${counted(h.granted, present)}; used ${numbers(h.used, present)} across ${runs}; ${counted(h.excess, present)} ${was(total(h.excess, present))} never exercised.`
    : `Granted ${counted(h.granted, present)}; used ${numbers(h.used, present)} across ${runs}; ${counted(h.notSeen, present)} ${was(total(h.notSeen, present))} not seen in the records, but the records are incomplete (below), so this is not a least-privilege statement.`];
  if (h.status === 'complete' && total(h.qualified, present)) out.push(`${capital(counted(h.qualified, nonzero(h.qualified, present)))} more ${was(total(h.qualified, present))} not seen, but only in records that cannot show a grant went unused (the application's own, or a snapshot's net change, or end marks taken with no declared settle).`);
  if (total(h.possiblyUsed, present)) out.push(`${capital(counted(h.possiblyUsed, nonzero(h.possiblyUsed, present)))} ${was(total(h.possiblyUsed, present))} possibly used: ${POSSIBLY}.`);
  if (total(h.refused, present)) out.push(`${capital(counted(h.refused, nonzero(h.refused, present)))} ${was(total(h.refused, present))} requested and refused: the allowed use did not work, which is not excess.`);
  if (total(h.unobservable, present)) out.push(`${capital(counted(h.unobservable, nonzero(h.unobservable, present)))} could not be observed, so ${total(h.unobservable, present) === 1 ? 'it is' : 'they are'} neither used nor excess.`);
  return out.join(' ');
}

const reasonText = r => {
  const detail = r.reason ? reasonOf(r.reason) : null;
  const what = r.coverage ? `the ${r.observer} window read ${r.coverage}${detail ? ` (${detail})` : ''}${r.unfollowed ? ', and nothing later followed its late entries' : ''}` : `${detail}${r.observer ? ` (${r.observer})` : ''}`;
  return `${what}${r.at ? ` at ${r.at}` : ''}${r.run ? ` in run ${short(r.run)}` : ''}`;
};
const groupOf = (report, key) => report.grant.entries.find(e => e.key === key)?.group;
const usedOf = (report, a, g) => `${a.used.filter(u => groupOf(report, u.key) === g).length} of ${a.granted.filter(k => groupOf(report, k) === g).length}`;
const excessText = (report, a, present) => a.excess.status !== 'complete' ? 'inconclusive'
  : a.excess.entries.length ? list(present.map(g => plural(a.excess.entries.filter(k => groupOf(report, k) === g).length, NOUN[g]))) : 'none';
const ownRecordsText = a => a.excess.status !== 'complete' ? 'not judged' : String(a.excess.qualified.length);
const qualifiedText = q => `${code(q.key)} (${list(q.basis.map(b => BASIS[b] ?? b))})`;

export function renderGrantUseMarkdown(report) {
  const present = GROUPS.filter(g => report.headline.granted[g] > 0);
  const subject = report.kind === 'http' ? `target ${code(report.targetId)}` : `sequence ${code(report.sequenceId)}`;
  const out = [`# Grant versus use: ${subject}`, '', headline(report), '', `${report.caveat} ${report.scope}`, ''];
  if (report.grant.entries.some(e => e.channel === 'table')) out.push('Tables are read from snapshots of net change: a write undone inside one window is not seen, so a table is never listed as never exercised.', '');
  const columns = ['Actor', 'Role, tenant', ...present.map(g => `${capital(NOUN[g][1])} used`), 'Possibly used', 'Excess', 'Not seen, own records only'];
  out.push(`| ${columns.join(' | ')} |`, `|${columns.map(() => '---|').join('')}`);
  for (const a of report.actors) out.push(`| ${[cell(a.alias), cell([a.role, a.tenantId].filter(x => x !== undefined && x !== null).join(', ') || 'none'), ...present.map(g => usedOf(report, a, g)), a.possiblyUsed.length, cell(excessText(report, a, present)), ownRecordsText(a)].join(' | ')} |`);
  out.push('');
  const notGranted = report.application.usedNotGranted;
  if (notGranted.length) {
    out.push('## Used but not granted', '');
    for (const n of notGranted) {
      const by = [...new Set(report.actors.filter(a => a.usedNotGranted.some(x => x.key === n.key && !x.shared)).map(a => a.alias))];
      const linked = n.findings.length ? `Already a finding: ${list(n.findings.map(f => `${f.id} in run ${short(f.run)}`))}.` : 'No failing row holds this use, so this report is where it shows.';
      out.push(`- ${code(n.key)} (${KIND[n.kind] ?? n.kind}): ${plural(n.uses.length, ['use', 'uses'])}, first in ${where(n.uses[0])} (${source(n.uses[0])})${by.length ? `, by ${list(by)}` : ', in a window several actors could have caused'}. ${linked}`);
    }
    out.push('');
  }
  const delegated = report.actors.flatMap(a => (a.delegated ?? []).map(d => ({ ...d, by: a.alias })));
  if (delegated.length || report.undeclaredPrincipals.length) {
    out.push('## Recorded under another principal', '');
    for (const d of delegated) out.push(`- During ${d.by}'s ${d.use.checkId ?? d.use.window} (run ${short(d.use.run)}), ${d.use.source} recorded ${list(d.keys.map(code))} under ${code(d.principalId)}${d.actor ? ` (actor ${d.actor})` : ', a principal no actor declares'} (custody ${d.use.custody}).`);
    for (const p of report.undeclaredPrincipals) if (!delegated.some(d => d.principalId === p.principalId)) out.push(`- ${code(p.principalId)}, a principal no actor declares, used ${list(p.uses.map(u => code(u.key)))}.`);
    out.push('');
  }
  out.push('## Per actor', '');
  for (const a of report.actors) {
    out.push(`### ${a.alias}`, '');
    out.push(a.used.length ? `- Used: ${a.used.map(u => `${code(u.key)} (${plural(u.runs, ['run', 'runs'])}; ${source(u.uses[0])})`).join('; ')}.` : '- Used: nothing granted.');
    if (a.possiblyUsed.length) {
      const others = [...new Set(a.possiblyUsed.flatMap(p => p.uses.flatMap(u => u.windowActors ?? [])))].filter(x => x !== a.alias);
      out.push(`- Possibly used (${POSSIBLY}${others.length ? `; shared with ${list(others)}` : ''}): ${a.possiblyUsed.map(p => code(p.key)).join(', ')}.`);
    }
    if (a.refused.length) out.push(`- Requested and refused (the allowed use did not work, which is not excess): ${a.refused.map(r => `${code(r.key)} (HTTP ${r.uses[0].httpStatus ?? 'none'} in ${r.uses[0].checkId})`).join(', ')}.`);
    if (a.excess.status === 'complete') {
      out.push(a.excess.entries.length ? `- Never exercised in these runs: ${a.excess.entries.map(code).join(', ')}.` : '- Never exercised in these runs: nothing a record held outside the application could show.');
      if (a.excess.qualified.length) out.push(`- Not seen, but only in records that cannot show a grant went unused: ${a.excess.qualified.map(qualifiedText).join(', ')}.`);
    } else out.push(`- Excess: inconclusive. Not seen in the records: ${a.excess.notSeen.length ? a.excess.notSeen.map(code).join(', ') : 'nothing'}; the records could have missed a use (${list(a.excess.reasons.map(reasonText))}).`);
    if (a.unobservable.length) out.push(`- Not observable: ${a.unobservable.map(u => `${code(u.key)} (${reasonOf(u.reason)})`).join(', ')}.`);
    if (a.usedNotGranted.length) out.push(`- Used but not granted: ${a.usedNotGranted.map(n => `${code(n.key)}${n.shared ? ' (possibly: a shared window)' : ''}`).join(', ')}.`);
    out.push('');
  }
  const reasons = report.application.excess.status === 'inconclusive' ? report.application.excess.reasons : [];
  if (reasons.length) out.push('## Incomplete records', '', ...reasons.map(r => `- ${capital(reasonText(r))}.`), '');
  out.push('## What this report cannot say', '',
    '- Nothing about grants ScopeHaven does not see: database roles and row-level policies, cloud IAM, provider API key scopes, OAuth scopes, or tools the declared observers do not cover.',
    '- An unused grant is excess for these runs only; a path the runs never exercised (a rare workflow, a month-end job) may still need it.',
    '- Operations are never excess: the actor\'s requests are the suite\'s, so an operation reads used, refused, or not requested.',
    '- A use is credited to an actor by the record\'s own principal, or by the actor\'s own check window. A background job inside that window that no declared background source names, and an earlier check\'s effect that commits after its settle, are credited to that actor too. Anything else is possibly used, never excess.',
    '- The application can write, omit or revert its own tables and audit records (custody subject-writable), so what only they show unused is listed apart, never as never exercised. Telemetry (traces, MCP logs) and the application\'s own action log are not read as uses.',
    '- An effect that commits after the last end mark (an HTTP run\'s final settle and drain, a sequence\'s last mark) is in no record. A sequence whose observers declare no settle takes its end marks right after the last request, so its excess is listed apart too.',
    `- ${report.note}`, '');
  return out.join('\n');
}
