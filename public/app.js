const $ = (id) => document.getElementById(id);
const statuses = ['pass', 'fail', 'inconclusive', 'error', 'not_applicable'];
const statusLabels = { pass: 'Passed', fail: 'Failed', inconclusive: 'Inconclusive', error: 'Errors', not_applicable: 'N/A' };
const state = { bootstrap: null, run: null, selectedCase: null, loadingRun: false, running: false, detailRequest: 0, compareRequest: 0 };
let workbenchKey = null; // Memory only; never cookies, localStorage or sessionStorage.
const launchFragment = new URLSearchParams(window.location.hash.slice(1));
if (launchFragment.has('access')) {
  const candidate = launchFragment.get('access');
  if (/^[A-Za-z0-9_-]{32,128}$/.test(candidate || '')) workbenchKey = candidate;
  window.history.replaceState(null, '', window.location.pathname + window.location.search);
}
function accessRequired() {
  workbenchKey = null;
  state.bootstrap = null; state.run = null; state.selectedCase = null;
  $('history-list').replaceChildren(el('p', 'empty-copy', 'Unlock the workbench to view saved evidence.'));
  $('history-count').textContent = '—'; $('history-more').hidden = true;
  for (const id of ['run-metadata', 'counts', 'results-toolbar', 'run-exports', 'run-limitations', 'run-outcome', 'finding-detail']) $(id).hidden = true;
  $('results-heading').textContent = 'Workbench locked';
  $('findings-list').replaceChildren(); $('comparison-result').replaceChildren();
  for (const id of ['baseline', 'candidate', 'target']) { $(id).replaceChildren(); $(id).disabled = true; }
  $('run-button').disabled = true; $('compare-button').disabled = true; $('lock-button').hidden = true;
  $('access-panel').hidden = false;
  $('target-description').textContent = 'Unlock the workbench to choose an application.';
  $('access-status').textContent = 'This local workbench is locked. Open its private launch page or enter the local workbench key.';
}

function el(tag, className, content) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (content !== undefined) node.textContent = String(content);
  return node;
}
function showMessage(message, error = false) {
  const box = $('global-message');
  box.textContent = message;
  box.className = error ? 'message error' : 'message';
  box.hidden = !message;
}
async function api(path, body) {
  const options = { headers: { Accept: 'application/json' }, cache: 'no-store' };
  if (workbenchKey) options.headers.Authorization = `Bearer ${workbenchKey}`;
  if (body !== undefined) {
    options.method = 'POST';
    options.headers['Content-Type'] = 'application/json';
    options.headers['X-Scopehaven-Request'] = '1';
    options.body = JSON.stringify(body);
  }
  const response = await fetch(path, options);
  let data;
  try { data = await response.json(); } catch { throw new Error('The local server returned an unreadable response.'); }
  if (response.status === 401) accessRequired();
  if (!response.ok) throw Object.assign(new Error(data.error || `Request failed (${response.status}).`), { status: response.status });
  return data;
}
function date(value, full = false) {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? String(value || 'Unknown time') : parsed.toLocaleString(undefined, full ? { dateStyle: 'medium', timeStyle: 'medium' } : { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
}
function printable(value) {
  if (typeof value === 'string') return value;
  if (value === undefined) return 'Not provided';
  return JSON.stringify(value, null, 2);
}
function badge(status) {
  const known = statuses.includes(status);
  const node = el('span', `badge ${known ? status : 'error'}`);
  node.append(el('span', 'status-dot'), document.createTextNode(known ? (status === 'not_applicable' ? 'Not applicable' : status) : String(status || 'Unknown')));
  return node;
}
function setRunBusy(busy) {
  state.running = busy;
  $('run-button').disabled = busy || !state.bootstrap;
  $('target').disabled = busy || !state.bootstrap;
  $('run-button').textContent = busy ? 'Running checks…' : '▷ Run assessment';
  $('run-form').setAttribute('aria-busy', String(busy));
}
function updateTargetDescription() {
  const target = state.bootstrap?.targets.find((item) => item.id === $('target').value);
  $('target-description').textContent = target ? `${target.description} · Build ${target.build}` : 'Choose an application build.';
  for (const anchor of document.querySelectorAll('[data-suite-export]')) anchor.href = `/api/suite/export.json?${new URLSearchParams({ targetId: target?.id || '' })}`;
}
function renderHistory() {
  const runs = state.bootstrap.runs;
  $('history-count').textContent = String(state.bootstrap.history?.total ?? runs.length);
  $('history-more').hidden = !state.bootstrap.history?.nextCursor;
  $('history-list').replaceChildren();
  if (!runs.length) $('history-list').append(el('p', 'empty-copy', 'No saved runs yet. Start an assessment above to collect evidence.'));
  for (const run of runs) {
    const button = el('button', `history-item${state.run?.id === run.id ? ' selected' : ''}`);
    button.type = 'button';
    button.setAttribute('aria-pressed', String(state.run?.id === run.id));
    const title = el('span', 'history-title', run.targetName);
    button.append(title, el('span', 'history-date', date(run.createdAt)));
    const stats = el('span', 'history-stats');
    for (const status of statuses) stats.append(el('span', status, `${run.counts?.[status] ?? (status === 'not_applicable' ? 0 : '—')} ${status}`));
    button.append(stats, el('span', 'history-id', `${run.build} · ${run.id.slice(0, 8)}`));
    button.addEventListener('click', () => loadRun(run.id));
    $('history-list').append(button);
  }
  renderCompareSelectors();
}
function renderCompareSelectors() {
  const runs = state.bootstrap.runs;
  for (const id of ['baseline', 'candidate']) {
    const select = $(id);
    const previous = select.value;
    select.replaceChildren();
    if (!runs.length) select.append(el('option', '', 'No saved runs'));
    for (const run of runs) {
      const option = el('option', '', `${run.targetName} · ${date(run.createdAt)} · ${run.id.slice(0, 8)}`);
      option.value = run.id;
      select.append(option);
    }
    if (id === 'candidate' && previous === $('baseline').value && runs.some((run) => run.targetId === 'demo-repaired')) select.value = runs.find((run) => run.targetId === 'demo-repaired').id;
    else if (runs.some((run) => run.id === previous)) select.value = previous;
    else if (id === 'baseline') select.value = (runs.find((run) => run.targetId === 'demo-vulnerable') || runs[runs.length - 1])?.id || '';
    else select.value = (runs.find((run) => run.targetId === 'demo-repaired') || runs[0])?.id || '';
    select.disabled = runs.length < 2;
  }
  $('compare-button').disabled = runs.length < 2;
  if (runs.length >= 2 && !$('comparison-result').dataset.loaded) $('comparison-result').replaceChildren(el('p', 'empty-copy', 'Choose two runs and compare their observed outcomes.'));
}
async function bootstrap() {
  $('refresh-button').disabled = true;
  try {
    const data = await api('/api/bootstrap');
    state.bootstrap = data;
    $('access-panel').hidden = true;
    $('lock-button').hidden = false;
    $('product-version').textContent = `${data.product.name} ${data.product.version}`;
    $('workspace-mode').textContent = data.product.mode;
    const previous = $('target').value;
    $('target').replaceChildren();
    for (const target of data.targets) {
      const option = el('option', '', target.name);
      option.value = target.id;
      option.disabled = target.available === false;
      $('target').append(option);
    }
    if (data.targets.some((target) => target.id === previous)) $('target').value = previous;
    setRunBusy(state.running);
    updateTargetDescription();
    renderHistory();
    return true;
  } catch (error) {
    if (error.status === 401) { showMessage(''); return false; }
    showMessage(`Could not load the workspace. ${error.message} Use refresh to try again.`, true);
    if (!state.bootstrap) {
      $('history-list').replaceChildren(el('p', 'empty-copy', 'Run history could not be loaded.'));
      $('target-description').textContent = 'Local server unavailable. Refresh the workspace to retry.';
    }
    return false;
  } finally { $('refresh-button').disabled = false; }
}
async function loadRun(id) {
  const request = ++state.detailRequest;
  state.loadingRun = true;
  $('results-heading').textContent = 'Loading run evidence…';
  $('findings-list').setAttribute('aria-busy', 'true');
  try {
    const run = await api(`/api/runs/${encodeURIComponent(id)}`);
    if (request !== state.detailRequest) return;
    state.run = run;
    state.selectedCase = null;
    $('status-filter').value = 'all';
    renderRun();
    renderHistory();
    showMessage('');
  } catch (error) {
    if (request !== state.detailRequest) return;
    if (state.run) renderRun();
    else $('results-heading').textContent = 'Run evidence unavailable';
    showMessage(`Could not open this run. ${error.message}`, true);
  } finally {
    if (request === state.detailRequest) { state.loadingRun = false; $('findings-list').setAttribute('aria-busy', 'false'); }
  }
}
function renderRun() {
  const run = state.run;
  $('run-label').textContent = `RUN ${run.id.slice(0, 8)} · ${date(run.createdAt)}`;
  $('results-heading').textContent = run.targetName;
  for (const id of ['run-metadata', 'counts', 'results-toolbar', 'run-exports', 'run-limitations']) $(id).hidden = false;
  $('json-export').href = `/api/runs/${encodeURIComponent(run.id)}/export.json`;
  $('report-export').href = `/api/runs/${encodeURIComponent(run.id)}/report.html`;
  const metadata = $('run-metadata');
  metadata.replaceChildren();
  for (const [label, value] of [['Build', run.build], ['Suite', run.suiteId], ['Fixture', run.fixtureVersion], ['Duration', `${run.durationMs} ms`], ['Checks', run.checksTotal]]) {
    const item = el('span'); item.append(document.createTextNode(`${label} `), el('strong', '', value)); metadata.append(item);
  }
  $('counts').replaceChildren();
  for (const status of statuses) {
    const stat = el('div', `stat status-${status}`);
    const label = el('span', 'stat-label'); label.append(el('span', `status-dot status-${status}`), document.createTextNode(statusLabels[status]));
    stat.append(el('span', 'stat-value', run.counts?.[status] ?? (status === 'not_applicable' ? 0 : '—')), label);
    $('counts').append(stat);
  }
  const outcome = $('run-outcome');
  const unverified = run.counts.inconclusive + run.counts.error;
  outcome.hidden = false;
  outcome.className = `run-outcome ${run.counts.fail ? 'fail' : unverified ? 'inconclusive' : 'pass'}`;
  outcome.textContent = run.counts.fail ? `${run.counts.fail} of ${run.checksTotal} checks failed.` : unverified ? `${unverified} of ${run.checksTotal} checks could not be verified.` : `${run.counts.pass} of ${run.checksTotal} named checks passed.`;
  if (run.counts.fail && unverified) outcome.textContent += ` ${unverified} other checks remain unverified.`;
  if (run.counts.not_applicable) outcome.textContent += ` ${run.counts.not_applicable} not applicable under the declared scope.`;
  if (run.evidenceOrigin === 'local-http-response') outcome.textContent += ' Response contracts only; backend effects unverified.';
  const limits = el('details');
  limits.append(el('summary', '', 'Assessment scope & limitations'));
  const list = el('ul');
  for (const limitation of run.limitations || []) list.append(el('li', '', limitation));
  limits.append(list);
  const provenance = el('pre');
  const provenanceFields = [['Run ID', run.id], ['Application', run.applicationId], ['Evidence origin', run.evidenceOrigin], ['Suite hash', run.suiteHash], ['Policy hash', run.policyHash], ['Fixture hash', run.fixtureHash], ['Target build hash', run.targetBuildHash], ['Target config hash', run.targetConfigHash], ['Evaluator hash', run.evaluatorHash], ['Run integrity SHA-256', run.integrity?.sha256]];
  provenance.textContent = provenanceFields.filter(([, value]) => value !== undefined).map(([label, value]) => `${label}: ${value}`).join('\n');
  limits.append(provenance);
  $('run-limitations').replaceChildren(limits);
  renderFindings();
}
function renderFindings() {
  if (!state.run) return;
  const filter = $('status-filter').value;
  const results = state.run.results.filter((result) => filter === 'all' || result.status === filter);
  $('visible-count').textContent = `${results.length} of ${state.run.results.length} checks`;
  $('findings-list').replaceChildren();
  if (!results.length) $('findings-list').append(el('p', 'empty-copy', 'No checks match this outcome filter.'));
  for (const result of results) {
    const button = el('button', `finding${state.selectedCase === result.id ? ' selected' : ''}`);
    button.type = 'button'; button.setAttribute('aria-pressed', String(state.selectedCase === result.id));
    button.setAttribute('aria-controls', 'finding-detail');
    const copy = el('span');
    copy.append(el('span', 'finding-title', result.title), el('span', 'finding-subtitle', `${result.category} · ${result.summary}`));
    const tags = el('span', 'finding-tags'); tags.append(el('span', 'severity', result.severity), badge(result.status));
    button.append(copy, tags);
    button.addEventListener('click', () => { state.selectedCase = result.id; renderFindings(); renderDetail(result); });
    $('findings-list').append(button);
  }
  if (!state.selectedCase || !results.some((result) => result.id === state.selectedCase)) {
    state.selectedCase = null;
    $('finding-detail').hidden = true;
  }
}
function detailSection(title) {
  const section = el('section', 'detail-section'); section.append(el('h3', '', title)); return section;
}
function renderDetail(result) {
  const runId = state.run.id;
  const detail = $('finding-detail');
  detail.hidden = false; detail.replaceChildren();
  const header = el('div', 'panel-heading detail-heading');
  const heading = el('div'); heading.append(el('div', 'eyebrow', `${result.category} · ${result.severity} severity`));
  const h2 = el('h2', '', result.title); h2.id = 'detail-heading';
  heading.append(h2, el('p', '', result.summary)); header.append(heading, badge(result.status)); detail.append(header);
  const body = el('div', 'detail-body'); const left = el('div'); const right = el('div');
  const observation = detailSection('Expected policy & observed behavior'); const pair = el('div', 'evidence-pair');
  for (const [label, value] of [['EXPECTED', result.expected], ['OBSERVED', result.observed]]) {
    const box = el('div', 'evidence-box'); box.append(el('span', '', label), el('pre', '', printable(value))); pair.append(box);
  }
  observation.append(pair); left.append(observation);
  const assertions = detailSection('Evidence assertions');
  const wrap = el('div', 'table-wrap'); const table = el('table'); const thead = el('thead'); const headRow = el('tr');
  for (const label of ['Assertion', 'Outcome', 'Expected', 'Actual']) headRow.append(el('th', '', label));
  thead.append(headRow); table.append(thead); const tbody = el('tbody');
  for (const assertion of result.assertions || []) {
    const row = el('tr'); const status = el('td'); status.append(badge(assertion.status));
    const expected = el('td'); expected.append(el('pre', '', printable(assertion.expected)));
    const actual = el('td'); actual.append(el('pre', '', printable(assertion.actual)));
    row.append(el('td', '', assertion.name), status, expected, actual); tbody.append(row);
  }
  table.append(tbody); wrap.append(table); assertions.append(wrap);
  if (!result.assertions?.length) assertions.append(el('p', 'field-help', 'No assertions were provided for this check.'));
  left.append(assertions);
  const trace = detailSection('Execution trace');
  for (const entry of result.trace || []) {
    const item = el('details', 'trace-item'); const summary = el('summary');
    summary.append(el('span', 'trace-type', entry.type), document.createTextNode(entry.label || 'Trace event'));
    item.append(summary, el('pre', '', printable(entry.data))); trace.append(item);
  }
  if (!result.trace?.length) trace.append(el('p', 'field-help', 'No execution trace was provided. Missing evidence does not establish a pass.'));
  left.append(trace);
  const repair = el('section', 'remediation'); const remediation = result.remediation;
  repair.append(el('div', 'eyebrow', 'REMEDIATION GUIDANCE'), el('h3', '', remediation?.title || 'Review this check'));
  if (remediation?.why) repair.append(el('p', '', remediation.why));
  const steps = el('ol'); for (const step of remediation?.steps || []) steps.append(el('li', '', step));
  if (steps.children.length) repair.append(steps);
  if (remediation?.codePointers?.length) {
    repair.append(el('div', 'eyebrow', 'SOURCE POINTERS'));
    for (const pointer of remediation.codePointers) repair.append(el('code', 'code-pointer', pointer));
  }
  right.append(repair);
  const noteForm = el('form', 'note-form'); const noteLabel = el('label', '', 'Investigation note'); noteLabel.htmlFor = 'case-note';
  const textarea = el('textarea'); textarea.id = 'case-note'; textarea.name = 'note'; textarea.maxLength = 5000;
  textarea.placeholder = 'Record context, repair decisions, or next steps…'; textarea.value = state.run.notes?.[result.id]?.note || '';
  const actions = el('div', 'note-actions'); const save = el('button', 'button secondary', 'Save note'); save.type = 'submit';
  const noteStatus = el('span', 'note-status', state.run.notes?.[result.id]?.updatedAt ? `Saved ${date(state.run.notes[result.id].updatedAt)}` : '');
  noteStatus.setAttribute('role', 'status'); noteStatus.setAttribute('aria-live', 'polite');
  actions.append(save, noteStatus); noteForm.append(noteLabel, textarea, el('p', 'field-help', 'Human notes are stored separately and never change computed verdicts.'), actions);
  noteForm.addEventListener('submit', async (event) => {
    event.preventDefault(); save.disabled = true; noteStatus.textContent = 'Saving…';
    try {
      const saved = await api(`/api/runs/${encodeURIComponent(runId)}/notes`, { caseId: result.id, note: textarea.value });
      if (state.run?.id === runId) { state.run.notes ||= {}; state.run.notes[result.id] = saved; }
      noteStatus.textContent = `Saved ${date(saved.updatedAt)}`;
    } catch (error) { noteStatus.textContent = `Could not save: ${error.message}`; }
    finally { save.disabled = false; }
  });
  right.append(noteForm); body.append(left, right); detail.append(body);
  detail.append(el('div', 'evidence-footer', `Check ${result.id} · ${result.durationMs} ms · Evidence digest ${result.evidenceDigest || 'not provided'}`));
}
// Model attribution (integrations/model-identity), shown when the comparison carries it.
const ATTRIBUTION_LABELS = { app: 'Application change', model: 'Model change', confounded: 'Model and application may both have changed', unexplained: 'Run-to-run variation',
  'model-unverified': 'Model not observed comparably', 'held-across-model-change': 'Held across a model change', 'failed-across-model-change': 'Failed across a model change', 'no-change': 'No change', incompatible: 'Not comparable' };
const REPAIR_TRANSITIONS = ['fixed', 'contract-restored', 'local-control-restored'];
const attributionLabel = value => Object.hasOwn(ATTRIBUTION_LABELS, value) ? ATTRIBUTION_LABELS[value] : 'Unrecognized attribution';
function renderComparison(data) {
  const root = $('comparison-result'); root.dataset.loaded = 'true'; root.replaceChildren();
  const notice = el('div', `comparison-notice${data.compatible ? '' : ' warning'}`);
  notice.append(el('strong', '', data.compatible ? 'Compatible evidence' : 'These runs are not comparable'));
  notice.append(el('p', '', data.compatible ? (data.evidenceScope || 'Transitions below reflect the observed checks for these two runs.') : 'A repair cannot be verified from this comparison.'));
  if (data.reasons?.length) { const list = el('ul'); for (const reason of data.reasons) list.append(el('li', '', reason)); notice.append(list); }
  const attribution = data.modelAttribution;
  if (attribution?.state === 'recorded') {
    notice.append(el('p', '', `Verdict changes are attributed to: ${attribution.flipCause ? attributionLabel(attribution.flipCause) : 'nobody (the runs are not comparable)'}. Model ${attribution.relation || 'unknown'} (${attribution.strength || 'unknown'}); application ${attribution.app?.basis || 'unknown'}.`));
    for (const caveat of attribution.caveats || []) notice.append(el('p', '', caveat));
  } else if (attribution?.state === 'not-recorded') {
    notice.append(el('p', '', attribution.note || 'Model identity was not recorded for one or both runs.'));
    if (attribution.malformed?.length) notice.append(el('p', '', `A model identity was present but could not be read (${attribution.malformed.join(', ')}).`));
  }
  root.append(notice);
  const stats = el('div', 'comparison-stats');
  for (const [key, label] of [['fixed', data.restorationLabel || 'Fixed'], ['stillFailing', 'Still failing'], ['newFailures', 'New failures'], ['preservedPasses', 'Preserved passes'], ['unverified', 'Unverified']]) {
    const card = el('div', 'comparison-stat'); card.append(el('strong', '', data.summary?.[key] ?? '—'), document.createTextNode(label)); stats.append(card);
  }
  root.append(stats);
  if (data.summary?.notApplicable) root.append(el('p', 'field-help', `${data.summary.notApplicable} checks are not applicable under the unchanged declared scope. These are not passing tests.`));
  const wrap = el('div', 'table-wrap comparison-table'); const table = el('table'); const thead = el('thead'); const headRow = el('tr');
  const attributed = (data.rows || []).some(item => typeof item.attribution === 'string'), unreadable = attribution?.malformed?.length > 0;
  for (const label of ['Check', 'Baseline', 'Candidate', 'Transition', ...(attributed ? ['Attribution'] : [])]) headRow.append(el('th', '', label));
  thead.append(headRow); table.append(thead); const tbody = el('tbody');
  for (const item of data.rows || []) {
    const row = el('tr'); const before = el('td'); before.append(badge(item.before)); const after = el('td'); after.append(badge(item.after));
    // A repair credited to anything but the application is not shown as one.
    const transition = REPAIR_TRANSITIONS.includes(item.transition) && (unreadable || (attributed && item.attribution !== 'app')) ? `${item.transition} (not credited to the application)` : item.transition;
    row.append(el('td', '', item.title), before, after, el('td', '', transition));
    if (attributed) row.append(el('td', '', attributionLabel(item.attribution)));
    tbody.append(row);
  }
  table.append(tbody); wrap.append(table); root.append(wrap);
}
$('target').addEventListener('change', updateTargetDescription);
$('refresh-button').addEventListener('click', async () => { showMessage(''); await bootstrap(); });
$('access-form').addEventListener('submit', async event => {
  event.preventDefault();
  const entered = $('access-key').value; $('access-key').value = '';
  if (!/^[A-Za-z0-9_-]{32,128}$/.test(entered)) { $('access-status').textContent = 'Enter a valid local workbench key.'; return; }
  workbenchKey = entered; $('unlock-button').disabled = true;
  try { if (await bootstrap()) { $('access-status').textContent = ''; showMessage('Local workbench unlocked.'); } }
  finally { $('unlock-button').disabled = false; }
});
$('lock-button').addEventListener('click', () => { workbenchKey = null; window.location.reload(); });
$('history-more').addEventListener('click', async () => {
  const button = $('history-more'), cursor = state.bootstrap?.history?.nextCursor;
  if (!cursor) return; button.disabled = true;
  try {
    const page = await api(`/api/history?${new URLSearchParams({ before: cursor })}`);
    const seen = new Set(state.bootstrap.runs.map(run => run.id));
    state.bootstrap.runs.push(...page.runs.filter(run => !seen.has(run.id)));
    state.bootstrap.history = { nextCursor: page.nextCursor, total: page.total }; renderHistory();
  } catch (error) { showMessage(error.message, true); }
  finally { button.disabled = false; }
});
document.addEventListener('click', async event => {
  const anchor = event.target.closest('a[data-protected-download]');
  if (!anchor) return; event.preventDefault();
  try {
    if (!workbenchKey) { accessRequired(); return; }
    const url = new URL(anchor.href);
    if (url.origin !== window.location.origin || !url.pathname.startsWith('/api/')) throw new Error('Unsupported export destination.');
    const response = await fetch(url, { headers: { Authorization: `Bearer ${workbenchKey}` }, redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(10000) });
    if (response.status === 401) { accessRequired(); return; }
    if (!response.ok) throw new Error('Export could not be generated.');
    const reader = response.body.getReader(), chunks = []; let bytes = 0;
    try { while (true) { const part = await reader.read(); if (part.done) break; bytes += part.value.length; if (bytes > 8 * 1024 * 1024) throw new Error('Export exceeds the browser download limit.'); chunks.push(part.value); } }
    finally { await reader.cancel().catch(() => {}); }
    const blob = new Blob(chunks, { type: url.pathname.endsWith('.html') ? 'text/html' : 'application/json' });
    const objectURL = URL.createObjectURL(blob), download = document.createElement('a');
    download.href = objectURL; download.download = url.pathname.endsWith('.html') ? 'scopehaven-report.html' : 'scopehaven-evidence.json';
    document.body.append(download); download.click(); download.remove(); setTimeout(() => URL.revokeObjectURL(objectURL), 1000);
  } catch (error) { showMessage(error.message, true); }
});
$('status-filter').addEventListener('change', renderFindings);
for (const id of ['baseline', 'candidate']) {
  $(id).addEventListener('change', () => {
    ++state.compareRequest;
    $('comparison-result').dataset.loaded = '';
    $('comparison-result').replaceChildren(el('p', 'empty-copy', 'Run selection changed. Compare these runs to see their observed transitions.'));
  });
}
$('run-form').addEventListener('submit', async (event) => {
  event.preventDefault(); if (state.running || !state.bootstrap) return;
  const targetId = $('target').value; setRunBusy(true); showMessage('Running the configured checks and collecting available evidence…');
  try {
    const run = await api('/api/runs', { targetId });
    ++state.detailRequest; state.run = run; state.selectedCase = null; $('status-filter').value = 'all';
    renderRun();
    const refreshed = await bootstrap();
    showMessage(`Assessment saved. ${run.checksTotal} checks executed against ${run.targetName}.${refreshed ? '' : ' Run history could not be refreshed; use refresh to retry.'}`, !refreshed);
  } catch (error) { showMessage(`Assessment could not complete. ${error.message}`, true); }
  finally { setRunBusy(false); }
});
$('compare-form').addEventListener('submit', async (event) => {
  event.preventDefault(); const baseline = $('baseline').value; const candidate = $('candidate').value;
  if (!baseline || !candidate) return;
  if (baseline === candidate) { $('comparison-result').replaceChildren(el('p', 'empty-copy', 'Choose two different runs to investigate a change.')); return; }
  const request = ++state.compareRequest;
  $('compare-button').disabled = true; $('compare-button').textContent = 'Comparing…'; $('comparison-result').setAttribute('aria-busy', 'true');
  try {
    const data = await api(`/api/compare?${new URLSearchParams({ baseline, candidate })}`);
    if (request === state.compareRequest) renderComparison(data);
  } catch (error) { if (request === state.compareRequest) $('comparison-result').replaceChildren(el('p', 'empty-copy', `Comparison unavailable. ${error.message}`)); }
  finally { $('compare-button').disabled = (state.bootstrap?.runs?.length || 0) < 2; $('compare-button').textContent = 'Compare runs'; $('comparison-result').setAttribute('aria-busy', 'false'); }
});
await bootstrap();
