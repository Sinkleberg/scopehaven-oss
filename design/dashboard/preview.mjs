import { mountDashboard } from './dashboard.mjs';
import { createDashboardAdapter } from './adapter.mjs';

const root = document.getElementById('dashboard-root');
const status = document.getElementById('preview-status');
let fixture, memory, view, mode = 'normal', delayed = false;
const copy = value => structuredClone(value);
const summary = ({results, notes, limitations, integrity, ...rest}) => rest;
const fail = (message, status = 400, code = 'PREVIEW_UNSUPPORTED') => { throw Object.assign(new Error(message), {status, code}); };
const say = message => { status.textContent = `PREVIEW ONLY · ${message}`; };
function ensureAccess() {
  if (mode === 'locked') fail('Preview locked. Use the preview unlock control.', 401, 'ACCESS_REQUIRED');
  if (mode === 'error') fail('Simulated preview API error. Reset synthetic data to recover.', 503, 'PREVIEW_ERROR');
}
function findRun(id) {
  const run = memory.find(run => run.id === id);
  if (!run) fail('This run is unavailable in the isolated preview.', 404);
  return run;
}
function bootstrap() {
  const data = copy(fixture.bootstrap);
  data.runs = memory.map(summary);
  data.history = {total:memory.length, nextCursor:null};
  return data;
}
async function request(path, body) {
  ensureAccess();
  let result;
  if (path === '/api/bootstrap') result = bootstrap();
  else if (path === '/api/history') result = {runs:memory.map(summary),total:memory.length,nextCursor:null};
  else if (path.startsWith('/api/history?')) fail('No additional history pages exist in the isolated preview.', 404);
  else if (path === '/api/runs') fail('Preview does not execute a new assessment. The displayed runs were generated from owned synthetic fixtures.');
  else if (path === '/api/external-evaluations/preview') fail('External evaluation import requires the core API. This isolated preview does not parse or save imported evaluations.');
  else if (path.startsWith('/api/compare?')) {
    const params = new URLSearchParams(path.slice(path.indexOf('?') + 1));
    const baseline = params.get('baseline'), candidate = params.get('candidate');
    findRun(baseline); findRun(candidate);
    result = fixture.comparisons[`${baseline}:${candidate}`];
    if (!result) fail('This comparison is unavailable in the preview.', 404);
  } else {
    const match = /^\/api\/runs\/([0-9a-f-]+)(?:\/(notes|gate))?$/.exec(path);
    if (!match) fail('Unsupported isolated preview route.', 404);
    const [, id, action] = match, run = findRun(id);
    if (action === 'notes') {
      if (!run.results.some(row => row.id === body?.caseId) || typeof body?.note !== 'string' || body.note.length > 5000) fail('Invalid preview note.');
      result = {note:body.note, updatedAt:new Date().toISOString()};
      run.notes ||= {}; run.notes[body.caseId] = copy(result);
      result = {caseId:body.caseId,...result};
      say('Note saved in this page’s memory only. Reload resets it.');
    } else if (action === 'gate') { result = fixture.gates[id]; if (!result) fail('Gate evaluation is unavailable in this snapshot preview. Use the authenticated core workbench.'); }
    else result = run;
  }
  const snapshot = copy(result);
  if (delayed) {
    delayed = false;
    await new Promise(resolve => setTimeout(resolve, 1600));
  }
  return snapshot;
}
async function download(path, filename) {
  ensureAccess();
  let data;
  if (path.startsWith('/api/suite/export.json?')) {
    const targetId = new URLSearchParams(path.split('?')[1]).get('targetId');
    data = fixture.suites[targetId];
    if (!data) fail('No preview suite exists for this target.', 404);
  } else {
    const match = /^\/api\/runs\/([0-9a-f-]+)\/(export\.json|report\.html)$/.exec(path);
    if (!match) fail('Unsupported preview export destination.', 404);
    if (match[2] === 'report.html') fail('HTML report export requires the core report renderer. JSON preview export is available.');
    data = findRun(match[1]);
  }
  const blob = new Blob([JSON.stringify({previewOnly:true,provenance:fixture.preview,evidence:data},null,2)], {type:'application/json'});
  const url = URL.createObjectURL(blob), link = document.createElement('a');
  link.href = url; link.download = filename.replace('scopehaven-', 'scopehaven-preview-');
  document.body.append(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30000);
  say('Saved a JSON preview export with explicit synthetic provenance.');
}
const adapter = createDashboardAdapter({request, download});
function mount() {
  view = mountDashboard(root, {adapter, preview:true,
    onLock() { mode = 'locked'; say('Locked. Pending dashboard responses must not restore evidence.'); },
    onUnlockRequest() { mode = 'normal'; void view.unlock(); say('Unlocked isolated preview.'); },
  });
  return view.ready;
}
async function control(action) {
  if (!fixture) return;
  if (action === 'unmount') { view?.destroy(); view = null; say('Unmounted. Dashboard root and listeners removed.'); return; }
  if (action === 'remount') { view?.destroy(); mode = 'normal'; await mount(); say('Remounted isolated preview.'); return; }
  if (!view) { say('Dashboard is unmounted. Use Remount.'); return; }
  if (action === 'lock') { mode = 'locked'; view.lock(); say('Locked isolated preview.'); }
  else if (action === 'unlock') { mode = 'normal'; await view.unlock(); say('Unlocked isolated preview.'); }
  else if (action === 'normal' || action === 'empty' || action === 'error') {
    memory = action === 'empty' ? [] : copy(fixture.runs);
    mode = action === 'error' ? 'error' : 'normal';
    view.destroy(); await mount();
    say(action === 'error' ? 'Simulated API error active. Reset to recover.' : action === 'empty' ? 'Empty history active. Targets remain available; execution is unsupported in preview.' : 'Fixture data reset. Notes cleared.');
  } else if (action === 'stale') {
    mode = 'normal'; delayed = true;
    const pending = view.refresh();
    mode = 'locked'; view.lock();
    say('A captured synthetic response is delayed 1.6 seconds. Dashboard must remain locked when it resolves.');
    await pending;
    say('Delayed response resolved. Dashboard should still be locked with no evidence rendered.');
  }
}
for (const button of document.querySelectorAll('[data-preview]')) button.addEventListener('click', () => { void control(button.dataset.preview).catch(error => say(error.message)); });
try {
  const response = await fetch('/preview-data.json', {cache:'no-store'});
  if (!response.ok) throw new Error('Isolated fixture data could not be loaded.');
  fixture = await response.json(); memory = copy(fixture.runs);
  await mount(); say('Synthetic-state evidence snapshot loaded. Notes are memory-only; new assessments, HTML export and external import show unsupported-preview errors.');
} catch (error) { say(error.message); }
window.addEventListener('pagehide', () => { view?.destroy(); memory = null; fixture = null; }, {once:true});
