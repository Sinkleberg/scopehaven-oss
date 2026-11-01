import { mountDashboard } from '/dashboard/dashboard.mjs';
import { createDashboardAdapter } from '/dashboard/adapter.mjs';

const panel = document.getElementById('access-panel');
const form = document.getElementById('access-form');
const input = document.getElementById('access-key');
const status = document.getElementById('access-status');
const unlockButton = document.getElementById('unlock-button');
let key = null, epoch = 0, dashboard, expiryTimer, expiresAt = null, unlocked = false;
let session = new AbortController();
const blobs = new Map();
{
  const fragment = new URLSearchParams(location.hash.slice(1));
  if (fragment.has('access')) {
    const candidate = fragment.get('access');
    if (/^[A-Za-z0-9_-]{32,128}$/.test(candidate || '')) key = candidate;
    history.replaceState(null, '', location.pathname + location.search);
  }
}
function accessError(message = 'Unlock this local workbench to continue.') {
  return Object.assign(new Error(message), { status: 401, code: 'ACCESS_REQUIRED' });
}
function releaseBlob(url) {
  clearTimeout(blobs.get(url)); blobs.delete(url); URL.revokeObjectURL(url);
}
function lock(message = 'Workbench locked. Reopen the private launch page or enter its key.') {
  key = null; unlocked = false; expiresAt = null; ++epoch;
  clearTimeout(expiryTimer); session.abort(); session = new AbortController();
  for (const url of blobs.keys()) releaseBlob(url);
  input.value = ''; status.textContent = message; dashboard?.lock();
}
function showUnlock() {
  if (!panel.open) panel.showModal();
  input.focus();
}
function route(path) {
  const url = new URL(path, location.origin);
  if (typeof path !== 'string' || !path.startsWith('/api/') || url.origin !== location.origin || url.hash) throw new Error('Unsupported local API destination.');
  return url;
}
async function bytes(response, maximum = 8 * 1024 * 1024) {
  // A declared length is checked before native buffering. Script-side stream
  // reads make Chromium report completed local responses as aborted requests.
  const declared = response.headers?.get?.('content-length');
  if (typeof declared === 'string' && /^\d{1,10}$/.test(declared) && typeof response.arrayBuffer === 'function') {
    if (Number(declared) > maximum) { await response.body?.cancel?.().catch(() => {}); throw new Error('The local response exceeds its limit.'); }
    const result = new Uint8Array(await response.arrayBuffer());
    if (result.length > maximum) throw new Error('The local response exceeds its limit.');
    return result;
  }
  const reader = response.body.getReader(), parts = []; let size = 0, complete = false;
  try {
    while (true) {
      const { value, done } = await reader.read(); if (done) { complete = true; break; }
      size += value.length; if (size > maximum) throw new Error('The local response exceeds its limit.');
      parts.push(value);
    }
  } finally { if (!complete) await reader.cancel().catch(() => {}); }
  const result = new Uint8Array(size); let offset = 0;
  for (const part of parts) { result.set(part, offset); offset += part.length; }
  return result;
}
// Starting an assessment waits for the whole run. An HTTP profile may declare a
// run budget of up to two hours (src/http-timing.mjs TIMING_BOUNDS.runBudgetMs),
// which bounds every request and wait the run starts; observer collections already
// in progress may finish after it, so only that request waits for the largest
// valid budget plus 60 s and a margin. Every other local request keeps 65 s.
const REQUEST_TIMEOUT_MS = 65000, ASSESSMENT_TIMEOUT_MS = 7200000 + 60000 + 5000;
async function transport(path, body) {
  const url = route(path);
  if (!key) throw accessError();
  const version = epoch;
  const timeoutMs = body !== undefined && url.pathname === '/api/runs' ? ASSESSMENT_TIMEOUT_MS : REQUEST_TIMEOUT_MS;
  const options = { method: body === undefined ? 'GET' : 'POST', headers: { Authorization: `Bearer ${key}`, Accept: 'application/json' }, credentials: 'omit', redirect: 'error', cache: 'no-store', signal: AbortSignal.any([session.signal, AbortSignal.timeout(timeoutMs)]) };
  if (body !== undefined) {
    options.headers['Content-Type'] = 'application/json'; options.headers['X-Scopehaven-Request'] = '1'; options.body = JSON.stringify(body);
  }
  const response = await fetch(url, options);
  if (version !== epoch) throw accessError();
  if (response.status === 401) { lock('This key is invalid or expired. Open the current private launch page.'); throw accessError(); }
  const content = await bytes(response);
  if (version !== epoch) throw accessError();
  if (!response.ok) {
    let message, code;
    try { const data = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(content)); message = typeof data.error === 'string' ? data.error : data.error?.message; code = data.code; } catch {}
    throw Object.assign(new Error(message || `Local request failed (${response.status}).`), { status: response.status, code });
  }
  return { content, version };
}
async function armExpiry(version) {
  if (expiresAt !== null) return;
  const response = await fetch('/api/access-info', { cache: 'no-store', credentials: 'omit', redirect: 'error', signal: AbortSignal.any([session.signal, AbortSignal.timeout(10000)]) });
  const info = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(await bytes(response, 4096)));
  if (version !== epoch) throw accessError();
  if (!response.ok || !Number.isFinite(info.expiresAt) || info.expiresAt <= Date.now() || info.expiresAt - Date.now() > 8 * 60 * 60 * 1000 + 1000) {
    lock('The local session expired or its expiry could not be verified. Restart the workbench.'); throw accessError();
  }
  expiresAt = info.expiresAt;
  clearTimeout(expiryTimer);
  expiryTimer = setTimeout(() => { if (version === epoch) lock('This local session expired. Restart the workbench for a new launch key.'); }, expiresAt - Date.now());
}
async function request(path, body) {
  const { content, version } = await transport(path, body);
  let data;
  try { data = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(content)); }
  catch { throw new Error('The local API returned unreadable JSON.'); }
  if (path === '/api/bootstrap') {
    await armExpiry(version);
    if (version !== epoch) throw accessError();
    unlocked = true; status.textContent = ''; if (panel.open) panel.close();
  }
  return data;
}
async function download(path, filename) {
  const { content, version } = await transport(path);
  if (version !== epoch) throw accessError();
  const blob = new Blob([content], { type: path.endsWith('.html') ? 'text/html' : 'application/json' });
  const url = URL.createObjectURL(blob), anchor = document.createElement('a');
  while (blobs.size >= 8) releaseBlob(blobs.keys().next().value);
  blobs.set(url, setTimeout(() => releaseBlob(url), 60000));
  anchor.href = url; anchor.download = filename; document.body.append(anchor); anchor.click(); anchor.remove();
  // Browsers do not expose a reliable saved-to-disk receipt here. The dashboard
  // says "prepared for download" and offers the verified local CLI fallback.
  return { prepared: true, bytes: content.length };
}
const adapter = createDashboardAdapter({ request, download });
dashboard = mountDashboard(document.getElementById('dashboard-root'), { adapter, onLock: () => lock(), onUnlockRequest: showUnlock, preview: false });
form.addEventListener('submit', async event => {
  event.preventDefault();
  const candidate = input.value.trim(); input.value = '';
  if (!/^[A-Za-z0-9_-]{32,128}$/.test(candidate)) { status.textContent = 'Enter the key from this server session’s private launch page.'; return; }
  lock('Unlocking…'); key = candidate; unlockButton.disabled = true;
  const version = epoch;
  try { await dashboard.unlock(); if (version === epoch && !unlocked) status.textContent = 'Could not unlock. Check the local server and its current launch key.'; }
  finally { unlockButton.disabled = false; }
});
document.getElementById('close-access').addEventListener('click', () => { input.value = ''; panel.close(); });
panel.addEventListener('close', () => { input.value = ''; });
window.addEventListener('pagehide', () => { lock(); dashboard.destroy(); });
window.addEventListener('pageshow', event => { if (event.persisted) location.reload(); });
await dashboard.ready;
