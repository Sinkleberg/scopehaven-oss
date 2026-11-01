// Authentication, transport and Blob saving belong to the mounting application.
// This module holds no capability and accepts no caller-selected destinations.
export const EXTERNAL_PREVIEW_FORMAT = 'promptfoo-output/0.123.1-summary-v3';
export const EXTERNAL_PREVIEW_MAX_BYTES = 16 * 1024 * 1024;

function invalid(message) {
  const error = new TypeError(message);
  error.status = 400;
  error.code = 'INVALID_INPUT';
  throw error;
}
function runId(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) invalid('Choose a valid run identifier.');
  return encodeURIComponent(value);
}
function identifier(value, label) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{1,80}$/.test(value)) invalid(`Choose a valid ${label} identifier.`);
  return value;
}
function query(values) { return new URLSearchParams(values).toString(); }

/** request(path, body?) returns authenticated JSON; download(path, filename)
 * saves an authenticated Blob. Both callbacks retain their native return values
 * and errors, including status=401 / code=ACCESS_REQUIRED. */
export function createDashboardAdapter({ request, download } = {}) {
  if (typeof request !== 'function' || typeof download !== 'function') invalid('Authenticated request and download callbacks are required.');
  return Object.freeze({
    bootstrap() { return request('/api/bootstrap'); },
    history(cursor) {
      if (cursor === undefined) return request('/api/history');
      if (typeof cursor !== 'string' || !/^[A-Za-z0-9_-]{1,256}$/.test(cursor)) invalid('Choose a valid history cursor.');
      return request(`/api/history?${query({ before: cursor })}`);
    },
    run(id) { return request(`/api/runs/${runId(id)}`); },
    assess(targetId) { return request('/api/runs', { targetId: identifier(targetId, 'target') }); },
    note(id, caseId, note) {
      const segment = runId(id);
      identifier(caseId, 'check');
      if (typeof note !== 'string' || note.length > 5000) invalid('Notes must contain at most 5,000 characters.');
      return request(`/api/runs/${segment}/notes`, { caseId, note });
    },
    compare(baseline, candidate) {
      runId(baseline); runId(candidate);
      return request(`/api/compare?${query({ baseline, candidate })}`);
    },
    exportSuite(targetId) {
      identifier(targetId, 'target');
      return download(`/api/suite/export.json?${query({ targetId })}`, 'scopehaven-check-definitions.json');
    },
    exportRun(id, format = 'json') {
      const segment = runId(id);
      if (!['json', 'html'].includes(format)) invalid('Choose JSON or HTML export.');
      return download(`/api/runs/${segment}/${format === 'json' ? 'export.json' : 'report.html'}`, `scopehaven-${id}.${format}`);
    },
    gate(id) { return request(`/api/runs/${runId(id)}/gate`); },
    previewExternal(content) {
      if (typeof content !== 'string' || !content.trim()) invalid('Provide external evaluation JSON text.');
      if (content.length > EXTERNAL_PREVIEW_MAX_BYTES || new TextEncoder().encode(content).byteLength > EXTERNAL_PREVIEW_MAX_BYTES) {
        const error = new RangeError('External evaluation text exceeds the 16 MiB limit.');
        error.status = 413; error.code = 'CONTENT_TOO_LARGE'; throw error;
      }
      return request('/api/external-evaluations/preview', { format: EXTERNAL_PREVIEW_FORMAT, content });
    },
  });
}
