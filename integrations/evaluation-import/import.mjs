import { createHash } from 'node:crypto';
import { ImportFailure, LIMITS, parseBoundedJson } from './bounded-json.mjs';

export { LIMITS } from './bounded-json.mjs';
export const INPUT_CONTRACT = 'promptfoo-output/0.123.1-summary-v3';
export const ENVELOPE_VERSION = 'scopehaven.external-evaluation/1';
export const MAPPING_COMMIT = '34f74d34e140b5e17d23770dfb2340057b1936b8';
export const ERROR_MESSAGES = Object.freeze({
  invalid_input: 'Import requires UTF-8 JSON text.',
  input_limit: 'Import exceeds the input byte limit.',
  structure_limit: 'Import exceeds a structural limit.',
  invalid_json: 'Import is not valid supported JSON.',
  unsafe_key: 'Import contains an unsupported object key.',
  duplicate_key: 'Import contains duplicate object keys.',
  unsupported_format: 'Import does not match the selected versioned format.',
  invalid_shape: 'Import does not match the required result shape.',
  invalid_file: 'Input must be a readable bounded local regular file.',
  invalid_utf8: 'Input must contain valid UTF-8 text.',
  file_changed: 'Input changed while being read.',
  usage: 'Usage: cli.mjs --format promptfoo-output/0.123.1-summary-v3 --input LOCAL_FILE',
  runtime_unsupported: 'A supported Node runtime (22 or 24 LTS) is required.',
  import_failed: 'Import could not be completed.',
});

export function failureResult(code) {
  const safeCode = typeof code === 'string' && Object.hasOwn(ERROR_MESSAGES, code) ? code : 'import_failed';
  return { ok: false, error: { code: safeCode, message: ERROR_MESSAGES[safeCode] } };
}
const fail = code => { throw new ImportFailure(code); };
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const nullableString = value => value === null || typeof value === 'string';
const count = value => Number.isSafeInteger(value) && value >= 0;
const numeric = value => typeof value === 'number' && Number.isFinite(value);
const allowedTopKeys = new Set(['evalId', 'results', 'config', 'shareableUrl', 'metadata', 'vars', 'runtimeOptions', 'traces', 'blobAssets']);

function validateGrade(grade) {
  if (!record(grade) || typeof grade.pass !== 'boolean' || !numeric(grade.score) || typeof grade.reason !== 'string' ||
      (grade.metadata !== undefined && !record(grade.metadata)) ||
      (grade.metadata?.graderError !== undefined && grade.metadata.graderError !== true)) fail('invalid_shape');
  if (grade.componentResults !== undefined) {
    if (!Array.isArray(grade.componentResults)) fail('invalid_shape');
    for (const component of grade.componentResults) validateGrade(component);
  }
}

function hasGraderError(grade) {
  return !!grade && (grade.metadata?.graderError === true || grade.componentResults?.some(hasGraderError) === true);
}

function validateEnvelope(input) {
  if (!record(input) || !record(input.results) || input.results.version !== 3 ||
      Object.keys(input).some(key => !allowedTopKeys.has(key))) fail('unsupported_format');
  if (!nullableString(input.evalId) || !nullableString(input.shareableUrl) || !record(input.config)) fail('invalid_shape');
  for (const key of ['metadata', 'runtimeOptions']) if (input[key] !== undefined && !record(input[key])) fail('invalid_shape');
  for (const key of ['vars', 'traces', 'blobAssets']) if (input[key] !== undefined && !Array.isArray(input[key])) fail('invalid_shape');
  if (input.vars?.some(value => typeof value !== 'string')) fail('invalid_shape');
  const summary = input.results;
  if (typeof summary.timestamp !== 'string' || !summary.timestamp.length || !Array.isArray(summary.results) ||
      !Array.isArray(summary.prompts) || summary.prompts.some(value => !record(value)) ||
      !record(summary.stats) || !record(summary.stats.tokenUsage) ||
      !['successes', 'failures', 'errors'].every(key => count(summary.stats[key]))) fail('invalid_shape');
  if (summary.results.length > LIMITS.maxResults) fail('structure_limit');
  for (const row of summary.results) {
    if (!record(row) || typeof row.success !== 'boolean' || ![0, 1, 2].includes(row.failureReason) ||
        !numeric(row.score) || !count(row.promptIdx) || !count(row.testIdx) ||
        typeof row.promptId !== 'string' || !record(row.testCase) || !record(row.provider) ||
        !record(row.prompt) || !record(row.vars) || !record(row.namedScores) ||
        Object.values(row.namedScores).some(value => !numeric(value)) ||
        !numeric(row.latencyMs) || row.latencyMs < 0 ||
        (row.response !== undefined && !record(row.response)) ||
        (Object.hasOwn(row, 'error') && !nullableString(row.error))) fail('invalid_shape');
    if (row.gradingResult !== undefined && row.gradingResult !== null) validateGrade(row.gradingResult);
  }
  return summary.results;
}

// Exported for the judge-vs-records matrix (second-opinion.mjs), which reads the same rows.
export function classify(row) {
  // Promptfoo also puts failed-assertion reasons in `error`. Never classify by
  // error text, score/threshold, aggregate counts or raw provider output.
  if (!row.success && row.failureReason === 2) return ['error', 'reported-execution-error'];
  if (hasGraderError(row.gradingResult)) return row.success
    ? ['unknown', 'inconsistent-reported-verdict'] : ['error', 'reported-grader-error'];
  if (!row.success && row.failureReason === 1 && row.gradingResult?.pass !== true) return ['fail', 'reported-assertion-failure'];
  if (row.success && row.failureReason === 0) {
    if (row.error) return ['unknown', 'inconsistent-reported-verdict'];
    if (row.gradingResult?.pass === true) return ['pass', 'reported-assertion-pass'];
    if (row.gradingResult == null) return ['unknown', 'no-assertion-verdict'];
  }
  return ['unknown', 'inconsistent-reported-verdict'];
}

/**
 * Pure, deterministic import of untrusted JSON text. `format` must be the
 * explicit contract identifier; there is no format autodetection or fallback.
 * Returns a fresh minimized preview or a fixed safe error. Never executes
 * providers, scripts, assertion expressions, URLs or native assessments.
 */
export function importPromptfooJson(text, format) {
  try {
    if (format !== INPUT_CONTRACT) fail('unsupported_format');
    const input = parseBoundedJson(text), rows = validateEnvelope(input);
    const checks = rows.map((row, index) => {
      const [state, basis] = classify(row);
      return { key: `external-check-${String(index + 1).padStart(4, '0')}`, label: `Promptfoo check ${index + 1}`, state, basis, attributedTo: 'promptfoo' };
    });
    const summary = { total: checks.length, pass: 0, fail: 0, error: 0, unknown: 0 };
    for (const check of checks) summary[check.state]++;
    return {
      ok: true,
      record: {
        kind: 'external-evaluation-preview',
        envelopeVersion: ENVELOPE_VERSION,
        provenance: {
          tool: 'promptfoo',
          producerIdentity: 'unverified',
          inputContract: INPUT_CONTRACT,
          mappingSourceCommit: MAPPING_COMMIT,
          mappedPackageVersion: '0.123.1',
          actualPackageVersion: 'unverified',
          summaryFormatVersion: 3,
          sourceDigest: { algorithm: 'sha256', value: createHash('sha256').update(text, 'utf8').digest('hex'), scope: 'exact-input-utf8-bytes' },
          sourceBytes: Buffer.byteLength(text, 'utf8'),
        },
        trust: {
          claims: 'unverified-tool-reported',
          nativeAssessment: false,
          backendObservations: false,
          signatureVerified: false,
          repairVerification: 'not-assessed',
        },
        summary,
        checks,
        limitations: [
          'External tool claims only; the producer identity and actual package version are unverified.',
          'No native assessment, trusted backend observation, signed attestation or verified repair is created.',
          'Counts are derived from imported rows; source aggregate statistics and scores are discarded.',
          'Prompts, outputs, configuration, credentials, traces, URLs, names and other source content are discarded.',
          'Generated labels identify row order only and cannot establish correspondence across imports.',
          'Only the selected bounded contract is mapped; other formats and real vendor execution are unverified.',
          'The source digest identifies input bytes; it does not authenticate their author or claims.',
        ],
      },
    };
  } catch (error) {
    return failureResult(error instanceof ImportFailure ? error.code : 'import_failed');
  }
}
