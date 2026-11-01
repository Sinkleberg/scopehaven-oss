import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile, mkdtemp, rm, symlink, readdir } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { INPUT_CONTRACT, ENVELOPE_VERSION, LIMITS, ERROR_MESSAGES, importPromptfooJson } from '../integrations/evaluation-import/import.mjs';
import { importLocalFile, main } from '../integrations/evaluation-import/cli.mjs';
import { parseBoundedJson, ImportFailure } from '../integrations/evaluation-import/bounded-json.mjs';
import { createStore } from '../src/store.mjs';
import { compareRuns } from '../src/runner.mjs';
import { assertRuntime } from '../src/runtime.mjs';
import { startServer } from '../src/server.mjs';
import { createDashboardAdapter, EXTERNAL_PREVIEW_FORMAT, EXTERNAL_PREVIEW_MAX_BYTES } from '../design/dashboard/adapter.mjs';
import { EXTERNAL_PREVIEW_MAX_BYTES as SERVED_PREVIEW_MAX_BYTES } from '../public/dashboard/adapter.mjs';

// Side effects: synthetic local files only under the lane-owned integration
// directory, then cleanup. Child processes execute only the local CLI with the
// current pinned runtime. API acceptance adds owned ephemeral loopback HTTP
// only, with empty env/profiles and an assessment sentinel. No external network,
// providers, actual native assessments or existing private data are used.
assertRuntime();
const owned = fileURLToPath(new URL('../integrations/evaluation-import/', import.meta.url));
const fixturePath = join(owned, 'fixtures/promptfoo-0.123.1-v3.synthetic.json');
const fixtureText = await readFile(fixturePath, 'utf8');
const fixture = () => JSON.parse(fixtureText);
const invoke = value => importPromptfooJson(JSON.stringify(value), INPUT_CONTRACT);
const row = () => fixture().results.results[0];
const oneRow = mutate => { const value = fixture(); value.results.results = [row()]; mutate?.(value.results.results[0]); return invoke(value); };
const parsed = result => { assert.equal(result.ok, true, JSON.stringify(result)); return result.record; };
const rejected = (result, code) => {
  assert.equal(result.ok, false);
  if (code) assert.equal(result.error.code, code);
  assert.deepEqual(Object.keys(result).sort(), ['error', 'ok']);
  assert.deepEqual(Object.keys(result.error).sort(), ['code', 'message']);
  assert.equal(result.error.message, ERROR_MESSAGES[result.error.code]);
  assert.doesNotMatch(JSON.stringify(result), /SYNTHETIC_PRIVATE_SENTINEL|<script|secret-path|https?:/);
};
async function temporary(fn) {
  const path = await mkdtemp(join(owned, '.test-'));
  try { return await fn(path); } finally { await rm(path, { recursive: true, force: true }); }
}

test('documented v3 synthetic export yields an attributed, minimized external preview', () => {
  const result = parsed(importPromptfooJson(fixtureText, INPUT_CONTRACT));
  assert.equal(result.kind, 'external-evaluation-preview');
  assert.equal(result.envelopeVersion, ENVELOPE_VERSION);
  assert.deepEqual(result.summary, { total: 4, pass: 1, fail: 1, error: 1, unknown: 1 });
  assert.deepEqual(result.checks.map(x => x.state), ['pass', 'fail', 'error', 'unknown']);
  assert.deepEqual(result.checks.map(x => x.key), ['external-check-0001', 'external-check-0002', 'external-check-0003', 'external-check-0004']);
  assert.equal(result.checks.every(x => x.attributedTo === 'promptfoo'), true);
  assert.equal(result.provenance.actualPackageVersion, 'unverified');
  assert.equal(result.provenance.producerIdentity, 'unverified');
  assert.deepEqual(result.provenance.sourceDigest, { algorithm: 'sha256', value: createHash('sha256').update(fixtureText).digest('hex'), scope: 'exact-input-utf8-bytes' });
  assert.equal(result.provenance.sourceBytes, Buffer.byteLength(fixtureText));
  assert.deepEqual(importPromptfooJson(fixtureText, INPUT_CONTRACT), importPromptfooJson(fixtureText, INPUT_CONTRACT));
});

test('assertion failures with error text remain fail; explicit execution failures are error', () => {
  for (const error of [undefined, null, '', 'SYNTHETIC_PRIVATE_SENTINEL timeout <script>']) {
    const failure = parsed(oneRow(r => { r.success = false; r.failureReason = 1; r.error = error; r.gradingResult.pass = false; }));
    assert.equal(failure.checks[0].state, 'fail');
    const execution = parsed(oneRow(r => { r.success = false; r.failureReason = 2; r.error = error; delete r.gradingResult; }));
    assert.equal(execution.checks[0].state, 'error');
  }
});

test('unknown and contradictory verdicts are never inferred as a pass or repair', () => {
  for (const mutate of [
    r => { delete r.gradingResult; },
    r => { r.gradingResult = null; },
    r => { r.success = false; r.failureReason = 0; r.gradingResult.pass = false; },
    r => { r.success = true; r.failureReason = 1; },
    r => { r.success = true; r.failureReason = 2; },
    r => { r.success = false; r.failureReason = 1; },
    r => { r.gradingResult.pass = false; },
    r => { r.error = 'SYNTHETIC_PRIVATE_SENTINEL'; },
  ]) {
    const result = parsed(oneRow(mutate));
    assert.equal(result.checks[0].state, 'unknown');
    assert.equal(result.summary.pass, 0);
    assert.equal(result.trust.repairVerification, 'not-assessed');
  }
});

test('documented grader errors including nested components do not become assertion verdicts', () => {
  for (const nested of [false, true]) {
    const mutate = r => {
      r.success = false; r.failureReason = 1; r.gradingResult.pass = false;
      const grading = nested ? r.gradingResult.componentResults[0] = { pass: false, score: 0, reason: 'SYNTHETIC_PRIVATE_SENTINEL' } : r.gradingResult;
      grading.metadata = { graderError: true };
    };
    assert.equal(parsed(oneRow(mutate)).checks[0].state, 'error');
    assert.equal(parsed(oneRow(r => { mutate(r); r.success = true; r.failureReason = 0; r.gradingResult.pass = true; })).checks[0].state, 'unknown');
  }
});

test('explicit contract and envelope version are required; native, legacy and future shapes are rejected', () => {
  for (const format of [undefined, '', 'promptfoo', 'promptfoo-output/0.123.2-summary-v3', 3, {}, null]) rejected(importPromptfooJson(fixtureText, format), 'unsupported_format');
  for (const value of [null, [], {}, { results: [] }, { schemaVersion: 1, results: [] }, { version: 3, ...fixture().results }]) rejected(invoke(value), 'unsupported_format');
  for (const version of [undefined, '3', 2, 4, null]) {
    const value = fixture(); value.results.version = version;
    rejected(invoke(value), 'unsupported_format');
  }
  const unexpected = fixture(); unexpected.nativeAssessment = true;
  rejected(invoke(unexpected), 'unsupported_format');
});

test('required immediate shape and result field types are checked before any preview', () => {
  const requiredRows = ['success', 'failureReason', 'score', 'promptIdx', 'testIdx', 'testCase', 'promptId', 'provider', 'prompt', 'vars', 'latencyMs', 'namedScores'];
  for (const field of requiredRows) rejected(oneRow(r => { delete r[field]; }), 'invalid_shape');
  for (const mutate of [
    v => { delete v.evalId; }, v => { delete v.config; }, v => { delete v.shareableUrl; },
    v => { v.config = []; }, v => { v.results.prompts = {}; }, v => { v.results.timestamp = 1; },
    v => { v.results.stats.errors = -1; }, v => { delete v.results.stats.tokenUsage; },
    v => { v.traces = {}; }, v => { v.vars = [1]; }, v => { v.metadata = 'private'; },
  ]) { const value = fixture(); mutate(value); rejected(invoke(value), 'invalid_shape'); }
  for (const mutate of [
    r => { r.success = 'true'; }, r => { r.failureReason = 3; }, r => { r.error = {}; },
    r => { r.promptIdx = -1; }, r => { r.latencyMs = '1'; }, r => { r.namedScores = { bad: '1' }; },
    r => { r.gradingResult = []; }, r => { delete r.gradingResult.score; },
    r => { r.gradingResult.reason = {}; }, r => { r.gradingResult.componentResults = [null]; },
    r => { r.gradingResult.metadata = { graderError: false }; },
  ]) rejected(oneRow(mutate), 'invalid_shape');
});

test('all source content including identifiers, HTML, URLs, scripts and synthetic secrets is discarded', () => {
  const value = fixture(), marker = 'SYNTHETIC_PRIVATE_SENTINEL';
  value.config.code = '<script>globalThis.importCodeRan=true</script>';
  value.config.assert = [{ type: 'javascript', value: 'throw new Error("SYNTHETIC_PRIVATE_SENTINEL")' }];
  value.config.credentials = { token: marker, password: marker };
  value.results.results[0].metadata = { schemaVersion: 1, nativeAssessment: true, repairVerified: true, customer: marker };
  const result = parsed(invoke(value)), exported = JSON.stringify(result);
  assert.doesNotMatch(exported, /SYNTHETIC_PRIVATE_SENTINEL|<|>|https?:\/\/|synthetic-provider|importCodeRan|apiKey|password|2026-09-18T/);
  assert.equal(globalThis.importCodeRan, undefined);
  assert.equal(result.trust.nativeAssessment, false);
  assert.equal(result.trust.backendObservations, false);
  for (const check of result.checks) assert.deepEqual(Object.keys(check).sort(), ['attributedTo', 'basis', 'key', 'label', 'state']);
  const changed = fixture(); changed.config = { customer: 'different-private-content' }; changed.results.results[0].response = { output: 'different-private-output' };
  const before = parsed(invoke(fixture())), after = parsed(invoke(changed));
  assert.notEqual(before.provenance.sourceDigest.value, after.provenance.sourceDigest.value);
  delete before.provenance.sourceDigest; delete after.provenance.sourceDigest;
  delete before.provenance.sourceBytes; delete after.provenance.sourceBytes;
  assert.deepEqual(before, after);
});

test('raw source statistics and scores cannot create additional passes', () => {
  const value = fixture(); value.results.stats = { successes: 999999, failures: 0, errors: 0, tokenUsage: {} };
  value.results.results.forEach(r => { r.score = 100; if (r.gradingResult) r.gradingResult.score = 100; });
  assert.deepEqual(parsed(invoke(value)).summary, { total: 4, pass: 1, fail: 1, error: 1, unknown: 1 });
  value.results.results = [];
  assert.deepEqual(parsed(invoke(value)).summary, { total: 0, pass: 0, fail: 0, error: 0, unknown: 0 });
});

test('malformed JSON and non-text input produce fixed errors without invoking getters', () => {
  for (const text of ['', '{', '{"a":}', '{"a":1,}', '[1,]', 'NaN', '{"a":01}', '{"a":1e999}', '{"a":"\n"}', '{"a":"\\uZZZZ"}', fixtureText + 'SYNTHETIC_PRIVATE_SENTINEL', '\uFEFF' + fixtureText]) rejected(importPromptfooJson(text, INPUT_CONTRACT), 'invalid_json');
  let invoked = false;
  const hostile = { get results() { invoked = true; throw new Error('SYNTHETIC_PRIVATE_SENTINEL'); }, toString() { invoked = true; throw new Error('SYNTHETIC_PRIVATE_SENTINEL'); } };
  for (const value of [hostile, null, 123, Buffer.from(fixtureText)]) rejected(importPromptfooJson(value, INPUT_CONTRACT), 'invalid_input');
  assert.equal(invoked, false);
});

test('duplicate and prototype-polluting keys are rejected even in discarded or escaped fields', () => {
  for (const text of ['{"a":1,"a":2}', '{"a":1,"\\u0061":2}']) rejected(importPromptfooJson(text, INPUT_CONTRACT), 'duplicate_key');
  for (const key of ['__proto__', 'prototype', 'constructor', '\\u005f_proto__']) {
    const text = fixtureText.replace('"config": {', `"config": {"${key}":{"polluted":"SYNTHETIC_PRIVATE_SENTINEL"},`);
    rejected(importPromptfooJson(text, INPUT_CONTRACT), 'unsafe_key');
  }
  assert.equal({}.polluted, undefined);
});

test('byte, string and key limits include discarded and multibyte source data', () => {
  rejected(importPromptfooJson(' '.repeat(LIMITS.maxBytes + 1), INPUT_CONTRACT), 'input_limit');
  rejected(importPromptfooJson('é'.repeat(LIMITS.maxBytes / 2 + 1), INPUT_CONTRACT), 'input_limit');
  const value = fixture(); value.config.data = 'é'.repeat(LIMITS.maxStringBytes / 2);
  parsed(invoke(value));
  value.config.data += 'é'; rejected(invoke(value), 'structure_limit');
  value.config = { ['x'.repeat(LIMITS.maxKeyBytes + 1)]: true }; rejected(invoke(value), 'structure_limit');
  const padded = fixtureText + ' '.repeat(LIMITS.maxBytes - Buffer.byteLength(fixtureText));
  assert.equal(parsed(importPromptfooJson(padded, INPUT_CONTRACT)).provenance.sourceBytes, LIMITS.maxBytes);
});

test('real-size Promptfoo exports import: synthetic stand-ins sized like the saved runs the old limits refused', () => {
  // Row count, total bytes and longest string of four saved exports (two practice-app runs and two
  // pilot runs). The 1 MiB input and 16 KiB string limits refused all four shapes.
  // The saved files hold run content, so only their sizes are reused; every byte here is synthetic.
  const shapes = [['practice-agent', 65, 1_391_593, 13_281], ['practice-viewer', 70, 1_480_425, 12_166], ['workspace-app', 14, 536_172, 87_004], ['real-app', 28, 3_512_826, 315_767]];
  const base = row();
  for (const [label, rows, bytes, longest] of shapes) {
    const value = fixture(), empty = Buffer.byteLength(JSON.stringify({ ...value, results: { ...value.results, results: [] } }));
    const perRow = Math.floor((bytes - empty) / rows) - Buffer.byteLength(JSON.stringify({ ...base, testIdx: 0, response: { output: '' } })) - 1;
    value.results.results = Array.from({ length: rows }, (_, i) => ({ ...base, testIdx: i, response: { output: 'o'.repeat(i === 0 ? longest : Math.max(0, perRow - Math.ceil((longest - perRow) / (rows - 1)))) } }));
    const text = JSON.stringify(value), size = Buffer.byteLength(text);
    assert(Math.abs(size - bytes) / bytes < 0.02, `${label}: ${size} bytes against ${bytes}`);
    assert(size > 1_048_576 || longest > 16_384, `${label} was over an old limit`);
    const record = parsed(importPromptfooJson(text, INPUT_CONTRACT));
    assert.equal(record.summary.total, rows, label); assert.equal(record.provenance.sourceBytes, size);
    // Long outputs are read for the bounds and discarded, never copied into the record.
    assert.doesNotMatch(JSON.stringify(record), /oooooooo/);
  }
  // The limits still bound a hostile input: one string byte over is refused.
  const overString = fixture(); overString.results.results = [{ ...base, response: { output: 'o'.repeat(LIMITS.maxStringBytes + 1) } }];
  rejected(invoke(overString), 'structure_limit');
  assert.deepEqual(LIMITS, { maxBytes: 16_777_216, maxDepth: 24, maxNodes: 200_000, maxArrayItems: 1_000, maxObjectKeys: 256, maxStringBytes: 1_048_576, maxKeyBytes: 128, maxResults: 500 });
});

test('each parser bound: exactly at the cap parses, one over is refused', () => {
  const ok = text => assert.doesNotThrow(() => parseBoundedJson(text));
  const over = (text, code) => assert.throws(() => parseBoundedJson(text), error => error instanceof ImportFailure && error.code === code);
  // Input bytes.
  ok('0' + ' '.repeat(LIMITS.maxBytes - 1)); over('0' + ' '.repeat(LIMITS.maxBytes), 'input_limit');
  // Depth: the root is depth 0, so maxDepth nested arrays put the innermost value at maxDepth.
  const nest = levels => '['.repeat(levels) + '0' + ']'.repeat(levels);
  ok(nest(LIMITS.maxDepth)); over(nest(LIMITS.maxDepth + 1), 'structure_limit');
  // Nodes: a root array of full arrays plus one partial array, totalling exactly maxNodes values.
  const full = Math.floor((LIMITS.maxNodes - 1) / (LIMITS.maxArrayItems + 1)), rest = LIMITS.maxNodes - 1 - full * (LIMITS.maxArrayItems + 1) - 1;
  const nodes = extra => '[' + [...Array(full).fill('[' + Array(LIMITS.maxArrayItems).fill('0').join(',') + ']'), '[' + Array(rest + extra).fill('0').join(',') + ']'].join(',') + ']';
  ok(nodes(0)); over(nodes(1), 'structure_limit');
  // Array items and object keys.
  ok('[' + Array(LIMITS.maxArrayItems).fill('0').join(',') + ']'); over('[' + Array(LIMITS.maxArrayItems + 1).fill('0').join(',') + ']', 'structure_limit');
  const keys = n => JSON.stringify(Object.fromEntries(Array.from({ length: n }, (_, i) => [`k${i}`, 0])));
  ok(keys(LIMITS.maxObjectKeys)); over(keys(LIMITS.maxObjectKeys + 1), 'structure_limit');
  // String and key bytes, counted in UTF-8 after unescaping.
  ok(JSON.stringify('x'.repeat(LIMITS.maxStringBytes))); over(JSON.stringify('x'.repeat(LIMITS.maxStringBytes + 1)), 'structure_limit');
  ok(JSON.stringify(['é'.repeat(LIMITS.maxStringBytes / 2)])); over(JSON.stringify(['é'.repeat(LIMITS.maxStringBytes / 2) + 'x']), 'structure_limit');
  ok(JSON.stringify({ ['k'.repeat(LIMITS.maxKeyBytes)]: 0 })); over(JSON.stringify({ ['k'.repeat(LIMITS.maxKeyBytes + 1)]: 0 }), 'structure_limit');
  // The other refusals are unchanged by the larger caps.
  over('{"a":1,"a":2}', 'duplicate_key'); over('{"__proto__":1}', 'unsafe_key'); over('\ufeff{}', 'invalid_json'); over('[1e999]', 'invalid_json'); over('{} {}', 'invalid_json');
});

test('the served and design dashboards state the importer\'s own input limit', async () => {
  assert.equal(EXTERNAL_PREVIEW_MAX_BYTES, LIMITS.maxBytes); assert.equal(SERVED_PREVIEW_MAX_BYTES, LIMITS.maxBytes);
  for (const file of ['../public/dashboard/dashboard.mjs', '../design/dashboard/dashboard.mjs', '../public/dashboard/adapter.mjs', '../design/dashboard/adapter.mjs']) {
    const source = await readFile(new URL(file, import.meta.url), 'utf8');
    for (const [, digits] of source.matchAll(/encode\(content\)\.length>(\d+)/g)) assert.equal(Number(digits), LIMITS.maxBytes, `${file} inline check`);
    for (const [, mib] of source.matchAll(/(\d+) MiB/g)) assert.equal(Number(mib) * 1_048_576, LIMITS.maxBytes, `${file} stated limit`);
  }
});

test('depth, node, object, array and evaluation item bounds cannot be bypassed by unused data', () => {
  const nested = fixture(); let data = 0;
  for (let i = 0; i <= LIMITS.maxDepth; i++) data = { nested: data };
  nested.config = data; rejected(invoke(nested), 'structure_limit');
  // The last case is just over the node limit, built from arrays that each fit maxArrayItems.
  const overNodes = Array.from({ length: Math.ceil(LIMITS.maxNodes / LIMITS.maxArrayItems) }, () => Array(LIMITS.maxArrayItems).fill(0));
  for (const data of [Array(LIMITS.maxArrayItems + 1).fill(0), Object.fromEntries(Array.from({ length: LIMITS.maxObjectKeys + 1 }, (_, i) => [`k${i}`, 0])), overNodes]) {
    const value = fixture(); value.config = { data }; rejected(invoke(value), 'structure_limit');
  }
  const minimal = { promptIdx: 0, testIdx: 0, testCase: {}, promptId: '', provider: {}, prompt: {}, vars: {}, success: true, failureReason: 0, score: 1, latencyMs: 0, namedScores: {} };
  const max = fixture(); max.results.results = Array.from({ length: LIMITS.maxResults }, () => minimal);
  assert.equal(parsed(invoke(max)).summary.unknown, LIMITS.maxResults);
  max.results.results.push(minimal); rejected(invoke(max), 'structure_limit');
});

test('grammar accepts valid escaped strings and primitive subtrees without copying their values', () => {
  const value = fixture(); value.config = { values: [null, true, false, 0, -0.3, 1e8, 'quote" slash\\ tab\t newline\n unicodeé🙂'] };
  parsed(invoke(value));
  const escaped = JSON.stringify(value).replace('quote\\"', '\\u0071uote\\"');
  parsed(importPromptfooJson(escaped, INPUT_CONTRACT));
});

test('file CLI imports only bounded regular UTF-8 files and keeps path failures private', async () => {
  await temporary(async directory => {
    const path = join(directory, 'secret-path.json'), link = join(directory, 'link.json');
    await writeFile(path, fixtureText);
    assert.deepEqual(await importLocalFile(path, INPUT_CONTRACT), importPromptfooJson(fixtureText, INPUT_CONTRACT));
    await symlink(path, link); rejected(await importLocalFile(link, INPUT_CONTRACT), 'invalid_file');
    rejected(await importLocalFile(directory, INPUT_CONTRACT), 'invalid_file');
    rejected(await importLocalFile(join(directory, 'missing-secret-path'), INPUT_CONTRACT), 'invalid_file');
    for (const path of ['https://synthetic.invalid/private', 'file:///secret-path', '', 'x\0y']) rejected(await importLocalFile(path, INPUT_CONTRACT), 'invalid_file');
    await writeFile(path, Buffer.from([0x7b, 0xff, 0x7d])); rejected(await importLocalFile(path, INPUT_CONTRACT), 'invalid_utf8');
    await writeFile(path, Buffer.alloc(LIMITS.maxBytes + 1)); rejected(await importLocalFile(path, INPUT_CONTRACT), 'input_limit');
  });
});

test('CLI process outputs only normalized JSON or safe stderr, with no writes', async () => {
  const run = promisify(execFile), cli = join(owned, 'cli.mjs');
  await temporary(async directory => {
    const good = await run(process.execPath, [cli, '--format', INPUT_CONTRACT, '--input', fixturePath], { timeout: 10000, cwd: directory });
    assert.equal(good.stderr, '');
    assert.deepEqual(JSON.parse(good.stdout), parsed(importPromptfooJson(fixtureText, INPUT_CONTRACT)));
    await assert.rejects(run(process.execPath, [cli, '--format', INPUT_CONTRACT, '--input', join(directory, 'missing-secret-path')], { timeout: 10000, cwd: directory }), error => {
      assert.equal(error.code, 2); assert.equal(error.stdout, ''); rejected(JSON.parse(error.stderr), 'invalid_file'); return true;
    });
    assert.deepEqual(await readdir(directory), []);
  });
  for (const args of [[], ['--input', fixturePath], ['--format', INPUT_CONTRACT, '--input', fixturePath, '--output', 'secret-path']]) rejected(await main(args), 'usage');
});

test('external envelope cannot be stored or compared as a native run and makes no repair claim', async () => {
  const preview = parsed(importPromptfooJson(fixtureText, INPUT_CONTRACT));
  assert.equal(preview.schemaVersion, undefined);
  assert.equal(preview.results, undefined);
  assert.equal(preview.applicationId, undefined);
  assert.equal(preview.id, undefined);
  assert.equal(preview.trust.nativeAssessment, false);
  assert.equal(preview.trust.signatureVerified, false);
  assert.equal(preview.trust.repairVerification, 'not-assessed');
  // Current native API assumes native inputs and throws for a preview. It must
  // never receive this envelope in product integration, even for comparison.
  assert.throws(() => compareRuns(preview, preview));
  await temporary(async directory => {
    const store = createStore(join(directory, 'native-rejection'));
    await store.ready;
    await assert.rejects(store.save(preview), /Invalid run evidence format/);
    assert.deepEqual(await store.list(), []);
  });
});

async function previewServer(fn) {
  await temporary(async directory => {
    let assessments = 0;
    const token = 'SYNTHETIC_IMPORT_ACCESS_TOKEN_000000000000';
    const app = await startServer({ port: 0, dataDir: join(directory, 'api-store'), profiles: [], env: {}, accessToken: token,
      assess: async () => { assessments++; throw new Error('Synthetic assessment must not run during import.'); } });
    const headers = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', 'X-Scopehaven-Request': '1' };
    const post = (input, overrides = {}) => fetch(`${app.origin}/api/external-evaluations/preview`, {
      method: 'POST', headers: { ...headers, ...overrides }, body: typeof input === 'string' || Buffer.isBuffer(input) ? input : JSON.stringify(input), signal: AbortSignal.timeout(5000),
    });
    try {
      await fn({ app, headers, post, directory, token });
      assert.equal(assessments, 0, 'Preview must not execute native or provider assessments.');
      assert.deepEqual(await app.store.list(), [], 'Preview must not persist a native run.');
      assert.deepEqual(await readdir(join(directory, 'api-store', 'runs')), []);
      assert.deepEqual(await readdir(join(directory, 'api-store', 'notes')), []);
    } finally { await app.close(); }
  });
}

test('authenticated HTTP preview preserves exact source digest and external states without native history or assessment', async () => {
  await previewServer(async ({ app, headers, post, token }) => {
    const bootstrap = await (await fetch(`${app.origin}/api/bootstrap`, { headers })).json();
    assert.deepEqual(bootstrap.capabilities.externalPreview, { format: INPUT_CONTRACT, maxBytes: LIMITS.maxBytes, retained: false });
    const response = await post({ format: INPUT_CONTRACT, content: fixtureText });
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('cache-control'), 'no-store');
    assert.match(response.headers.get('content-security-policy'), /default-src 'none'/);
    const text = await response.text(), result = JSON.parse(text);
    assert.deepEqual(result, importPromptfooJson(fixtureText, INPUT_CONTRACT));
    assert.doesNotMatch(text, /SYNTHETIC_PRIVATE_SENTINEL|https?:\/\/|<script/);
    assert.equal(text.includes(token), false);
    assert.equal(result.record.trust.repairVerification, 'not-assessed');
    assert.deepEqual(result.record.summary, { total: 4, pass: 1, fail: 1, error: 1, unknown: 1 });
    const history = await (await fetch(`${app.origin}/api/history`, { headers })).json();
    assert.equal(history.total, 0); assert.deepEqual(history.runs, []);
    const attemptToPromote = await fetch(`${app.origin}/api/runs`, { method: 'POST', headers, body: JSON.stringify(result.record) });
    assert.equal(attemptToPromote.status, 400);
  });
});

test('HTTP preview authenticates before import and safely rejects malformed, hostile and non-text source payloads', async () => {
  await previewServer(async ({ app, post, token }) => {
    for (const [overrides, expected] of [[{ Authorization: '' }, 401], [{ Authorization: 'Bearer wrong' }, 401], [{ 'X-Scopehaven-Request': '' }, 403], [{ Origin: 'https://synthetic.invalid' }, 403], [{ 'Content-Type': 'text/plain' }, 415]]) {
      const response = await post('SYNTHETIC_PRIVATE_SENTINEL malformed', overrides);
      assert.equal(response.status, expected); assert.doesNotMatch(await response.text(), /SYNTHETIC_PRIVATE_SENTINEL|Bearer|wrong/);
    }
    const cases = [
      { content: fixtureText },
      { format: INPUT_CONTRACT, content: fixture() },
      { format: 'unknown', content: fixtureText },
      { format: INPUT_CONTRACT, content: fixtureText + 'SYNTHETIC_PRIVATE_SENTINEL' },
      { format: INPUT_CONTRACT, content: '{"a":1,"a":2}' },
      { format: INPUT_CONTRACT, content: '{"__proto__":{"polluted":"SYNTHETIC_PRIVATE_SENTINEL"}}' },
      { format: INPUT_CONTRACT, content: fixtureText, path: '/SYNTHETIC_PRIVATE_SENTINEL' },
      { format: INPUT_CONTRACT, url: 'https://synthetic.invalid/SYNTHETIC_PRIVATE_SENTINEL' },
      Buffer.from([0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d]),
    ];
    for (const input of cases) {
      const response = await post(input); assert.equal(response.status, 400);
      const text = await response.text(); assert.doesNotMatch(text, /SYNTHETIC_PRIVATE_SENTINEL|https?:\/\/|<script/);
      assert.equal(text.includes(token), false);
      const error = JSON.parse(text); assert.equal(typeof error.error, 'string'); assert.equal(error.record, undefined);
    }
    assert.equal({}.polluted, undefined);
    const stillReady = await post({ format: INPUT_CONTRACT, content: fixtureText });
    assert.equal(stillReady.status, 200); await stillReady.arrayBuffer();
  });
});

test('HTTP preview enforces decoded source bounds and accepts a complete source at its byte limit', async () => {
  await previewServer(async ({ post }) => {
    const padded = fixtureText + ' '.repeat(LIMITS.maxBytes - Buffer.byteLength(fixtureText));
    const accepted = await post({ format: INPUT_CONTRACT, content: padded });
    assert.equal(accepted.status, 200);
    const result = await accepted.json();
    assert.equal(result.record.provenance.sourceBytes, LIMITS.maxBytes);
    assert.equal(result.record.provenance.sourceDigest.value, createHash('sha256').update(padded).digest('hex'));
    for (const content of [padded + ' ', fixtureText.replace('SYNTHETIC_PRIVATE_SENTINEL', 'é'.repeat(LIMITS.maxStringBytes))]) {
      const response = await post({ format: INPUT_CONTRACT, content });
      assert.equal(response.status, content === padded + ' ' ? 413 : 400);
      const error = await response.json(); assert.equal(error.ok, false); assert.equal(error.record, undefined);
      assert.equal(typeof error.code, 'string');
    }
  });
});

test('HTTP preview bounds the transport body and remains usable after rejection', async () => {
  await previewServer(async ({ post }) => {
    const oversized = JSON.stringify({ format: INPUT_CONTRACT, content: ' '.repeat(2 * LIMITS.maxBytes) });
    const response = await post(oversized);
    assert.equal(response.status, 413);
    const error = await response.json();
    assert.equal(typeof error.error, 'string');
    assert.equal(error.record, undefined);
    const retry = await post({ format: INPUT_CONTRACT, content: fixtureText });
    assert.equal(retry.status, 200);
    assert.equal((await retry.json()).record.summary.total, 4);
  });
});

test('HTTP preview runs one at a time: a concurrent preview gets 429 with a retry message before its body is read', async () => {
  await previewServer(async ({ app, headers, post }) => {
    const { request } = await import('node:http');
    const url = `${app.origin}/api/external-evaluations/preview`;
    // A raw request whose body the test controls: headers go out at once, the body only when the test writes it.
    const raw = length => {
      const req = request(url, { method: 'POST', headers: { ...headers, 'Content-Length': String(length) } });
      const response = new Promise((resolve, reject) => {
        req.on('response', res => { let text = ''; res.setEncoding('utf8'); res.on('data', chunk => { text += chunk; }); res.on('end', () => resolve({ status: res.statusCode, retryAfter: res.headers['retry-after'], body: text ? JSON.parse(text) : null })); });
        req.on('error', reject);
      });
      req.flushHeaders();
      return { req, response };
    };
    const within = (promise, ms, label) => Promise.race([promise, new Promise((_, reject) => setTimeout(() => reject(new Error(`${label} did not answer within ${ms} ms`)), ms))]);
    const full = Buffer.from(JSON.stringify({ format: INPUT_CONTRACT, content: fixtureText }));
    // Hold a first preview mid-body, then send a second whose body never comes: it must be answered at once, so the
    // server never waits to read it. Repeat until the first preview has reached the server.
    const first = raw(full.length); first.req.write(full.subarray(0, full.length >> 1));
    let refused = null;
    for (let attempt = 0; attempt < 100 && !refused; attempt++) {
      const second = raw(full.length);
      const answer = await within(second.response, 2000, 'the second preview');
      second.req.destroy();
      if (answer.status === 429) refused = answer;
      else await new Promise(resolve => setTimeout(resolve, 20));
    }
    assert(refused, 'a concurrent preview was refused');
    assert.deepEqual(refused.body, { error: 'Another external evaluation preview is running. Try again after it finishes.', code: 'preview-in-progress' });
    assert.equal(refused.retryAfter, '1');
    // The held preview still completes, and the slot is free again afterwards.
    first.req.end(full.subarray(full.length >> 1));
    const done = await within(first.response, 5000, 'the held preview');
    assert.equal(done.status, 200); assert.equal(done.body.record.summary.total, 4);
    const after = await post({ format: INPUT_CONTRACT, content: fixtureText });
    assert.equal(after.status, 200);
    // A preview whose client goes away mid-body frees the slot too.
    const abandoned = raw(full.length); abandoned.req.write(full.subarray(0, 10)); abandoned.response.catch(() => {});
    await new Promise(resolve => setTimeout(resolve, 50)); abandoned.req.destroy();
    let freed = false;
    for (let attempt = 0; attempt < 100 && !freed; attempt++) {
      const retry = await post({ format: INPUT_CONTRACT, content: fixtureText });
      freed = retry.status === 200; await retry.arrayBuffer();
      if (!freed) await new Promise(resolve => setTimeout(resolve, 20));
    }
    assert(freed, 'an abandoned preview releases the slot');
  });
});

test('actual dashboard adapter reaches authenticated preview without altering source bytes or converting external verdicts', async () => {
  await previewServer(async ({ app, headers }) => {
    let requests = 0;
    const adapter = createDashboardAdapter({
      request: async (path, input) => {
        assert.equal(path, '/api/external-evaluations/preview'); requests++;
        const response = await fetch(`${app.origin}${path}`, { method: 'POST', headers, body: JSON.stringify(input), signal: AbortSignal.timeout(5000) });
        const result = await response.json();
        if (!response.ok) throw Object.assign(new Error(result.error), { status: response.status, code: result.code });
        return result;
      },
      download: () => { assert.fail('External preview cannot invoke native export.'); },
    });
    assert.equal(EXTERNAL_PREVIEW_FORMAT, INPUT_CONTRACT);
    assert.equal(EXTERNAL_PREVIEW_MAX_BYTES, LIMITS.maxBytes);
    const result = await adapter.previewExternal(fixtureText);
    assert.deepEqual(result, importPromptfooJson(fixtureText, INPUT_CONTRACT));
    assert.equal(result.record.trust.nativeAssessment, false);
    assert.equal(result.record.trust.repairVerification, 'not-assessed');
    assert.deepEqual(result.record.checks.map(check => check.state), ['pass', 'fail', 'error', 'unknown']);
    await assert.rejects(adapter.previewExternal('{"a":1,"a":2}'), { status: 400, code: 'duplicate_key' });
    assert.equal(requests, 2);
    assert.throws(() => adapter.previewExternal('x'.repeat(LIMITS.maxBytes + 1)), { status: 413 });
    assert.equal(requests, 2, 'Oversized source must be rejected before transport.');
  });
});
