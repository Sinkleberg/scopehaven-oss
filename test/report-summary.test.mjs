import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, stat, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { runAssessment } from '../src/runner.mjs';
import { createStore } from '../src/store.mjs';
import { renderReport, CUSTODY_RULE } from '../src/report.mjs';
import { CONTROL_CUSTODY_LIMIT } from '../src/custody.mjs';
import { renderSummary, SUMMARY_LIMITS } from '../src/report-summary.mjs';
import { residualDocument } from '../src/residual.mjs';
import { exportRun } from '../src/export-cli.mjs';
import { generateSigningKey, signFiles } from '../integrations/attest/sign.mjs';
import { verifyEnvelope } from '../integrations/attest/verify.mjs';
import packageInfo from '../package.json' with { type: 'json' };

// Owned synthetic loopback fixture only. Files stay in fresh private temporary directories.
const vulnerable = await runAssessment('demo-vulnerable');
const repaired = await runAssessment('demo-repaired');
const copy = value => structuredClone(value);
async function dir(t) { const d = await mkdtemp(join(tmpdir(), 'scopehaven-summary-')); t.after(() => rm(d, { recursive: true, force: true })); return d; }

// Plants a unique value in every string leaf of every result (fixture records, request data, observed
// values, assertion evidence, titles, remediation) except the id and status the summary is allowed to read,
// and in the human notes. Returns the run and the planted values with their paths.
function planted(run) {
  const out = copy(run), canaries = [];
  const plant = (value, path) => {
    if (typeof value === 'string') { const canary = `CANARY${randomBytes(6).toString('hex')}`; canaries.push({ canary, path }); return `${value} ${canary}`; }
    if (Array.isArray(value)) return value.map((item, index) => plant(item, `${path}.${index}`));
    if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, plant(item, `${path}.${key}`)]));
    return value;
  };
  out.results = out.results.map(row => { const { id, status, ...rest } = row; return { id, status, ...plant(rest, row.id) }; });
  out.notes = Object.fromEntries(out.results.map(row => [row.id, { note: plant('reviewer note', `notes.${row.id}`) }]));
  return { run: out, canaries };
}

test('the summary carries scope, counts, what was not tested, custody and how to verify', () => {
  const html = renderSummary(vulnerable);
  assert.match(html, /<strong>Owned synthetic fixture\. No live language model or customer system assessed\.<\/strong>/);
  assert.match(html, /<td>44<\/td><td>18<\/td><td>26<\/td><td>0<\/td><td>0<\/td><td>0<\/td>/);
  assert.match(html, /<th>Checks listed<\/th>/);
  assert.doesNotMatch(html, /Checks run/);
  assert.match(html, /<h2>What was not tested<\/h2><ul><li>/);
  assert.match(html, /Observed-effect clause custody: not recorded for this run\./);
  assert.match(html, /Ledger anchor custody: not supplied\./);
  assert(html.includes(CUSTODY_RULE));
  assert(html.includes(CONTROL_CUSTODY_LIMIT));
  assert.match(html, new RegExp(`Evidence integrity sha256 ${vulnerable.integrity?.sha256 ?? 'not recorded'}\\.`));
  assert.match(html, /node integrations\/attest\/cli\.mjs verify --key KEY\.pub\.pem --envelope ENVELOPE\.dsse\.json --dir DIR/);
  assert.match(html, /not a safety certification/);
  assert.match(html, /default-src 'none'/);
  assert.doesNotMatch(html, /<script|<img|<link|@import|url\(/i);
});

test('planted canaries in records, request data, evidence and notes never reach the summary', () => {
  const { run, canaries } = planted(vulnerable);
  assert(canaries.length > 1000, `planted ${canaries.length}`);
  assert(canaries.some(({ path }) => /\.trace\..*\.data\.(before|after)\./.test(path)), 'fixture records planted');
  assert(canaries.some(({ path }) => /\.trace\..*\.data\.(requestId|actor)/.test(path)), 'request data planted');
  const report = renderReport(run), summary = renderSummary(run);
  assert(canaries.filter(({ canary }) => report.includes(canary)).length > 100, 'positive control: the full report shows planted values');
  assert.deepEqual(canaries.filter(({ canary }) => summary.includes(canary)), []);
  assert.doesNotMatch(summary, /CANARY[0-9a-f]{12}/);
});

test('ledger anchor custody is caller-supplied and separate from the run assertion tags', () => {
  const anchors = [{ source: 'smtp-sink', custody: 'observer-held' }, { source: 'sql-snapshot', custody: 'subject-writable' }];
  assert.match(renderSummary(vulnerable, { custody: anchors }), /Ledger anchor custody: subject-writable \(weakest of 2 caller-supplied anchors: smtp-sink observer-held, sql-snapshot subject-writable\)\./);
  assert.match(renderSummary(vulnerable, { custody: [{ source: 'egress-recorder', custody: 'independent' }] }), /Ledger anchor custody: independent \(weakest of 1 caller-supplied anchor: egress-recorder independent\)\./);
  assert.match(renderSummary(vulnerable, { custody: [{ source: 'x', custody: 'certain' }] }), /Ledger anchor custody: 1 of 1 caller-supplied anchor is unrecognized or malformed; no aggregate grade is reported\./);
  for (const invalid of [{ source: 'PRIVATE-INVALID', custody: 'PRIVATE-GRADE' }, { custody: 'independent' }, null, { source: '', custody: 'independent' }]) {
    const html = renderSummary(vulnerable, { custody: [{ source: 'sink', custody: 'independent' }, invalid] });
    assert.match(html, /1 of 2 caller-supplied anchors is unrecognized or malformed; no aggregate grade is reported\./);
    assert.doesNotMatch(html, /Ledger anchor custody: independent|PRIVATE-INVALID|PRIVATE-GRADE/);
  }
  assert.match(renderSummary(vulnerable, { custody: 'PRIVATE-INPUT' }), /Ledger anchor custody: unrecognized input; no aggregate grade is reported\./);
  const run = copy(vulnerable);
  run.results[0].assertions.push({ name: 'private clause', actual: 'private record', custody: 'subject-writable' });
  const html = renderSummary(run, { custody: [{ source: 'egress-recorder', custody: 'independent' }] });
  assert.match(html, /Observed-effect clause custody: 1 subject-writable\./);
  assert(html.includes(CUSTODY_RULE));
  assert(html.includes(CONTROL_CUSTODY_LIMIT));
  assert.doesNotMatch(html, /private clause|private record/);
  assert.equal(run.results[0].status, vulnerable.results[0].status, 'the summary never changes a verdict');
});

test('long limitation and not-applicable lists retain whole entries within the compact summary budgets', () => {
  const run = copy(vulnerable);
  run.limitations = Array.from({ length: 20 }, (_, i) => `Limitation ${i} ${'x'.repeat(400)}`);
  run.results = run.results.map((row, index) => index < 30 ? { ...row, status: 'not_applicable' } : row);
  const html = renderSummary(run), each = run.limitations[0].length, fit = Math.floor(SUMMARY_LIMITS.limitationChars / each);
  assert.match(html, /<th>Checks listed<\/th>/);
  assert.doesNotMatch(html, /Checks run/);
  assert.equal((html.match(/<li>Limitation \d+ x+<\/li>/g) || []).length, fit, 'whole limitations only');
  for (const line of run.limitations.slice(0, fit)) assert(html.includes(`<li>${line}</li>`), 'each shown limitation is complete');
  const real = renderSummary(vulnerable);
  assert(real.includes(`<li>${vulnerable.limitations[0]}</li>`), 'the first real limitation is shown whole');
  assert.match(html, new RegExp(`<li>${20 - fit} further limitations are listed in the full report\\.</li>`));
  assert.match(html, /Not applicable to this target: [A-Z0-9, -]+ and 18 more\./);
  const huge = copy(vulnerable); huge.limitations = ['y'.repeat(SUMMARY_LIMITS.limitationChars + 1)];
  assert.match(renderSummary(huge), /<li>1 limitation is listed in the full report\.<\/li>/);
  assert.doesNotMatch(renderSummary(huge), /yyyy|No limitation was recorded/);
});

test('the summary is an attest subject: a signed summary verifies and a changed byte is rejected', () => {
  const key = generateSigningKey(), content = Buffer.from(renderSummary(vulnerable));
  const { envelope } = signFiles([{ name: 'summary.html', content }], { privateKey: key.privatePem, version: packageInfo.version });
  const ok = verifyEnvelope({ envelope, publicKey: key.publicPem, files: new Map([['summary.html', content]]) });
  assert.equal(ok.verified, true); assert.equal(ok.verdict, 'verified');
  const changed = Buffer.from(content); changed[changed.length - 10] ^= 1;
  const bad = verifyEnvelope({ envelope, publicKey: key.publicPem, files: new Map([['summary.html', changed]]) });
  assert.equal(bad.verified, false); assert.equal(bad.verdict, 'rejected');
});

test('summary wording: never compliant, satisfies or certified', () => {
  for (const run of [vulnerable, repaired]) assert.doesNotMatch(renderSummary(run), /\bcomplian(t|ce)\b|\bsatisf(y|ies|ied)\b|\bcertified\b/i, run.targetId);
});

test('export --format summary writes a private, exclusive file like the other formats', async t => {
  const root = await dir(t), data = join(root, 'store'), out = join(root, 'exports');
  const store = createStore(data); await store.ready;
  const saved = await store.save(copy(vulnerable));
  await mkdir(out, { mode: 0o700 });
  const file = join(out, 'summary.html');
  const result = await exportRun({ runId: saved.id, format: 'summary', outputFile: file, dataDir: data });
  assert.equal(result.format, 'summary');
  assert.equal((await stat(file)).mode & 0o777, 0o600);
  // The export hands the page the residual it computes from the run (src/residual.mjs); the page itself reads no trace.
  const stored = await store.get(saved.id), expected = renderSummary(stored, { residual: residualDocument(stored) });
  assert.equal(await readFile(file, 'utf8'), expected);
  await assert.rejects(exportRun({ runId: saved.id, format: 'summary', outputFile: file, dataDir: data }));
  assert.equal(await readFile(file, 'utf8'), expected, 'an existing export stays intact');
  await assert.rejects(exportRun({ runId: saved.id, baselineRunId: saved.id, format: 'summary', outputFile: join(out, 'comparison-summary.html'), dataDir: data }), /Invalid export options/);
});

test('the HTML report has a print cover with identities, the findings, and a closing limits section', () => {
  const html = renderReport(vulnerable);
  const cover = html.indexOf('<section class="cover">'), first = html.indexOf('<article>'), limits = html.indexOf('<section class="limits">');
  assert(cover >= 0 && cover < first && first < limits, 'cover, findings, limits in order');
  const coverHtml = html.slice(cover, html.indexOf('</section>', cover));
  for (const label of ['Run', 'Suite hash', 'Policy hash', 'Fixture hash', 'Evaluator hash']) assert.match(coverHtml, new RegExp(`<tr><th>${label}</th><td>`), label);
  assert.match(coverHtml, new RegExp(`<td>${vulnerable.suiteHash}</td>`));
  const print = html.slice(html.indexOf('@media print{'), html.indexOf('</style>'));
  assert(print.includes('.cover{break-after:page}.limits,.residual{break-before:page}'), 'print CSS breaks after the cover and before the residual and the limits');
  const limitsHtml = html.slice(limits);
  for (const line of vulnerable.limitations) assert(limitsHtml.includes(line.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c])), line);
  assert.match(limitsHtml, /<h2>Scope and provenance<\/h2><pre>/);
  assert(limitsHtml.includes('These are observed checks, not a safety certification.'));
});

test('the summary omits detail fields without reading them and explicitly retains metadata', () => {
  const run = copy(vulnerable), row = { id: 'CHECK-PRIVATE', status: 'inconclusive', severity: 'control', assertions: [{ custody: null }] };
  const unread = label => ({ get() { throw new Error(`summary read ${label}`); } });
  for (const key of ['title', 'observed', 'trace', 'remediation']) Object.defineProperty(row, key, unread(key));
  for (const key of ['name', 'actual', 'custodyReason', 'custodyUpgrade']) Object.defineProperty(row.assertions[0], key, unread(`assertion.${key}`));
  Object.defineProperty(run, 'notes', unread('notes'));
  run.results = [row]; run.targetName = 'Retained target <private>'; run.scopeLabel = 'Retained scope'; run.limitations = ['Retained limitation'];
  const html = renderSummary(run);
  assert(html.includes('Retained target &lt;private&gt;'));
  for (const text of ['Retained scope', 'Retained limitation', 'CHECK-PRIVATE', 'this summary is not anonymized', 'Observed-effect clause custody: 1 no observer decided.']) assert(html.includes(text), text);
  assert(html.includes(CUSTODY_RULE)); assert(html.includes(CONTROL_CUSTODY_LIMIT));
  assert.doesNotMatch(html, /Retained target <private>/);
});

test('new cover identity cells escape the same untrusted run metadata as provenance', () => {
  const run = { ...vulnerable, applicationId: '<img src=x onerror=alert(1)>', targetId: '<script>bad()</script>' };
  const html = renderReport(run), cover = html.slice(html.indexOf('<section class="cover">'), html.indexOf('</section>'));
  assert(cover.includes('&lt;img src=x onerror=alert(1)&gt;'));
  assert(cover.includes('&lt;script&gt;bad()&lt;/script&gt;'));
  assert.doesNotMatch(cover, /<img|<script/);
});

test('review: unrecognized custody tags are counted, held verdicts are counted, not-applicable never reads as passed, the cover names evidence integrity, and an anchor is read once', () => {
  // An unrecognized tag is reported as unrecognized, never dropped.
  const tagged = copy(vulnerable);
  tagged.results[0].assertions.push({ name: 'x', actual: 'y', custody: 'made-up-grade' });
  assert.match(renderSummary(tagged), /Observed-effect clause custody: 1 unrecognized\./);
  // An assertion carrying custodyReason counts as a verdict custody held at inconclusive; the reason text is never printed.
  const held = copy(vulnerable);
  held.results[0].assertions.push({ name: 'x', actual: 'y', custody: 'subject-writable', custodyReason: 'PRIVATE-REASON' });
  const heldHtml = renderSummary(held);
  assert.match(heldHtml, /1 clause verdict read inconclusive because only records the application can write decided it\./);
  assert.doesNotMatch(heldHtml, /PRIVATE-REASON/);
  // A not-applicable row is counted in its own column, never as passed.
  const na = copy(vulnerable), passedBefore = na.results.filter(r => r.status === 'pass').length, firstPass = na.results.findIndex(r => r.status === 'pass');
  assert.ok(firstPass >= 0);
  na.results[firstPass] = { ...na.results[firstPass], status: 'not_applicable' };
  const cells = renderSummary(na).match(/<tbody><tr><td>(\d+)<\/td><td>(\d+)<\/td><td>(\d+)<\/td><td>(\d+)<\/td><td>(\d+)<\/td><td>(\d+)<\/td><\/tr>/);
  assert.deepEqual([Number(cells[2]), Number(cells[6])], [passedBefore - 1, 1]);
  // The cover carries the evidence integrity hash.
  const withIntegrity = copy(vulnerable); withIntegrity.integrity = { ...(withIntegrity.integrity ?? {}), sha256: 'a'.repeat(64) };
  const html = renderReport(withIntegrity), start = html.indexOf('<section class="cover">');
  assert(html.slice(start, html.indexOf('</section>', start)).includes(`<tr><th>Evidence integrity (sha256)</th><td>${'a'.repeat(64)}</td>`));
  // An accessor anchor is read once: it cannot validate as one grade and print as another.
  let reads = 0;
  const sneaky = { source: 'sink', get custody() { return reads++ === 0 ? 'subject-writable' : 'independent'; } };
  assert.match(renderSummary(vulnerable, { custody: [sneaky] }), /Ledger anchor custody: subject-writable \(weakest of 1 caller-supplied anchor: sink subject-writable\)\./);
});
