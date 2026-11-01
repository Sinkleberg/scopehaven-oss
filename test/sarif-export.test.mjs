import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile, readdir, stat, symlink, chmod, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { runAssessment } from '../src/runner.mjs';
import { createStore } from '../src/store.mjs';
import { SUITE, POLICY_HASH, FIXTURE_HASH, digest } from '../src/suite.mjs';
import { renderSarif, serializeSarif, validateStandardsMap, validateSuppliedStandardsMap, SARIF_VERSION, MAPPING_STATEMENT } from '../src/sarif.mjs';
import { exportRun, main } from '../src/export-cli.mjs';
import standardsMap from '../src/standards-map.json' with { type: 'json' };
import vocabularies from '../src/standards-vocabularies.json' with { type: 'json' };
import cweUsage from './fixtures/cwe-4.20-mapping-usage.json' with { type: 'json' };

// Owned synthetic loopback fixture only. No model, provider, hosted service or
// network destination beyond ephemeral 127.0.0.1 ports. Files stay in fresh
// private temporary directories. One local child process proves that a changed
// standards map leaves suite and policy hashes unchanged.
const vulnerable = await runAssessment('demo-vulnerable');
const repaired = await runAssessment('demo-repaired');
const copy = value => structuredClone(value);
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
async function dir(t) { const d = await mkdtemp(join(tmpdir(), 'scopehaven-sarif-')); t.after(() => rm(d, { recursive: true, force: true })); return d; }

const KINDS = ['notApplicable', 'pass', 'fail', 'review', 'open', 'informational'];
const LEVELS = ['none', 'note', 'warning', 'error'];
const REQUIRED_RUN_PROPERTIES = ['runId', 'suiteHash', 'policyHash', 'applicationId', 'fixtureVersion', 'build', 'targetId', 'scope', 'certification', 'evidenceIntegrity', 'standardsMap'];
const LOCAL_PATH = /\/Users\/|\/home\/|\/private\/|\/var\/folders\/|\/tmp\/|[A-Za-z]:\\\\/;

/** Structural checks for the SARIF 2.1.0 subset this exporter emits. Not a JSON-schema validation. */
function validateSarifStructure(log) {
  assert.equal(JSON.stringify(JSON.parse(JSON.stringify(log))), JSON.stringify(log), 'pure JSON values only');
  assert.equal(log.version, '2.1.0'); assert.equal(typeof log.$schema, 'string'); assert.match(log.$schema, /^https:\/\/.+sarif-2\.1\.0\.json$/);
  assert(Array.isArray(log.runs) && log.runs.length === 1);
  const [run] = log.runs, driver = run.tool?.driver;
  assert.equal(driver.name, 'Scopehaven'); assert.equal(typeof driver.version, 'string'); assert.equal(driver.informationUri, undefined);
  assert(Array.isArray(driver.rules) && driver.rules.length > 0);
  assert.equal(new Set(driver.rules.map(rule => rule.id)).size, driver.rules.length, 'unique rule ids');
  for (const rule of driver.rules) {
    assert.equal(typeof rule.id, 'string'); assert(rule.shortDescription.text.length > 0); assert(rule.fullDescription.text.length > 0); assert(rule.help.text.length > 0);
    assert(LEVELS.includes(rule.defaultConfiguration.level)); assert(Array.isArray(rule.properties.tags));
    for (const relation of rule.relationships || []) {
      const taxonomy = run.taxonomies?.[relation.target.toolComponent.index];
      assert(taxonomy && taxonomy.name === relation.target.toolComponent.name, 'relationship names an existing taxonomy');
      assert.equal(taxonomy.taxa[relation.target.index]?.id, relation.target.id, 'relationship names an existing taxon');
      assert.deepEqual(relation.kinds, ['relevant']);
    }
  }
  for (const taxonomy of run.taxonomies || []) { assert.equal(typeof taxonomy.name, 'string'); assert.equal(new Set(taxonomy.taxa.map(taxon => taxon.id)).size, taxonomy.taxa.length); }
  assert(Array.isArray(run.logicalLocations));
  run.logicalLocations.forEach((location, index) => { if (location.parentIndex !== undefined) assert(location.parentIndex >= 0 && location.parentIndex < index); });
  assert(Array.isArray(run.invocations) && run.invocations.length === 1 && typeof run.invocations[0].executionSuccessful === 'boolean');
  for (const notification of run.invocations[0].toolExecutionNotifications || []) {
    assert(LEVELS.includes(notification.level)); assert(notification.message.text.length > 0); assert.equal(driver.rules[notification.associatedRule.index].id, notification.associatedRule.id);
  }
  assert(Array.isArray(run.results));
  for (const result of run.results) {
    assert.equal(driver.rules[result.ruleIndex].id, result.ruleId, 'ruleIndex agrees with ruleId');
    assert(KINDS.includes(result.kind)); assert(LEVELS.includes(result.level));
    if (result.kind !== 'fail') assert.equal(result.level, 'none', 'SARIF requires level none unless kind is fail');
    else assert.notEqual(result.level, 'none');
    assert.equal(typeof result.message.text, 'string'); assert(result.message.text.length > 0);
    const [logical] = result.locations[0].logicalLocations;
    assert.equal(run.logicalLocations[logical.index].fullyQualifiedName, logical.fullyQualifiedName);
    assert.equal(logical.name, result.ruleId);
    assert.equal(result.locations[0].physicalLocation, undefined, 'no source location is claimed');
  }
  for (const key of REQUIRED_RUN_PROPERTIES) assert(Object.hasOwn(run.properties, key), `run.properties.${key}`);
  assert.doesNotMatch(JSON.stringify(log), LOCAL_PATH);
  return run;
}

test('SARIF export is structurally valid 2.1.0 with identity, scope and standards tags', () => {
  for (const source of [vulnerable, repaired]) {
    const run = validateSarifStructure(renderSarif(source));
    assert.equal(run.tool.driver.rules.length, source.results.length); assert.equal(run.results.length, source.results.length);
    for (const key of ['suiteHash', 'policyHash', 'applicationId', 'fixtureVersion', 'fixtureHash', 'build', 'targetBuildHash', 'evaluatorHash', 'profileHash', 'evidenceOrigin']) assert.equal(run.properties[key], source[key], key);
    assert.equal(run.properties.runId, source.id); assert.equal(run.properties.suiteHash, SUITE.hash); assert.equal(run.properties.policyHash, POLICY_HASH);
    assert.equal(run.properties.scope, 'Owned synthetic fixture. No live language model or customer system assessed.');
    assert.match(run.properties.certification, /not a safety certification/);
    assert.deepEqual(run.properties.requiredControlIds, source.requiredControlIds);
    assert.equal(run.automationDetails.id, `scopehaven/${source.applicationId}/${source.suiteId}/${source.id}`);
    assert.equal(run.properties.standardsMap.appliedToSuite, SUITE.id);
  }
  const before = renderSarif(vulnerable).runs[0], after = renderSarif(repaired).runs[0];
  assert.equal(before.results.filter(result => result.kind === 'fail').length, 26);
  assert(before.results.filter(result => result.kind === 'fail').every(result => result.level === 'error' && /^FAIL: /.test(result.message.text) && /Failed assertions: /.test(result.message.text)));
  assert.equal(before.results.filter(result => result.kind === 'pass').length, 18);
  assert(after.results.every(result => result.kind === 'pass' && result.level === 'none'));
  assert.equal(after.invocations[0].executionSuccessful, true);
  const tenant = before.tool.driver.rules.find(rule => rule.id === 'TENANT-01');
  assert.deepEqual(tenant.properties.standards, { owaspLlm2025: ['LLM02:2025'], cwe: ['CWE-639', 'CWE-200'], owaspAgentic2026: ['ASI03'], owaspAgentic2026Rationale: "The agent uses its own access to retrieve another tenant's record for the user.",
    owaspLlm2026: ['LLM02:2026'], mitreAtlas: ['AML.T0057', 'AML.T0085.001'], mitreAtlasRationale: "The request has the agent's tools fetch another tenant's record and return it to the user." });
  assert(tenant.properties.tags.includes('external/cwe/cwe-639') && tenant.properties.tags.includes('security'));
  const control = before.tool.driver.rules.find(rule => rule.id === 'ALLOWED-01');
  assert.equal(control.relationships, undefined); assert.deepEqual(control.properties.tags, ['allowed-use-control']);
  // Same check identity across baseline and repaired builds.
  assert.deepEqual(before.results.map(result => result.fingerprints), after.results.map(result => result.fingerprints));
});

test('OWASP agentic 2026 tags are pinned, rationalised, never on controls and never ASI10', () => {
  const run = renderSarif(vulnerable).runs[0];
  const rule = id => run.tool.driver.rules.find(entry => entry.id === id);
  const agentic = run.taxonomies.find(taxonomy => taxonomy.name === 'OWASP Top 10 for Agentic Applications');
  assert(agentic, 'agentic taxonomy present'); assert.equal(agentic.version, '2026'); assert.equal(agentic.organization, 'OWASP');
  assert(agentic.taxa.every(taxon => /^ASI(0[1-9]|10)$/.test(taxon.id)));
  assert.equal(agentic.taxa.some(taxon => taxon.id === 'ASI10'), false);
  for (const [id, asi] of [['MIDTASK-01', 'ASI03'], ['UNTRUSTED-01', 'ASI01'], ['APPROVAL-01', 'ASI02'], ['TRUTH-01', 'ASI09']]) {
    const entry = rule(id);
    assert(entry.properties.tags.includes(`owasp-asi-2026-${asi.toLowerCase()}`), `${id} tag`);
    assert.deepEqual(entry.properties.standards.owaspAgentic2026, [asi]);
    assert.equal(typeof entry.properties.standards.owaspAgentic2026Rationale, 'string');
    assert(entry.relationships.some(link => link.target.id === asi && link.target.toolComponent.name === agentic.name));
  }
  for (const id of ['ALLOWED-01', 'MIDTASK-02', 'TRUTH-02']) {
    const entry = rule(id);
    assert.equal(entry.properties.tags.some(tag => tag.startsWith('owasp-asi-')), false, `${id} control untagged`);
  }
  const unmapped = rule('CONCURRENT-01');
  assert.deepEqual(unmapped.properties.standards.owaspAgentic2026, []);
  assert.equal(Object.hasOwn(unmapped.properties.standards, 'owaspAgentic2026Rationale'), false);
  // A mapping without a rationale, or an agentic tag on a control, is refused.
  const noRationale = copy(standardsMap); delete noRationale.suites[SUITE.id].checks['MIDTASK-01'].owaspAgentic2026Rationale;
  assert.throws(() => renderSarif(vulnerable, { standardsMap: noRationale }), /Invalid standards map/);
  const taggedControl = copy(standardsMap); taggedControl.suites[SUITE.id].checks['ALLOWED-01'].owaspAgentic2026 = ['ASI03']; taggedControl.suites[SUITE.id].checks['ALLOWED-01'].owaspAgentic2026Rationale = 'x';
  assert.throws(() => renderSarif(vulnerable, { standardsMap: taggedControl }), /Invalid standards map/);
  const badId = copy(standardsMap); badId.suites[SUITE.id].checks['MIDTASK-01'].owaspAgentic2026 = ['ASI11'];
  assert.throws(() => renderSarif(vulnerable, { standardsMap: badId }), /Invalid standards map/);
});

test('every saved outcome maps to an explicit SARIF kind and level without a pass claim', () => {
  const run = copy(vulnerable); run.id = '00000000-0000-4000-8000-000000000001';
  const set = (id, status) => { run.results.find(row => row.id === id).status = status; };
  set('TENANT-01', 'inconclusive'); set('ROLE-01', 'error'); set('REVOKE-01', 'not_applicable'); set('APPROVAL-01', 'unexpected-status');
  run.results.find(row => row.id === 'TENANT-01').assertions.push({ name: 'Complete request-correlated backend evidence', status: 'inconclusive', expected: 'x', actual: 'y' });
  const sarif = validateSarifStructure(renderSarif(run));
  const byId = id => sarif.results.find(result => result.ruleId === id);
  assert.deepEqual([byId('TENANT-01').kind, byId('TENANT-01').level, byId('TENANT-01').properties.scopehavenStatus], ['open', 'none', 'inconclusive']);
  assert.match(byId('TENANT-01').message.text, /^INCONCLUSIVE: .*Unverified assertions: Complete request-correlated backend evidence\.$/);
  assert.deepEqual([byId('ROLE-01').kind, byId('ROLE-01').level, byId('ROLE-01').properties.scopehavenStatus], ['open', 'none', 'error']);
  assert.deepEqual([byId('REVOKE-01').kind, byId('REVOKE-01').level], ['notApplicable', 'none']);
  assert.deepEqual([byId('APPROVAL-01').kind, byId('APPROVAL-01').level, byId('APPROVAL-01').properties.scopehavenStatus], ['review', 'none', 'unrecognized']);
  assert.equal(sarif.invocations[0].executionSuccessful, false);
  assert.deepEqual(sarif.invocations[0].toolExecutionNotifications.map(note => note.associatedRule.id), ['ROLE-01']);
  // A run that cannot be represented faithfully is refused rather than guessed.
  const duplicate = copy(vulnerable); duplicate.results[1].id = duplicate.results[0].id;
  assert.throws(() => renderSarif(duplicate), /unique check identifiers/);
  assert.throws(() => renderSarif({ ...copy(vulnerable), results: [] }), /saved native run/);
});

test('SARIF output is deterministic and excludes editable human notes', () => {
  const noted = { ...copy(repaired), notes: { 'TENANT-01': { note: 'Reviewer comment', updatedAt: '2026-10-04T00:00:00.000Z' } } };
  assert.equal(serializeSarif(repaired), serializeSarif(copy(repaired)));
  assert.equal(serializeSarif(noted), serializeSarif(repaired));
  assert.doesNotMatch(serializeSarif(noted), /Reviewer comment/);
  assert.equal(SARIF_VERSION, '2.1.0');
});

test('standards tags stay outside suite, policy and profile hashes', () => {
  // Hash inputs contain no tags, and only the SARIF exporter reads the map.
  assert.equal(digest({ id: SUITE.id, title: SUITE.title, version: SUITE.version, checks: SUITE.checks }), SUITE.hash);
  assert.doesNotMatch(JSON.stringify(SUITE), /CWE-|LLM(0[1-9]|10):/);
  const altered = copy(standardsMap); altered.mapVersion = 'altered';
  altered.suites[SUITE.id].checks['TENANT-01'] = { role: 'prohibited-behaviour', owaspLlm2025: ['LLM10:2025'], cwe: ['CWE-770'] };
  const original = renderSarif(repaired).runs[0], changed = renderSarif(repaired, { standardsMap: altered }).runs[0];
  for (const key of ['suiteHash', 'policyHash', 'fixtureHash', 'profileHash', 'evaluatorHash']) assert.equal(changed.properties[key], original.properties[key]);
  assert.deepEqual(changed.results.map(result => result.fingerprints), original.results.map(result => result.fingerprints));
  assert.notDeepEqual(changed.tool.driver.rules[0].properties.standards, original.tool.driver.rules[0].properties.standards);
  assert.notEqual(changed.properties.standardsMap.sha256, original.properties.standardsMap.sha256);
});

test('a changed standards-map.json file leaves fresh run hashes unchanged in a separate process', async () => {
  const sources = await readdir(new URL('../src/', import.meta.url));
  for (const name of sources.filter(file => file.endsWith('.mjs'))) {
    const source = await readFile(new URL(`../src/${name}`, import.meta.url), 'utf8');
    if (source.includes('standards-map') || source.includes('standards-vocabularies')) assert.equal(name, 'sarif.mjs', `${name} must not read the standards map or its vocabularies`);
  }
  const url = path => new URL(path, import.meta.url).href;
  const script = `
import { registerHooks } from 'node:module';
registerHooks({ load(url, context, nextLoad) {
  const result = nextLoad(url, context);
  if (!url.endsWith('/src/standards-map.json')) return result;
  const map = JSON.parse(Buffer.from(result.source).toString('utf8'));
  map.mapVersion = 'altered-in-child';
  map.suites['support-access-and-actions'].checks['TENANT-01'] = { role: 'prohibited-behaviour', owaspLlm2025: ['LLM10:2025'], cwe: ['CWE-770'] };
  return { ...result, source: JSON.stringify(map) };
} });
const { SUITE, POLICY_HASH, FIXTURE_HASH } = await import(${JSON.stringify(url('../src/suite.mjs'))});
const { runAssessment } = await import(${JSON.stringify(url('../src/runner.mjs'))});
const { renderSarif } = await import(${JSON.stringify(url('../src/sarif.mjs'))});
const run = await runAssessment('demo-repaired'), sarif = renderSarif(run).runs[0];
process.stdout.write(JSON.stringify({ suite: SUITE.hash, policy: POLICY_HASH, fixture: FIXTURE_HASH, runSuite: run.suiteHash, runPolicy: run.policyHash, runProfile: run.profileHash,
  sarifSuite: sarif.properties.suiteHash, sarifPolicy: sarif.properties.policyHash, mapVersion: sarif.properties.standardsMap.mapVersion,
  tenant: sarif.tool.driver.rules.find(rule => rule.id === 'TENANT-01').properties.standards }));
`;
  const child = spawnSync(process.execPath, ['--input-type=module', '-e', script], { encoding: 'utf8', timeout: 120000, env: {} });
  assert.equal(child.status, 0, child.stderr);
  const observed = JSON.parse(child.stdout);
  assert.equal(observed.mapVersion, 'altered-in-child', 'the altered map was loaded');
  assert.deepEqual(observed.tenant, { owaspLlm2025: ['LLM10:2025'], cwe: ['CWE-770'] });
  for (const [key, expected] of [['suite', SUITE.hash], ['runSuite', SUITE.hash], ['sarifSuite', SUITE.hash], ['policy', POLICY_HASH], ['runPolicy', POLICY_HASH], ['sarifPolicy', POLICY_HASH], ['fixture', FIXTURE_HASH], ['runProfile', repaired.profileHash]]) assert.equal(observed[key], expected, key);
});

test('malformed or unreviewed standards maps are refused', () => {
  assert.equal(validateStandardsMap(standardsMap), standardsMap);
  const mutate = change => { const map = copy(standardsMap); change(map); return map; };
  const checks = map => map.suites[SUITE.id].checks;
  for (const bad of [
    mutate(map => { checks(map)['TENANT-01'].owaspLlm2025 = ['LLM11:2025']; }),
    mutate(map => { checks(map)['TENANT-01'].owaspLlm2025 = ['LLM02:2026']; }),
    mutate(map => { checks(map)['TENANT-01'].cwe = ['CWE-ABC']; }),
    mutate(map => { checks(map)['TENANT-01'].cwe = ['CWE-639', 'CWE-639']; }),
    mutate(map => { checks(map)['ALLOWED-01'].cwe = ['CWE-285']; }),
    mutate(map => { checks(map)['TENANT-01'].role = 'unknown'; }),
    mutate(map => { map.relationship = 'implies'; }),
    mutate(map => { map.schemaVersion = 2; }),
    // A map cannot rename a known vocabulary or widen its identifier shape, so no tag carries free text.
    mutate(map => { map.taxonomies.cwe.idPattern = '^.*$'; checks(map)['TENANT-01'].cwe = ['Compliant with every framework']; }),
    mutate(map => { map.taxonomies.owaspLlm2025.name = 'OWASP certified'; }),
    mutate(map => { map.taxonomies.owaspLlm2026.version = '2027'; }),
    mutate(map => { map.taxonomies.mitreAtlas.version = '2026.12'; }),
    mutate(map => { map.taxonomies.owaspAgentic2026.idPattern = '^ASI[0-9]+$'; }),
    mutate(map => { map.taxonomies.cwe.version = '4.19'; }),
    mutate(map => { delete map.taxonomies.cwe.version; }),
    mutate(map => { map.taxonomies.mitreAtlas.organization = 'MITRE (certified)'; }),
  ]) { assert.throws(() => validateStandardsMap(bad), /Invalid standards map/); assert.throws(() => renderSarif(repaired, { standardsMap: bad }), /Invalid standards map/); }
  // Every current synthetic check is reviewed explicitly; controls carry no weakness tags.
  assert.deepEqual(Object.keys(checks(standardsMap)).sort(), SUITE.checks.map(check => check.id).sort());
  for (const check of SUITE.checks) assert.equal(checks(standardsMap)[check.id].role === 'allowed-use-control', check.severity === 'control', check.id);
  // Agentic (ASI) identifiers appear only with a pinned primary source, and ASI10 is never used.
  assert.deepEqual(Object.keys(standardsMap.taxonomies).sort(), ['cwe', 'mitreAtlas', 'owaspAgentic2026', 'owaspLlm2025', 'owaspLlm2026']);
  assert.match(standardsMap.taxonomies.owaspAgentic2026.sourcePdfSha256, /^[0-9a-f]{64}$/);
  assert.equal(standardsMap.taxonomies.owaspAgentic2026.version, '2026');
  assert.doesNotMatch(JSON.stringify(standardsMap.suites), /ASI10/);
});

// The published 2025 to 2026 renumbering, restated here from the OWASP 2026 release list (github.com/GenAI-Security-Project/GenAI-LLM-Top10,
// commit 9253e38a, README "OWASP GenAI LLM Top 10 2026") so the map's own crosswalk is checked against a second copy.
const OWASP_LLM_2025_TO_2026 = { 'LLM01:2025': 'LLM01:2026', 'LLM02:2025': 'LLM02:2026', 'LLM03:2025': 'LLM04:2026', 'LLM04:2025': 'LLM05:2026', 'LLM05:2025': 'LLM10:2026',
  'LLM06:2025': 'LLM03:2026', 'LLM07:2025': 'LLM08:2026', 'LLM08:2025': 'LLM09:2026', 'LLM09:2025': 'LLM07:2026', 'LLM10:2025': 'LLM06:2026' };
const allEntries = map => Object.entries(map.suites).flatMap(([suiteId, suite]) => Object.entries(suite.checks).map(([checkId, entry]) => ({ suiteId, checkId, entry })));
// The current source definition of every suite the map reviews, keyed by the suiteId its runs carry.
const sourceSuites = () => Object.fromEntries([
  [SUITE.id, { version: SUITE.version, hash: SUITE.hash, checks: SUITE.checks }],
]);
// A minimal saved-run shape for one source suite, every row passing; enough for the exporter's standards projection.
const suiteRun = (suiteId, source, status = 'pass') => ({ schemaVersion: 1, id: '00000000-0000-4000-8000-0000000000a1', applicationId: 'standards-review', targetId: 'standards-review', suiteId, suiteHash: source.hash,
  results: source.checks.map(check => ({ id: check.id, title: check.title, severity: check.severity, status, expected: check.expected, assertions: [] })) });

test('every mapped suite is reviewed against its current source suite: same checks, roles, version and hash', () => {
  const sources = sourceSuites();
  assert.deepEqual(Object.keys(standardsMap.suites).sort(), Object.keys(sources).sort(), 'the map reviews exactly the owned fixed-ID suites');
  for (const [suiteId, mapped] of Object.entries(standardsMap.suites)) {
    const source = sources[suiteId];
    assert.deepEqual(Object.keys(mapped.checks).sort(), source.checks.map(check => check.id).sort(), `${suiteId} check IDs`);
    for (const check of source.checks) assert.equal(mapped.checks[check.id].role === 'allowed-use-control', check.severity === 'control', `${suiteId} ${check.id} role`);
    // A changed suite definition must be re-reviewed: the map pins the version and hash it was reviewed against.
    assert.equal(mapped.reviewedSuiteVersion, source.version, `${suiteId} version`); assert.equal(mapped.reviewedSuiteHash, source.hash, `${suiteId} hash`);
  }
  // Configured suites (operator profile IDs) and the unreviewed refund-lifecycle suite get no bundled tags.
  assert.match(standardsMap.omitted.otherSuites, /--standards-file/); assert.match(standardsMap.omitted.otherSuites, /refund-lifecycle/);
});

test('OWASP LLM 2026 identifiers are exactly the published renumbering of each entry\'s 2025 identifiers', () => {
  const taxonomy = standardsMap.taxonomies.owaspLlm2026;
  assert.equal(taxonomy.version, '2026'); assert.equal(taxonomy.published, '2026-08-04'); assert.match(taxonomy.sourceCommit, /^[0-9a-f]{40}$/);
  assert.deepEqual(taxonomy.renumberedFrom, { taxonomy: 'owaspLlm2025', ids: OWASP_LLM_2025_TO_2026 });
  for (const { suiteId, checkId, entry } of allEntries(standardsMap)) assert.deepEqual(entry.owaspLlm2026, entry.owaspLlm2025.map(id => OWASP_LLM_2025_TO_2026[id]), `${suiteId} ${checkId}`);
  const run = renderSarif(vulnerable).runs[0], rule = id => run.tool.driver.rules.find(entry => entry.id === id);
  const editions = run.taxonomies.filter(entry => entry.name === 'OWASP Top 10 for LLM Applications').map(entry => entry.version);
  assert.deepEqual(editions, ['2025', '2026'], 'both editions are separate taxonomies');
  assert(rule('ROLE-01').properties.tags.includes('OWASP-LLM06:2025') && rule('ROLE-01').properties.tags.includes('OWASP-LLM03:2026'));
  assert(rule('EFFECT-01').properties.tags.includes('OWASP-LLM07:2026') && rule('BUDGET-01').properties.tags.includes('OWASP-LLM06:2026'));
  assert.equal(rule('ALLOWED-01').properties.tags.some(tag => tag.endsWith(':2026')), false);
  // A 2026 list that is not the renumbering, or a crosswalk that is missing or not one-to-one, is refused.
  const mutate = change => { const map = copy(standardsMap); change(map); return map; };
  for (const bad of [
    mutate(map => { map.suites[SUITE.id].checks['ROLE-01'].owaspLlm2026 = ['LLM06:2026']; }),
    mutate(map => { map.suites[SUITE.id].checks['ROLE-01'].owaspLlm2026 = ['LLM06:2025']; }),
    mutate(map => { map.suites[SUITE.id].checks['ROLE-01'].owaspLlm2026 = []; }),
    mutate(map => { map.suites[SUITE.id].checks['UNTRUSTED-01'].owaspLlm2026.reverse(); }),
    mutate(map => { delete map.taxonomies.owaspLlm2026.renumberedFrom; }),
    mutate(map => { map.taxonomies.owaspLlm2026.renumberedFrom.ids['LLM03:2025'] = 'LLM03:2026'; }),
    mutate(map => { map.taxonomies.owaspLlm2026.renumberedFrom.taxonomy = 'cwe'; }),
    mutate(map => { delete map.taxonomies.owaspLlm2026; }),
  ]) assert.throws(() => validateStandardsMap(bad), /Invalid standards map/);
  // A map without any 2026 list still validates (older and operator maps).
  const older = mutate(map => { for (const { entry } of allEntries(map)) delete entry.owaspLlm2026; delete map.taxonomies.owaspLlm2026; });
  assert.equal(validateStandardsMap(older), older);
});

test('every CWE in the map is one CWE 4.20 allows for vulnerability mapping, except two the public site still shows', () => {
  assert.equal(cweUsage.cweVersion, '4.20');
  // scopehaven.dev's policy panel shows these entries (claim C53, tools/gen_standards_chips.py), so they change only with the site.
  const keptForSite = new Set([`${SUITE.id} TENANT-01 CWE-200`, `${SUITE.id} ROLE-01 CWE-285`]);
  for (const { suiteId, checkId, entry } of allEntries(standardsMap)) for (const id of entry.cwe) {
    assert(Object.hasOwn(cweUsage.usage, id), `${suiteId} ${checkId} ${id} has a recorded CWE usage`);
    const usage = cweUsage.usage[id], key = `${suiteId} ${checkId} ${id}`;
    if (keptForSite.has(key)) { assert.equal(usage, 'DISCOURAGED', key); keptForSite.delete(key); continue; }
    assert(['ALLOWED', 'ALLOWED-WITH-REVIEW'].includes(usage), `${key} is ${usage}`);
  }
  assert.deepEqual([...keptForSite], [], 'each kept exception is still in the map');
  // The replaced IDs stay recorded with the usage that ruled them out.
  for (const [id, usage] of [['CWE-840', 'PROHIBITED'], ['CWE-200', 'DISCOURAGED'], ['CWE-285', 'DISCOURAGED'], ['CWE-668', 'DISCOURAGED']]) assert.equal(cweUsage.usage[id], usage, id);
  assert.match(standardsMap.omitted.cweUsage, /CWE-840/);
});

test('MITRE ATLAS 2026.09 techniques exist in the release, carry a rationale, are never on controls and are absent where no adversary acts', () => {
  const taxonomy = standardsMap.taxonomies.mitreAtlas;
  const atlasRelease = vocabularies.mitreAtlas;
  assert.equal(taxonomy.version, '2026.09'); assert.equal(atlasRelease.version, '2026.09'); assert.equal(taxonomy.sourceSha256, atlasRelease.sourceSha256); assert.equal(taxonomy.source, atlasRelease.source);
  assert.equal(atlasRelease.techniqueIds.length, atlasRelease.count); assert.equal(new Set(atlasRelease.techniqueIds).size, 208);
  const release = new Set(atlasRelease.techniqueIds);
  for (const { suiteId, checkId, entry } of allEntries(standardsMap)) {
    for (const id of entry.mitreAtlas || []) assert(release.has(id), `${suiteId} ${checkId} ${id} is an ATLAS 2026.09 technique`);
    if ((entry.mitreAtlas || []).length) assert(entry.mitreAtlasRationale.trim().length > 20, `${suiteId} ${checkId} rationale`);
  }
  const support = standardsMap.suites[SUITE.id].checks;
  // Faults with no adversary input carry no technique; suites with scripted or direct inputs carry none at all.
  for (const id of ['CONCURRENT-01', 'EFFECT-01', 'MIDTASK-01', 'TRUTH-01', 'TRUTH-03', 'TARGET-BIND-01', 'CANARY-01']) assert.deepEqual(support[id].mitreAtlas, [], id);
  for (const suiteId of Object.keys(standardsMap.suites).filter(id => id !== SUITE.id)) {
    assert(allEntries(standardsMap).filter(item => item.suiteId === suiteId).every(item => (item.entry.mitreAtlas || []).length === 0), `${suiteId} has no ATLAS tags`);
    assert.match(standardsMap.suites[suiteId].mappingNote, /no MITRE ATLAS technique is mapped/);
  }
  const run = renderSarif(vulnerable).runs[0], rule = id => run.tool.driver.rules.find(entry => entry.id === id);
  const atlas = run.taxonomies.find(entry => entry.name === 'MITRE ATLAS');
  assert(atlas && atlas.version === '2026.09' && atlas.organization === 'MITRE');
  const untrusted = rule('UNTRUSTED-01');
  assert(untrusted.properties.tags.includes('mitre-atlas-aml.t0051.001') && untrusted.properties.tags.includes('mitre-atlas-aml.t0086'));
  assert(untrusted.relationships.some(link => link.target.id === 'AML.T0051.001' && link.target.toolComponent.name === 'MITRE ATLAS'));
  assert.equal(typeof untrusted.properties.standards.mitreAtlasRationale, 'string');
  assert.equal(Object.hasOwn(rule('EFFECT-01').properties.standards, 'mitreAtlasRationale'), false);
  assert.equal(rule('ALLOWED-01').properties.tags.some(tag => tag.startsWith('mitre-atlas-')), false);
  const mutate = change => { const map = copy(standardsMap); change(map); return map; };
  for (const bad of [
    mutate(map => { delete map.suites[SUITE.id].checks['FLOW-01'].mitreAtlasRationale; }),
    mutate(map => { map.suites[SUITE.id].checks['FLOW-01'].mitreAtlasRationale = ' '; }),
    mutate(map => { map.suites[SUITE.id].checks['FLOW-01'].mitreAtlas = ['AML.TA0010']; }),
    mutate(map => { map.suites[SUITE.id].checks['FLOW-01'].mitreAtlas = ['AML.T0086', 'AML.T0086']; }),
    mutate(map => { map.suites[SUITE.id].checks['FLOW-02'].mitreAtlas = ['AML.T0086']; map.suites[SUITE.id].checks['FLOW-02'].mitreAtlasRationale = 'x'; }),
    mutate(map => { map.suites[SUITE.id].checks['FLOW-01'].mappingNote = ''; }),
    mutate(map => { map.suites[SUITE.id].reviewedSuiteHash = 'not-a-hash'; }),
  ]) assert.throws(() => validateStandardsMap(bad), /Invalid standards map/);
});

test('every reviewed suite exports its tags, notes and suite review, and the run says "mapped to", never "compliant"', () => {
  const sources = sourceSuites();
  for (const [suiteId, source] of Object.entries(sources)) {
    const sarif = validateSarifStructure(renderSarif(suiteRun(suiteId, source)));
    const review = sarif.properties.standardsMap;
    assert.equal(review.appliedToSuite, suiteId); assert.equal(review.origin, 'bundled'); assert.equal(review.statement, MAPPING_STATEMENT);
    assert.deepEqual(review.suiteReview, { reviewedSuiteVersion: source.version, reviewedSuiteHash: source.hash, runSuiteHashMatches: true,
      ...(standardsMap.suites[suiteId].mappingNote ? { mappingNote: standardsMap.suites[suiteId].mappingNote } : {}) });
    for (const rule of sarif.tool.driver.rules) {
      const entry = standardsMap.suites[suiteId].checks[rule.id];
      if (entry.role === 'allowed-use-control') assert.deepEqual(rule.properties.tags, ['allowed-use-control'], `${suiteId} ${rule.id}`);
      if (entry.mappingNote) assert.equal(rule.properties.standards.mappingNote, entry.mappingNote);
    }
  }
  assert.match(MAPPING_STATEMENT, /mapped to/); assert.doesNotMatch(MAPPING_STATEMENT, /complian|certif|satisf/i);
  assert.doesNotMatch(JSON.stringify(standardsMap), /\bcompliant\b|\bsatisfies\b|\bcertified\b/i);
  // An older run of a mapped suite keeps its tags and says its suite hash differs from the reviewed one.
  const older = { ...copy(repaired), suiteHash: 'e'.repeat(64) };
  const olderReview = renderSarif(older).runs[0];
  assert.equal(olderReview.properties.standardsMap.suiteReview.runSuiteHashMatches, false);
  assert.deepEqual(olderReview.tool.driver.rules.find(rule => rule.id === 'TENANT-01').properties.standards.owaspLlm2026, ['LLM02:2026']);
  // A configured suite has no bundled review.
  const configured = { ...copy(repaired), suiteId: 'customer-profile-contracts' };
  const unmapped = renderSarif(configured).runs[0];
  assert.equal(unmapped.properties.standardsMap.appliedToSuite, null); assert.equal(Object.hasOwn(unmapped.properties.standardsMap, 'suiteReview'), false);
  assert(unmapped.tool.driver.rules.every(rule => rule.relationships === undefined && rule.properties.standards.note === 'No reviewed standards mapping for this check.'));
});

test('an operator standards file tags a configured suite in SARIF only, is validated, and never changes run hashes', async t => {
  const root = await dir(t), data = join(root, 'store'), out = join(root, 'exports'), maps = join(root, 'maps');
  const store = createStore(data); await store.ready;
  await mkdir(out, { mode: 0o700 }); await mkdir(maps, { mode: 0o700 });
  // A run whose suite ID came from an operator profile; the bundled map has no review for it.
  const configured = await store.save({ ...copy(repaired), id: '00000000-0000-4000-8000-0000000000c1', suiteId: 'acme-support-contracts' });
  const operatorMap = { schemaVersion: 1, mapVersion: 'acme-2026-10-19', relationship: 'relevant', taxonomies: { cwe: standardsMap.taxonomies.cwe, owaspLlm2025: standardsMap.taxonomies.owaspLlm2025 },
    suites: { 'acme-support-contracts': { checks: { 'TENANT-01': { role: 'prohibited-behaviour', owaspLlm2025: ['LLM02:2025'], cwe: ['CWE-639'] } } } } };
  const mapFile = join(maps, 'acme.json'); await writeFile(mapFile, JSON.stringify(operatorMap));
  const plain = await exportRun({ runId: configured.id, format: 'sarif', outputFile: join(out, 'plain.sarif'), dataDir: data });
  const tagged = await main(['--run', configured.id, '--format', 'sarif', '--out', join(out, 'tagged.sarif'), '--data', data, '--standards-file', mapFile]);
  assert.notEqual(tagged.sha256, plain.sha256);
  const before = JSON.parse(await readFile(join(out, 'plain.sarif'), 'utf8')).runs[0], after = validateSarifStructure(JSON.parse(await readFile(join(out, 'tagged.sarif'), 'utf8')));
  assert.equal(before.properties.standardsMap.appliedToSuite, null);
  assert.deepEqual([after.properties.standardsMap.origin, after.properties.standardsMap.mapVersion, after.properties.standardsMap.appliedToSuite], ['supplied', 'acme-2026-10-19', 'acme-support-contracts']);
  assert.equal(after.properties.standardsMap.sha256, digest(operatorMap));
  assert.deepEqual(after.tool.driver.rules.find(rule => rule.id === 'TENANT-01').properties.standards, { owaspLlm2025: ['LLM02:2025'], cwe: ['CWE-639'] });
  for (const key of ['suiteHash', 'policyHash', 'fixtureHash', 'profileHash', 'evaluatorHash', 'runId']) assert.equal(after.properties[key], before.properties[key], key);
  assert.deepEqual(after.results.map(result => [result.kind, result.fingerprints]), before.results.map(result => [result.kind, result.fingerprints]));
  // The file is SARIF-only, absolute, a regular file, small and a valid map; anything else is refused before any output.
  const badMap = join(maps, 'bad.json'); await writeFile(badMap, JSON.stringify({ ...operatorMap, suites: { x: { checks: { 'TENANT-01': { role: 'prohibited-behaviour', owaspLlm2025: ['LLM11:2025'], cwe: [] } } } } }));
  const notJson = join(maps, 'not.json'); await writeFile(notJson, '{');
  // Valid JSON and a valid map: exactly 1 MiB is accepted, one byte more is refused.
  const sized = bytes => { const body = JSON.stringify(operatorMap); return body + ' '.repeat(bytes - Buffer.byteLength(body)); };
  const atLimit = join(maps, 'at-limit.json'); await writeFile(atLimit, sized(1024 * 1024));
  assert.equal((await exportRun({ runId: configured.id, format: 'sarif', outputFile: join(out, 'at-limit.sarif'), dataDir: data, standardsFile: atLimit })).saved, true);
  const large = join(maps, 'large.json'); await writeFile(large, sized(1024 * 1024 + 1));
  const link = join(maps, 'link.json'); await symlink(mapFile, link);
  const fifo = join(maps, 'fifo.json'); assert.equal(spawnSync('mkfifo', [fifo]).status, 0, 'mkfifo');
  const retag = join(maps, 'retag.json'); await writeFile(retag, JSON.stringify({ ...operatorMap, suites: { ...operatorMap.suites, [SUITE.id]: { checks: { 'TENANT-01': { role: 'prohibited-behaviour', owaspLlm2025: ['LLM10:2025'], cwe: ['CWE-770'] } } } } }));
  await assert.rejects(exportRun({ runId: configured.id, format: 'json', outputFile: join(out, 'refused-a.json'), dataDir: data, standardsFile: mapFile }), /Invalid export options/);
  await assert.rejects(exportRun({ runId: configured.id, format: 'sarif', outputFile: join(out, 'refused-b.sarif'), dataDir: data, standardsFile: 'acme.json' }), /Invalid export options/);
  await assert.rejects(main(['--run', configured.id, '--baseline', configured.id, '--format', 'json', '--out', join(out, 'refused-c.json'), '--data', data, '--standards-file', mapFile]), /Invalid export options/);
  for (const [index, [file, pattern]] of [[notJson, /Invalid standards file/], [large, /Invalid standards file/], [link, /Invalid standards file/], [join(maps, 'missing.json'), /Invalid standards file/], [fifo, /Invalid standards file/], [badMap, /Invalid standards map/], [retag, /Invalid standards map/]].entries())
    await assert.rejects(exportRun({ runId: configured.id, format: 'sarif', outputFile: join(out, `refused-file-${index}.sarif`), dataDir: data, standardsFile: file }), pattern);
  assert.deepEqual((await readdir(out)).filter(name => name.startsWith('refused') || name.startsWith('.')), []);
});

// The SARIF 2.1.0 schema's types for the objects a standards map can influence: toolComponent (driver and taxonomies),
// reportingDescriptor (taxa, rules), reportingDescriptorRelationship, toolComponentReference, notification,
// reportingDescriptorReference and property bags. Not a full schema validation; the structure check above covers the rest.
function checkSarifSchemaTypes(logOrRun) {
  const str = (value, where) => assert.equal(typeof value, 'string', where);
  const optionalStr = (value, where) => { if (value !== undefined) str(value, where); };
  const int = (value, min, where) => assert(Number.isInteger(value) && value >= min, where);
  const bag = (value, where) => assert(value === undefined || (value !== null && typeof value === 'object' && !Array.isArray(value)), where);
  const run = Array.isArray(logOrRun.runs) ? logOrRun.runs[0] : logOrRun; // a SARIF log, or the run validateSarifStructure returns
  for (const [index, component] of [run.tool.driver, ...(run.taxonomies || [])].entries()) {
    str(component.name, `toolComponent ${index} name`); optionalStr(component.version, `toolComponent ${index} version`); optionalStr(component.organization, `toolComponent ${index} organization`);
    for (const taxon of component.taxa || []) { str(taxon.id, 'taxon id'); bag(taxon.properties, 'taxon properties'); }
  }
  for (const rule of run.tool.driver.rules) {
    str(rule.id, 'rule id'); bag(rule.properties, 'rule properties');
    for (const relation of rule.relationships || []) {
      str(relation.target.id, 'relationship target id'); int(relation.target.index, -1, 'relationship target index');
      str(relation.target.toolComponent.name, 'toolComponentReference name'); int(relation.target.toolComponent.index, -1, 'toolComponentReference index');
      assert(Array.isArray(relation.kinds) && relation.kinds.length > 0 && new Set(relation.kinds).size === relation.kinds.length && relation.kinds.every(kind => typeof kind === 'string'), 'relationship kinds');
    }
    for (const tag of rule.properties?.tags || []) str(tag, 'tag');
  }
  for (const invocation of run.invocations) for (const list of [invocation.toolExecutionNotifications, invocation.toolConfigurationNotifications]) for (const item of list || []) {
    str(item.message.text, 'notification message'); assert(['none', 'note', 'warning', 'error'].includes(item.level), 'notification level');
    str(item.associatedRule.id, 'associatedRule id'); int(item.associatedRule.index, -1, 'associatedRule index');
  }
  bag(run.properties, 'run properties');
  return run;
}

test('the pinned vocabularies: every ATLAS 2026.09 technique and every CWE 4.20 weakness, read only by the exporter', () => {
  assert.equal(vocabularies.mitreAtlas.count, 208); assert.equal(vocabularies.mitreAtlas.sourceSha256, standardsMap.taxonomies.mitreAtlas.sourceSha256);
  assert.equal(vocabularies.cwe.version, '4.20'); assert.equal(vocabularies.cwe.count, vocabularies.cwe.weaknessIds.length); assert.equal(new Set(vocabularies.cwe.weaknessIds).size, vocabularies.cwe.count);
  assert(vocabularies.cwe.count > 900, 'the full research view');
  const weaknesses = new Set(vocabularies.cwe.weaknessIds);
  for (const { entry } of allEntries(standardsMap)) for (const id of entry.cwe) assert(weaknesses.has(Number(id.slice(4))), id);
  // CWE-840 is a category (PROHIBITED for mapping), so it is not a weakness; CWE-99999 does not exist.
  for (const id of [840, 99999]) assert.equal(weaknesses.has(id), false, `CWE-${id}`);
});

test('the vocabulary file carries each source\'s licence and attribution, with the notice file beside it', async () => {
  const notice = await readFile(new URL('../src/standards-vocabularies.NOTICE.md', import.meta.url), 'utf8');
  assert.match(vocabularies.purpose, /src[/]standards-vocabularies[.]NOTICE[.]md/);
  assert.equal(vocabularies.mitreAtlas.licence, 'Apache-2.0'); assert.equal(vocabularies.mitreAtlas.copyright, 'Copyright 2021-2026 MITRE');
  assert.match(vocabularies.cwe.licence, /CWE Terms of Use/); assert.match(vocabularies.cwe.copyright, /The MITRE Corporation/);
  // The notice names each source, version, date and hash, and reproduces the ATLAS licence notice and CWE's designation and licence.
  for (const value of [vocabularies.mitreAtlas.source, vocabularies.mitreAtlas.sourceSha256, vocabularies.mitreAtlas.repositoryCommit, vocabularies.mitreAtlas.version,
    vocabularies.cwe.source, vocabularies.cwe.sourceSha256, vocabularies.cwe.version, vocabularies.cwe.copyright, 'Licensed under the Apache License, Version 2.0',
    'http://www.apache.org/licenses/LICENSE-2.0', 'reproduce MITRE’s copyright designation and this license in any such copy', 'retrieved 2026-10-19'])
    assert(notice.includes(value), value);
  assert.match(standardsMap.licenseNote, /standards-vocabularies[.]NOTICE[.]md/);
});

test('a supplied map selects vocabularies but cannot describe them, overstate a mapping, tag a control or carry claims (an earlier review probes)', () => {
  const run = { schemaVersion: 1, id: '00000000-0000-4000-8000-0000000000a1', applicationId: 'probe', targetId: 'probe', suiteId: 'acme-contracts', suiteHash: 'a'.repeat(64),
    results: [{ id: 'CLEAN', title: 'Clean', severity: 'high', status: 'pass', assertions: [] }, { id: 'ALLOWED', title: 'Allowed work', severity: 'control', status: 'pass', assertions: [] }] };
  const base = () => ({ schemaVersion: 1, mapVersion: 'acme-1', relationship: 'relevant', taxonomies: { cwe: copy(standardsMap.taxonomies.cwe), owaspLlm2025: copy(standardsMap.taxonomies.owaspLlm2025) },
    suites: { 'acme-contracts': { checks: { CLEAN: { role: 'prohibited-behaviour', owaspLlm2025: ['LLM02:2025'], cwe: ['CWE-639'] }, ALLOWED: { role: 'allowed-use-control', owaspLlm2025: [], cwe: [] } } } } });
  const withMap = change => { const map = base(); change(map); return map; };
  const checks = map => map.suites['acme-contracts'].checks;
  const control = String.fromCharCode(0x202e) + 'desrever' + String.fromCharCode(7, 0);
  const refused = {
    'cwe organization is an object': map => { map.taxonomies.cwe.organization = { injected: { nested: true } }; },
    'cwe organization is markup with a claim': map => { map.taxonomies.cwe.organization = '<img src=x onerror=alert(1)> Certified compliant'; },
    'cwe organization is 900 KB': map => { map.taxonomies.cwe.organization = 'x'.repeat(900000); },
    'cwe version is an object': map => { map.taxonomies.cwe.version = { injected: 1 }; },
    'cwe version is free text': map => { map.taxonomies.cwe.version = 'OWASP compliant edition'; },
    'owaspLlm2025 organization is an array': map => { map.taxonomies.owaspLlm2025.organization = ['a', 'b']; },
    'relationship equal': map => { map.relationship = 'equal'; },
    'relationship superset': map => { map.relationship = 'superset'; },
    'relationship incomparable': map => { map.relationship = 'incomparable'; },
    'mapVersion with a claim': map => { map.mapVersion = 'OWASP LLM Top 10 certified'; },
    'mapVersion over 64 characters': map => { map.mapVersion = 'v'.repeat(65); },
    'suite note with a claim': map => { map.suites['acme-contracts'].mappingNote = 'This application is compliant with OWASP LLM Top 10 2026.'; },
    'suite version with a claim': map => { map.suites['acme-contracts'].reviewedSuiteVersion = 'certified-1'; },
    'entry note with a claim': map => { checks(map).CLEAN.mappingNote = 'Satisfies LLM02 in full.'; },
    'rationale with a claim': map => { Object.assign(checks(map).CLEAN, { owaspAgentic2026: ['ASI03'], owaspAgentic2026Rationale: 'Certified: meets ASI03.' }); map.taxonomies.owaspAgentic2026 = copy(standardsMap.taxonomies.owaspAgentic2026); },
    'note over 500 characters': map => { checks(map).CLEAN.mappingNote = 'n'.repeat(501); },
    'bidi and control characters in a note': map => { checks(map).CLEAN.mappingNote = `ok${control}`; },
    'an arbitrary 2026 renumbering': map => { map.taxonomies.owaspLlm2026 = copy(standardsMap.taxonomies.owaspLlm2026); Object.assign(map.taxonomies.owaspLlm2026.renumberedFrom.ids, { 'LLM02:2025': 'LLM09:2026', 'LLM08:2025': 'LLM02:2026' }); checks(map).CLEAN.owaspLlm2026 = ['LLM09:2026']; },
    'an ATLAS ID absent from 2026.09': map => { map.taxonomies.mitreAtlas = copy(standardsMap.taxonomies.mitreAtlas); Object.assign(checks(map).CLEAN, { mitreAtlas: ['AML.T9999.999'], mitreAtlasRationale: 'Not a real technique at all.' }); },
    'CWE-840, a category PROHIBITED for mapping': map => { checks(map).CLEAN.cwe = ['CWE-840']; },
    'CWE-99999, which does not exist': map => { checks(map).CLEAN.cwe = ['CWE-99999']; },
  };
  for (const [name, change] of Object.entries(refused)) {
    const map = withMap(change);
    assert.throws(() => validateStandardsMap(map), /Invalid standards map/, name); assert.throws(() => renderSarif(run, { standardsMap: map }), /Invalid standards map/, name);
  }
  // At the limits: a 500-character note and a 64-character map version are accepted.
  assert.doesNotThrow(() => validateStandardsMap(withMap(map => { checks(map).CLEAN.mappingNote = 'n'.repeat(500); map.mapVersion = 'v'.repeat(64); })));
  // The vocabulary is emitted from the exporter, never from the map: a map without organization still names MITRE and CWE 4.20.
  const plain = checkSarifSchemaTypes(validateSarifStructure(renderSarif(run, { standardsMap: withMap(map => { delete map.taxonomies.cwe.organization; }) })));
  assert.deepEqual(plain.taxonomies.map(({ name, version, organization }) => [name, version, organization]), [['CWE', '4.20', 'MITRE'], ['OWASP Top 10 for LLM Applications', '2025', 'OWASP']]);
  assert.equal(plain.properties.standardsMap.origin, 'supplied');
  // "subset" is the one other relationship accepted; it never says a check covers a whole category.
  const subset = checkSarifSchemaTypes(renderSarif(run, { standardsMap: withMap(map => { map.relationship = 'subset'; }) }));
  assert.deepEqual([...new Set(subset.tool.driver.rules.flatMap(rule => (rule.relationships || []).flatMap(link => link.kinds)))], ['subset']);
  // An unknown taxonomy key is ignored and never emitted.
  const unknown = renderSarif(run, { standardsMap: withMap(map => { checks(map).CLEAN.nistAiRmf = ['GOVERN-1.1 certified']; }) });
  assert.doesNotMatch(JSON.stringify(unknown), /nistAiRmf|GOVERN/);
  // A map that tags a row the run marks as a control (or calls a prohibition a control) loses that row's tags, and says so.
  for (const [id, change] of [['ALLOWED', map => { checks(map).ALLOWED = { role: 'prohibited-behaviour', owaspLlm2025: ['LLM01:2025'], cwe: ['CWE-862'] }; }], ['CLEAN', map => { checks(map).CLEAN = { role: 'allowed-use-control', owaspLlm2025: [], cwe: [] }; }]]) {
    const out = checkSarifSchemaTypes(validateSarifStructure(renderSarif(run, { standardsMap: withMap(change) })));
    const rule = out.tool.driver.rules.find(entry => entry.id === id);
    assert.deepEqual(rule.properties.tags, [id === 'ALLOWED' ? 'allowed-use-control' : 'security'], id); assert.equal(rule.relationships, undefined);
    assert.match(rule.properties.standards.note, /^Mapping dropped: /); assert.deepEqual(out.properties.standardsMap.droppedForRole, [id]);
    assert.deepEqual(out.invocations[0].toolConfigurationNotifications.map(item => [item.level, item.associatedRule.id]), [['warning', id]]);
    assert.equal(out.invocations[0].executionSuccessful, true);
  }
  // A supplied map may cover only the operator's own suites, never one the bundled map reviews.
  const retag = withMap(map => { map.suites[SUITE.id] = { checks: { 'TENANT-01': { role: 'prohibited-behaviour', owaspLlm2025: ['LLM10:2025'], cwe: ['CWE-770'] } } }; });
  assert.equal(validateStandardsMap(retag), retag); assert.throws(() => validateSuppliedStandardsMap(retag), /Invalid standards map/);
  assert.equal(validateSuppliedStandardsMap(withMap(() => {})).mapVersion, 'acme-1');
});

test('the bundled map gets the same control guard: a run whose row roles disagree with the map loses those tags, with a warning', () => {
  const run = copy(vulnerable);
  run.results.find(row => row.id === 'TENANT-01').severity = 'control';
  run.results.find(row => row.id === 'ALLOWED-01').severity = 'high';
  const out = checkSarifSchemaTypes(validateSarifStructure(renderSarif(run)));
  const rule = id => out.tool.driver.rules.find(entry => entry.id === id);
  assert.deepEqual(rule('TENANT-01').properties.tags, ['allowed-use-control']); assert.equal(rule('TENANT-01').relationships, undefined);
  assert.match(rule('ALLOWED-01').properties.standards.note, /^Mapping dropped: /);
  assert.deepEqual(out.properties.standardsMap.droppedForRole, ['TENANT-01', 'ALLOWED-01']);
  assert.deepEqual(out.invocations[0].toolConfigurationNotifications.map(item => item.associatedRule.id), ['TENANT-01', 'ALLOWED-01']);
  // Untouched rows keep their tags; an unchanged run has no configuration notification.
  assert(rule('ROLE-01').properties.tags.includes('OWASP-LLM03:2026'));
  assert.equal(renderSarif(vulnerable).runs[0].invocations[0].toolConfigurationNotifications, undefined);
  for (const source of [vulnerable, repaired]) checkSarifSchemaTypes(renderSarif(source));
});

test('export CLI writes SARIF and comparisons with the existing private, exclusive and integrity protections', async t => {
  const root = await dir(t), data = join(root, 'store'), out = join(root, 'exports');
  const store = createStore(data); await store.ready;
  const baseline = await store.save(copy(vulnerable)), candidate = await store.save(copy(repaired));
  await mkdir(out, { mode: 0o700 });
  const receipts = {};
  for (const format of ['json', 'html', 'sarif']) {
    const path = join(out, `candidate.${format}`);
    const receipt = await exportRun({ runId: candidate.id, format, outputFile: path, dataDir: data });
    const bytes = await readFile(path); receipts[format] = receipt;
    assert.equal(receipt.sha256, sha256(bytes)); assert.equal((await stat(path)).mode & 0o777, 0o600);
    await assert.rejects(exportRun({ runId: baseline.id, format, outputFile: path, dataDir: data }));
    assert.deepEqual(await readFile(path), bytes, 'existing files are preserved');
  }
  const sarif = validateSarifStructure(JSON.parse(await readFile(join(out, 'candidate.sarif'), 'utf8')));
  assert.equal(sarif.properties.evidenceIntegrity.sha256, candidate.integrity.sha256);
  assert.equal(sarif.properties.runId, candidate.id);
  const again = await exportRun({ runId: candidate.id, format: 'sarif', outputFile: join(out, 'candidate-again.sarif'), dataDir: data });
  assert.equal(again.sha256, receipts.sarif.sha256, 'repeat export is byte-identical');
  const viaMain = await main(['--run', candidate.id, '--format', 'sarif', '--out', join(out, 'via-main.sarif'), '--data', data]);
  assert.equal(viaMain.sha256, receipts.sarif.sha256);

  // Comparison export copies the core labels.
  const compareJson = join(out, 'comparison.json'), compareHtml = join(out, 'comparison.html');
  await main(['--run', candidate.id, '--baseline', baseline.id, '--format', 'json', '--out', compareJson, '--data', data]);
  await exportRun({ runId: candidate.id, baselineRunId: baseline.id, format: 'html', outputFile: compareHtml, dataDir: data });
  const comparison = JSON.parse(await readFile(compareJson, 'utf8'));
  assert.equal(comparison.document, 'scopehaven-comparison/1'); assert.equal(comparison.verdict, 'comparable-controls-passed');
  assert.equal(comparison.comparison.compatible, true); assert.equal(comparison.comparison.controlsPass, true);
  assert.equal(comparison.comparison.summary.fixed, 26); assert.equal(comparison.comparison.summary.preservedPasses, 18);
  assert.equal(comparison.baseline.runId, baseline.id); assert.equal(comparison.candidate.runId, candidate.id);
  assert.match(await readFile(compareHtml, 'utf8'), /Comparable runs\. Every required allowed-use control passed/);

  // Options outside the supported set are refused before any file is written.
  for (const options of [
    { runId: candidate.id, baselineRunId: baseline.id, format: 'sarif', outputFile: join(out, 'refused-1.sarif'), dataDir: data },
    { runId: candidate.id, format: 'csv', outputFile: join(out, 'refused-2.csv'), dataDir: data },
    { runId: candidate.id, baselineRunId: 'not-a-run', format: 'json', outputFile: join(out, 'refused-3.json'), dataDir: data },
    { runId: candidate.id, format: 'sarif', outputFile: 'relative.sarif', dataDir: data },
  ]) await assert.rejects(exportRun(options), /Invalid export options/);
  const alias = join(root, 'alias'); await symlink(out, alias);
  await assert.rejects(exportRun({ runId: candidate.id, format: 'sarif', outputFile: join(alias, 'blocked.sarif'), dataDir: data }), /private/);
  const shared = join(root, 'shared'); await mkdir(shared); await chmod(shared, 0o755);
  await assert.rejects(exportRun({ runId: candidate.id, format: 'sarif', outputFile: join(shared, 'blocked.sarif'), dataDir: data }), /private/);
  assert.deepEqual((await readdir(out)).filter(name => name.startsWith('refused') || name.startsWith('.')), []);
});

test('incomplete and incompatible evidence is refused or labelled exactly like JSON and HTML exports', async t => {
  const root = await dir(t), data = join(root, 'store'), out = join(root, 'exports');
  await mkdir(out, { mode: 0o700 });
  const store = createStore(data); await store.ready;
  // All-error run: exported in every format and labelled, never shown as a pass.
  const failing = await store.save(await runAssessment('demo-vulnerable', { fixtureFactory: async () => { throw new Error('fixture unavailable'); } }));
  assert.equal(failing.counts.error, failing.results.length);
  for (const format of ['json', 'html', 'sarif']) await exportRun({ runId: failing.id, format, outputFile: join(out, `error.${format}`), dataDir: data });
  assert.match(await readFile(join(out, 'error.html'), 'utf8'), /<strong>ERROR<\/strong>/);
  const sarif = validateSarifStructure(JSON.parse(await readFile(join(out, 'error.sarif'), 'utf8')));
  assert(sarif.results.every(result => result.kind === 'open' && result.level === 'none' && /^ERROR: /.test(result.message.text)));
  assert.equal(sarif.invocations[0].executionSuccessful, false);
  assert.equal(sarif.invocations[0].toolExecutionNotifications.length, failing.results.length);

  // Missing or tampered evidence is refused in every format.
  const baseline = await store.save(copy(vulnerable)), candidate = await store.save(copy(repaired));
  for (const format of ['json', 'html', 'sarif']) await assert.rejects(exportRun({ runId: '00000000-0000-4000-8000-0000000000ff', format, outputFile: join(out, `missing.${format}`), dataDir: data }), /not found/);
  const file = join(data, 'runs', `${candidate.id}.json`), saved = JSON.parse(await readFile(file, 'utf8'));
  assert.equal(saved.core.results[0].status, 'pass'); saved.core.results[0].status = 'fail'; await writeFile(file, JSON.stringify(saved));
  for (const format of ['json', 'html', 'sarif']) await assert.rejects(exportRun({ runId: candidate.id, format, outputFile: join(out, `tampered.${format}`), dataDir: data }), /integrity/);
  await assert.rejects(exportRun({ runId: candidate.id, baselineRunId: baseline.id, format: 'json', outputFile: join(out, 'tampered-comparison.json'), dataDir: data }), /integrity/);

  // An incompatible pair is exported with its reasons; no row is labelled fixed.
  const changed = copy(repaired); changed.id = '00000000-0000-4000-8000-000000000002'; changed.suiteHash = 'f'.repeat(64);
  changed.results[0].title = '<script>alert(1)</script>';
  const incompatible = await store.save(changed);
  await exportRun({ runId: incompatible.id, baselineRunId: baseline.id, format: 'json', outputFile: join(out, 'incompatible.json'), dataDir: data });
  await exportRun({ runId: incompatible.id, baselineRunId: baseline.id, format: 'html', outputFile: join(out, 'incompatible.html'), dataDir: data });
  const document = JSON.parse(await readFile(join(out, 'incompatible.json'), 'utf8'));
  assert.equal(document.verdict, 'not-verified'); assert.equal(document.comparison.compatible, false);
  assert(document.comparison.reasons.includes('suiteHash differs or is missing.'));
  assert(document.comparison.rows.every(row => row.transition === 'incompatible')); assert.equal(document.comparison.summary.fixed, 0);
  const html = await readFile(join(out, 'incompatible.html'), 'utf8');
  assert.match(html, /Not verified\./); assert.match(html, /suiteHash differs or is missing\./);
  const reverse = join(out, 'reverse.html');
  await exportRun({ runId: baseline.id, baselineRunId: incompatible.id, format: 'html', outputFile: reverse, dataDir: data });
  const escaped = await readFile(reverse, 'utf8');
  assert(!escaped.includes('<script>alert(1)</script>')); assert(escaped.includes('&lt;script&gt;'));
});
