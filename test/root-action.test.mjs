// The root action.yml is a composite wrapper over integrations/github-action/action.yml: a workflow in another repository
// uses it as `uses: YusefSyed/scopehaven-oss@<ref>`, and GitHub Marketplace lists an action only from the repository root. These
// tests read the two files and check that they agree: the same inputs (names, required flags, defaults), the same outputs,
// every input forwarded unchanged to the inner action, every output taken from that step, and branding GitHub accepts.
// They also keep the CI guide's workflow and the README's snippet naming inputs that exist. Local files only; nothing runs.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { parseYamlSubset } from '../integrations/github-action/harness.mjs';

const read = path => readFile(new URL(`../${path}`, import.meta.url), 'utf8');
const rootText = await read('action.yml'), innerText = await read('integrations/github-action/action.yml');
const root = parseYamlSubset(rootText), inner = parseYamlSubset(innerText);
const STEP_ID = 'scopehaven';
// GitHub's metadata syntax reference: branding.color is one of these, and branding.icon a Feather (v4.28.0) icon name
// from its supported list. The names below were checked against that list; the root action uses one of them.
const COLOURS = ['white', 'black', 'yellow', 'blue', 'green', 'orange', 'red', 'purple', 'gray-dark'];
const ICONS = ['shield', 'check-square', 'check-circle', 'eye'];
// Wording the open edition never uses about itself or a target (test/claims-wording.test.mjs keeps product output within
// the same bounds): no detection claim, no repair claim, no vulnerability claim.
const FORBIDDEN = /fixed the app|found a vulnerabilit|detects every|catches every|better than/i;

test('the root action is a composite action with a name, a description, an author and branding GitHub accepts', () => {
  assert.equal(root.runs.using, 'composite');
  for (const key of ['name', 'description', 'author']) assert.ok(typeof root[key] === 'string' && root[key].trim().length > 0, key);
  assert.ok(COLOURS.includes(root.branding.color), `branding.color ${root.branding.color}`);
  assert.ok(ICONS.includes(root.branding.icon), `branding.icon ${root.branding.icon}`);
  assert.deepEqual(Object.keys(root.branding).sort(), ['color', 'icon']);
});

test('the root action declares the same inputs as integrations/github-action, with the same required flags and defaults', () => {
  assert.deepEqual(Object.keys(root.inputs), Object.keys(inner.inputs), 'the same inputs, in the same order');
  for (const [name, spec] of Object.entries(inner.inputs)) {
    const mirrored = root.inputs[name];
    assert.equal(mirrored.required, spec.required, `${name}: required`);
    assert.equal(Object.hasOwn(mirrored, 'default'), Object.hasOwn(spec, 'default'), `${name}: has a default`);
    assert.equal(mirrored.default, spec.default, `${name}: default`);
    assert.ok(typeof mirrored.description === 'string' && mirrored.description.trim().length > 0, `${name}: description`);
  }
});

test('the root action forwards every input to the inner action by name, and nothing else', () => {
  assert.equal(root.runs.steps.length, 1, 'one step: the inner action');
  const [step] = root.runs.steps;
  assert.equal(step.id, STEP_ID);
  assert.equal(step.uses, '$/integrations/github-action', 'the self-repository reference, which resolves to this repository at the running commit');
  assert.equal(step.run, undefined, 'no shell of its own');
  assert.deepEqual(Object.keys(step.with), Object.keys(inner.inputs), 'with: names every inner input, in order');
  for (const name of Object.keys(inner.inputs)) assert.equal(step.with[name], `\${{ inputs.${name} }}`, `${name} forwarded unchanged`);
  // The GitHub metadata syntax reference documents `$/` for composite steps; a `./` path would resolve against the caller's checkout.
  assert.doesNotMatch(rootText, /^\s+uses: \.\//m);
});

test('the root action declares the same outputs as the inner action, each taken from the forwarded step', () => {
  assert.deepEqual(Object.keys(root.outputs), Object.keys(inner.outputs));
  for (const [name, spec] of Object.entries(inner.outputs)) {
    assert.equal(root.outputs[name].value, `\${{ steps.${STEP_ID}.outputs.${name} }}`, `${name}: value`);
    assert.ok(typeof root.outputs[name].description === 'string' && root.outputs[name].description.length > 0, `${name}: description`);
    // The inner action's outputs come from its summary step; the wrapper adds no output of its own.
    assert.match(spec.value, /^\$\{\{ steps\.summary\.outputs\.[a-z-]+ \}\}$/);
  }
});

test('the root action and the guides keep to the approved wording, and no expression reaches a shell', async () => {
  for (const [path, text] of [['action.yml', rootText], ['docs/guides/ci-in-five-minutes.md', await read('docs/guides/ci-in-five-minutes.md')],
    ['docs/guides/mcp-target-from-claude-code-and-cursor.md', await read('docs/guides/mcp-target-from-claude-code-and-cursor.md')]]) assert.doesNotMatch(text, FORBIDDEN, path);
  // The wrapper has no shell step of its own; the guide's workflow keeps `${{ }}` out of every run: block (inputs reach shells through env:).
  assert.doesNotMatch(rootText, /^\s+run:/m, 'action.yml runs no shell');
  for (const block of workflowsIn(await read('docs/guides/ci-in-five-minutes.md'))) {
    const parsed = parseYamlSubset(block);
    for (const step of Object.values(parsed.jobs ?? {}).flatMap(job => job.steps ?? [])) if (typeof step.run === 'string') assert.doesNotMatch(step.run, /\$\{\{/, step.name ?? step.run);
  }
});

// Every fenced YAML block in a guide or the README that uses the root action names only inputs the action declares.
function workflowsIn(markdown) {
  return [...markdown.matchAll(/```ya?ml\n([\s\S]*?)```/g)].map(m => m[1]).filter(block => block.includes('YusefSyed/scopehaven-oss@'));
}
function rootActionSteps(block) {
  const parsed = parseYamlSubset(block);
  // A whole workflow (jobs.*.steps) or, as in the README, a bare list of steps.
  const steps = Array.isArray(parsed) ? parsed : Object.values(parsed.jobs ?? {}).flatMap(job => job.steps ?? []);
  return steps.filter(step => typeof step.uses === 'string' && step.uses.startsWith('YusefSyed/scopehaven-oss@'));
}
test('the CI guide and the README use the root action with inputs it declares, and name the repository', async () => {
  for (const path of ['docs/guides/ci-in-five-minutes.md', 'README.md']) {
    const text = await read(path);
    const blocks = workflowsIn(text);
    assert.ok(blocks.length >= 1, `${path}: a workflow that uses YusefSyed/scopehaven-oss@`);
    for (const block of blocks) {
      const steps = rootActionSteps(block);
      assert.ok(steps.length >= 1, `${path}: a step with uses: YusefSyed/scopehaven-oss@`);
      for (const step of steps) for (const name of Object.keys(step.with ?? {})) assert.ok(Object.hasOwn(root.inputs, name), `${path}: input ${name}`);
    }
    assert.match(text, /YusefSyed\/scopehaven-oss/, path);
    assert.doesNotMatch(text, /placeholder/i, `${path}: the repository name is final, no placeholder note`);
  }
});

test('the inner action README documents the root wrapper, and the MCP target README links its guide', async () => {
  const action = await read('integrations/github-action/README.md');
  assert.match(action, /uses: YusefSyed\/scopehaven-oss@/);
  assert.match(action, /\$\/integrations\/github-action/);
  assert.match(await read('integrations/mcp-target/README.md'), /docs\/guides\/mcp-target-from-claude-code-and-cursor\.md/);
  const readme = await read('README.md');
  const start = readme.indexOf('## Use it from CI or from your agent'); assert.ok(start >= 0, 'the README has the CI and agent section'); const end = readme.indexOf('\n## ', start + 1); const block = readme.slice(start, end === -1 ? readme.length : end);
  for (const link of ['docs/guides/ci-in-five-minutes.md', 'docs/guides/mcp-target-from-claude-code-and-cursor.md']) assert.ok(block.includes(link), link);
});
