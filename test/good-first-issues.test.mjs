// The good-first-issue drafts under .github/GOOD-FIRST-ISSUES/ and the labels beside them: issues.json parses, every
// body file exists and opens with its title, every repository path a body names in backticks exists in the tree (or is
// marked as a file the issue adds, or as a dead reference it removes), every label is defined in .github/labels.json,
// and both helper scripts only print unless --apply is given. Offline and local: a stand-in `gh` first on PATH records
// any call, the scripts run from outside the repository, and --apply is never run here.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const FOLDER = join(ROOT, '.github/GOOD-FIRST-ISSUES');
const ISSUES_SCRIPT = join(FOLDER, 'create-issues.sh');
const LABELS_SCRIPT = join(ROOT, '.github/create-labels.sh');
const issues = JSON.parse(readFileSync(join(FOLDER, 'issues.json'), 'utf8'));
const labels = JSON.parse(readFileSync(join(ROOT, '.github/labels.json'), 'utf8'));
const AREA = ['documentation', 'observer', 'check', 'cli', 'dashboard', 'docs-wording'];
const REQUIRED = ['good first issue', 'help wanted', 'bug', 'enhancement', ...AREA];
const TOP = ['docs/', 'src/', 'test/', 'integrations/', 'examples/', 'public/', 'packaging/', 'design/', '.github/'];
const TOP_FILES = new Set(['README.md', 'CONTRIBUTING.md', 'CHANGELOG.md', 'SECURITY.md', 'LICENSE', 'NOTICE', 'package.json', 'scopehaven', '.gitignore', '.node-version', '.nvmrc']);
const SECTIONS = ['## Pointers', '## Acceptance', '## Test', '## Labels', '## Effort'];
const FAKE_REPO = 'example-owner/example-repo';

// Backticked tokens that name a repository path: they start with a top-level folder or are a top-level file. A token
// followed by "(new)" (a file the issue adds) or "(not in this repository)" (a dead reference the issue removes) is skipped.
export function repositoryPaths(markdown) {
  const found = [];
  for (const match of markdown.matchAll(/`([^`\n]+)`(\s*\((?:new|not in this repository)\))?/g)) {
    const token = match[1];
    if (match[2] || !/^[A-Za-z0-9_./-]+$/.test(token)) continue;
    if (TOP.some(prefix => token.startsWith(prefix)) || TOP_FILES.has(token)) found.push(token);
  }
  return found;
}

// A stand-in gh, first on PATH, that records every call and fails. The scripts run from the temp folder, not the
// repository, so they must find their own root.
function stub(t) {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-first-issues-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const log = join(dir, 'gh-calls.log');
  writeFileSync(join(dir, 'gh'), `#!/bin/sh\nprintf '%s\\n' "$*" >> '${log}'\nexit 1\n`, { mode: 0o700 });
  return { dir, log };
}
const run = (script, args, bin) => spawnSync(script, args, { cwd: bin, env: { PATH: `${bin}:/usr/bin:/bin`, SCOPEHAVEN_NODE: process.execPath }, encoding: 'utf8', timeout: 60000 });

test('issues.json lists eight to ten drafts; each opens with its title, has two paragraphs and the sections in order, and carries good first issue plus one area label', () => {
  assert.ok(Array.isArray(issues) && issues.length >= 8 && issues.length <= 10, `${issues.length} drafts`);
  assert.equal(new Set(issues.map(i => i.title)).size, issues.length, 'titles are distinct');
  const drafts = readdirSync(FOLDER).filter(name => /^\d\d-.*\.md$/.test(name)).sort();
  assert.deepEqual(issues.map(i => i.body).sort(), drafts, 'every numbered draft is listed, and nothing else');
  for (const issue of issues) {
    const text = readFileSync(join(FOLDER, issue.body), 'utf8');
    assert.ok(text.startsWith(`# ${issue.title}\n\n`), `${issue.body} opens with its title`);
    const intro = text.slice(text.indexOf('\n\n') + 2, text.indexOf('\n## '));
    assert.ok(intro.split(/\n\n+/).filter(Boolean).length >= 2, `${issue.body}: two paragraphs before the pointers`);
    let at = 0;
    for (const heading of SECTIONS) { const next = text.indexOf(`\n${heading}\n`, at); assert.ok(next > at, `${issue.body} has ${heading}, in order`); at = next; }
    assert.ok(issue.labels.includes('good first issue'), `${issue.body} is a good first issue`);
    assert.equal(issue.labels.filter(label => AREA.includes(label)).length, 1, `${issue.body} has exactly one area label`);
    assert.equal(issue.labels.length, 2, `${issue.body}: good first issue plus the area label`);
    const listed = /\n## Labels\n\n([^\n]+)\n/.exec(text)?.[1] ?? '';
    assert.deepEqual(listed.split(', ').map(s => s.replaceAll('`', '')), issue.labels, `${issue.body}: the Labels section matches issues.json`);
    assert.match(/\n## Effort\n\n([^\n]+)/.exec(text)?.[1] ?? '', /\d+ (to \d+ )?hours/, `${issue.body}: effort in hours`);
  }
});

test('every repository path a draft names in backticks exists, unless marked (new) or (not in this repository)', () => {
  const missing = [];
  for (const issue of issues) {
    const paths = repositoryPaths(readFileSync(join(FOLDER, issue.body), 'utf8'));
    assert.ok(paths.length >= 3, `${issue.body} points at files`);
    for (const path of paths) if (!existsSync(join(ROOT, path))) missing.push(`${issue.body}: ${path}`);
  }
  assert.deepEqual(missing, []);
  assert.deepEqual(repositoryPaths('see `docs/a.md`, `docs/b.md` (new), `src/c.mjs` (not in this repository), `--json`, `data/x.json`, `README.md`'), ['docs/a.md', 'README.md']);
});

test('labels.json defines every required label once, with a 6-hex colour and a short description, and every label the drafts use', () => {
  assert.ok(Array.isArray(labels));
  const names = labels.map(label => label.name);
  assert.equal(new Set(names).size, names.length, 'no duplicate label');
  for (const required of REQUIRED) assert.ok(names.includes(required), required);
  for (const label of labels) {
    assert.match(label.color, /^[0-9a-f]{6}$/, label.name);
    assert.ok(typeof label.description === 'string' && label.description.length > 0 && label.description.length <= 100, `${label.name}: description`);
  }
  for (const issue of issues) for (const label of issue.labels) assert.ok(names.includes(label), `${issue.body}: ${label} is defined`);
});

test('create-issues.sh with a repository and no --apply prints one gh command per draft, pipes the body without its heading, and never calls gh', t => {
  const { dir, log } = stub(t);
  const r = run(ISSUES_SCRIPT, [FAKE_REPO], dir);
  assert.equal(r.status, 0, r.stderr);
  const lines = r.stdout.trim().split('\n');
  assert.equal(lines.length, issues.length);
  issues.forEach((issue, i) => {
    assert.ok(lines[i].startsWith(`sed '1{/^# /d;}' '.github/GOOD-FIRST-ISSUES/${issue.body}' | gh issue create --repo '${FAKE_REPO}' --title '`), lines[i]);
    for (const label of issue.labels) assert.ok(lines[i].includes(` --label '${label}'`), `${issue.body}: ${label}`);
    assert.ok(lines[i].endsWith(' --body-file -'), lines[i]);
  });
  assert.match(r.stderr, /Printed only; nothing was sent/);
  assert.equal(existsSync(log), false, 'gh was never called');
  const body = spawnSync('sed', ['1{/^# /d;}', join(FOLDER, issues[0].body)], { encoding: 'utf8' });
  assert.equal(body.status, 0, body.stderr);
  assert.equal(body.stdout.startsWith('#'), false, 'the title heading is dropped');
  assert.ok(body.stdout.includes('\n## Acceptance\n'), 'the rest of the draft is the body');
});

test('create-labels.sh with a repository and no --apply prints one gh command per label and never calls gh', t => {
  const { dir, log } = stub(t);
  const r = run(LABELS_SCRIPT, [FAKE_REPO], dir);
  assert.equal(r.status, 0, r.stderr);
  const lines = r.stdout.trim().split('\n');
  assert.equal(lines.length, labels.length);
  labels.forEach((label, i) => {
    assert.equal(lines[i], `gh label create '${label.name}' --repo '${FAKE_REPO}' --color '${label.color}' --description '${label.description.replaceAll("'", "'\\''")}' --force`);
  });
  assert.match(r.stderr, /Printed only; nothing was sent/);
  assert.equal(existsSync(log), false, 'gh was never called');
});

test('both scripts are POSIX sh, exit 2 on a missing or malformed repository or an unknown flag, and look for gh only behind --apply', t => {
  const { dir, log } = stub(t);
  for (const script of [ISSUES_SCRIPT, LABELS_SCRIPT]) {
    const text = readFileSync(script, 'utf8');
    assert.ok(text.startsWith('#!/bin/sh\n'), `${script} is sh`);
    assert.equal(spawnSync('/bin/sh', ['-n', script]).status, 0, `${script} parses`);
    assert.notEqual(statSync(script).mode & 0o100, 0, `${script} is executable`);
    assert.match(text, /if \[ "\$mode" = --apply \]; then\n\s+command -v gh/, `${script}: gh is looked up only on the apply branch`);
    assert.equal((text.match(/\beval\b/g) || []).length, 1, `${script}: one eval, on the apply branch`);
    for (const args of [[], ['not-a-repo'], ['--apply'], [FAKE_REPO, '--now'], [FAKE_REPO, '--apply', 'extra']]) {
      const r = run(script, args, dir);
      assert.equal(r.status, 2, `${script} ${args.join(' ')}: ${r.stderr}`);
      assert.match(r.stderr, /Usage/);
    }
  }
  assert.equal(existsSync(log), false, 'gh was never called');
});
