import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, rm, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { MANIFEST_NAME, excluded, filesAt } from '../../packaging/build-release.mjs';
import { ROOT, SHEET, SITES, render, readFacts, shippedFiles } from './render.mjs';

// Reads only this repository's files and throwaway folders it makes; no network, no model, no saved run.
const real = path => readFile(join(ROOT, path), 'utf8');
// The scan with one more file in it, reading that file's text as given.
const scanWith = (path, text) => readFacts({ modules: [...Object.keys(SITES), path], read: file => file === path ? Promise.resolve(text) : real(file) });
// A throwaway folder holding `files`, staged in a new git repository.
async function checkout(files, { git = true } = {}) {
  const root = await mkdtemp(join(tmpdir(), 'scopehaven-data-handling-'));
  for (const [path, text] of Object.entries(files)) { await mkdir(dirname(join(root, path)), { recursive: true }); await writeFile(join(root, path), text); }
  if (git) { execFileSync('git', ['-C', root, 'init', '-q']); execFileSync('git', ['-C', root, 'add', '--', ...Object.keys(files)]); }
  return root;
}

test('docs/DATA-HANDLING.md matches what the source says', async () => {
  assert.equal(await readFile(join(ROOT, SHEET), 'utf8'), await render(), 'stale: run node integrations/data-handling/render.mjs --write');
});

test('a new network call site fails the render until it is reviewed', async () => {
  const modules = [...Object.keys(SITES), 'src/new-uploader.mjs'];
  const read = path => path === 'src/new-uploader.mjs' ? Promise.resolve("await fetch('https://collector.example/upload');") : real(path);
  await assert.rejects(readFacts({ read, modules }), /unreviewed network call site: src\/new-uploader\.mjs/);
});

test('a reviewed site that stops making network calls fails the render', async () => {
  const read = path => path === 'src/runner.mjs' ? Promise.resolve('export const x = 1;') : real(path);
  await assert.rejects(readFacts({ read, modules: Object.keys(SITES) }), /reviewed site no longer makes network calls: src\/runner\.mjs/);
});

test('a store method that could delete evidence fails the render', async () => {
  const read = async path => path === 'src/store.mjs'
    ? (await real(path)).replace('return { ready, save, get, list,', 'return { ready, save, get, list, deleteRun,')
    : real(path);
  await assert.rejects(readFacts({ read, modules: Object.keys(SITES) }), /store now exposes deleteRun/);
});

test('a fact the source no longer states fails the render instead of rendering a guess', async () => {
  const read = async path => path === 'src/store.mjs' ? (await real(path)).replace(/mode: 0o700/g, 'mode: 0o755') : real(path);
  await assert.rejects(readFacts({ read, modules: Object.keys(SITES) }), /evidence directory mode 0700/);
});

// F5: the scan used to read only .mjs under src, integrations and examples, and skipped fixtures/ and upstream/.
test('a shipped file the old scan could not see fails the render when it reaches the network', async t => {
  const cases = {
    'integrations/new/fixtures/app.mjs': "import { createServer } from 'node:http';",
    'integrations/new/upstream/vendored.mjs': "import { connect } from 'node:net';",
    'integrations/new/test/fixtures/app.mjs': "import { lookup } from 'node:dns/promises';",
    'design/new/server.mjs': "import { request } from 'node:https';",
    'public/new.js': "await fetch('https://collector.example/upload');",
    'public/new.html': "<script>fetch('https://collector.example/upload')</script>",
    'public/remote.html': '<script src="https://cdn.example/a.js"></script>',
    'public/protocol-relative.html': '<img src="//cdn.example/a.png">',
    'public/new.css': '@import "https://cdn.example/a.css";',
    'packaging/new.cjs': "const net = require('node:net');",
    'packaging/new.mts': "const tls = await import('node:tls');",
    'packaging/h2.mjs': "import { connect } from 'node:http2';",
    'packaging/builtin.mjs': "process.getBuiltinModule('net');",
    'packaging/client.mjs': "import { request } from 'undici';",
    'packaging/socket.js': "new WebSocket('wss://collector.example');",
    'packaging/beacon.js': "navigator.sendBeacon('/x');",
    'packaging/tool.mjs': "execFileSync('curl', ['https://collector.example']);",
    'packaging/container.mjs': "spawn('docker', ['run', '--network', 'container:db', 'img']);",
    'integrations/new/a.py': 'import socket\n',
    'integrations/new/list.py': 'import json, requests\n',
    'integrations/new/indented.py': 'try:\n    import httpx\nexcept ImportError:\n    pass\n',
    'integrations/new/from.py': 'from http import client\n',
    'integrations/new/url.py': 'from urllib import request\n',
    'integrations/new/hosted.py': 'from langchain_openai import OpenAIEmbeddings\n',
    'integrations/new/dynamic.py': "__import__('socket')\n",
    'integrations/new/tool.py': "subprocess.run(['curl', url])\n",
    'integrations/new/a.sh': 'curl https://collector.example/upload\n',
    'integrations/new/clone.sh': 'git -C here clone "$SOURCE"\n',
    'integrations/new/install.sh': 'npm install left-pad\n',
    'integrations/new/tcp.sh': 'exec 3<>/dev/tcp/collector.example/80\n',
    'integrations/new/a.sh.example': 'wget https://collector.example/upload\n',
    'integrations/new/launcher': "#!/bin/sh\nnode --input-type=module <<'EOF'\nimport { createServer } from 'node:net';\nEOF\n",
    'integrations/new/runner': '#!/usr/bin/env python3\nimport socket\n',
    'integrations/new/noded': "#!/usr/bin/env node\nawait fetch('https://collector.example');\n",
    'integrations/new/step.yml': 'steps:\n  - uses: someone/action@abc\n',
    'integrations/new/job.sql': "select net.http_post('https://collector.example');\n",
    'integrations/new/policy.rego': 'x := http.send({"method": "get"})\n',
  };
  for (const [path, text] of Object.entries(cases)) await t.test(path, () => assert.rejects(scanWith(path, text), new RegExp(`unreviewed network call site: ${path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')};`)));
});

test('text that only looks like network use is not a site', async t => {
  const cases = {
    'packaging/fs.mjs': "import { readFile } from 'node:fs';",
    'packaging/lookalike.mjs': "import x from 'network-utils'; const y = await import('./net');",
    'packaging/ssh-keygen.mjs': "spawnSync('ssh-keygen', ['-Y', 'sign']);",
    'packaging/header.mjs': "const site = req.headers['sec-fetch-site'];",
    'packaging/compose.mjs': "execFileSync('docker', ['exec', name, 'psql']);",
    'integrations/new/status.py': 'from http import HTTPStatus\n',
    'integrations/new/lookalike.py': 'import socketless\nfrom ssl_helpers import x\n',
    'integrations/new/parse.py': 'from urllib.parse import urlparse\n',
    'integrations/new/link.html': '<a href="https://nodejs.org/">Node.js</a>',
    'integrations/new/local.css': 'a { background: url("./a.png"); }',
    'integrations/new/a.sh': 'command -v node; echo "see the docs"\n',
    'integrations/new/step.yml': 'steps:\n  - run: node a.mjs\n',
    'integrations/new/job.sql': 'select 1;\n',
    'docs/mentions.md': "Call fetch('https://collector.example') or import socket.\n",
    'integrations/new/data.json': '{"code": "await fetch(url)"}',
  };
  for (const [path, text] of Object.entries(cases)) await t.test(path, async () => { assert.ok(!(await scanWith(path, text)).sites.includes(path)); });
});

test('a shipped file of a kind the scan does not know fails the render', async () => {
  await assert.rejects(scanWith('integrations/new/uploader.rb', "require 'net/http'\n"), /of a kind the scan does not know: integrations\/new\/uploader\.rb/);
});

test('a reviewed site the release stops shipping fails the render', async () => {
  const read = real, modules = Object.keys(SITES).filter(file => file !== 'integrations/observers/fixtures/free-port.mjs');
  await assert.rejects(readFacts({ read, modules }), /reviewed site no longer makes network calls: integrations\/observers\/fixtures\/free-port\.mjs/);
});

test('the scan reads every file the release builder ships, and nothing it leaves out', async () => {
  const listed = new Set(await shippedFiles());
  const ships = filesAt('HEAD').filter(file => !excluded(file.path)).map(file => file.path);
  assert.deepEqual(ships.filter(file => !listed.has(file) && existsSync(join(ROOT, file))), []);
  assert.deepEqual([...listed].filter(excluded), []);
  for (const file of ['scopehaven', 'integrations/observers/fixtures/free-port.mjs', 'public/app.js', 'integrations/schedule/run-local.sh']) assert.ok(listed.has(file), file);
  for (const file of ['integrations/data-handling/data-handling.test.mjs', 'packaging/osv-snapshot.mjs']) assert.ok(!listed.has(file), file);
});

test('a fixture added to a checkout reaches the scan through the release builder\'s rules', async t => {
  const planted = {
    'integrations/new/fixtures/uploader.py': 'import socket\n',
    'integrations/new/uploader.test.mjs': "await fetch('https://collector.example');",
    'coordination/note.mjs': "await fetch('https://collector.example');",
    'packaging/osv-snapshot.mjs': "await fetch('https://collector.example');",
    '.gitignore': 'ignored.mjs\n',
    'tracked-then-deleted.mjs': 'export {};',
  };
  const root = await checkout(planted);
  t.after(() => rm(root, { recursive: true, force: true }));
  await writeFile(join(root, 'not-yet-committed.mjs'), 'export {};');
  await writeFile(join(root, 'ignored.mjs'), "await fetch('https://collector.example');");
  await unlink(join(root, 'tracked-then-deleted.mjs'));
  assert.deepEqual(await shippedFiles(root), ['integrations/new/fixtures/uploader.py', 'not-yet-committed.mjs']);
  // Facts come from the real tree; only the file list and the planted files come from the throwaway one.
  const read = path => Object.hasOwn(planted, path) ? Promise.resolve(planted[path]) : path === 'not-yet-committed.mjs' ? Promise.resolve('export {};') : real(path);
  await assert.rejects(readFacts({ root, read }), /unreviewed network call site: integrations\/new\/fixtures\/uploader\.py;/);
});

test('a release copy is scanned from its own manifest, and a folder with neither manifest nor git fails', async t => {
  const release = await checkout({ [MANIFEST_NAME]: JSON.stringify({ files: [{ path: 'b.mjs' }, { path: 'a/fixtures/c.py' }] }) }, { git: false });
  const bare = await checkout({ 'a.mjs': 'export {};' }, { git: false });
  t.after(() => Promise.all([release, bare].map(root => rm(root, { recursive: true, force: true }))));
  assert.deepEqual(await shippedFiles(release), ['a/fixtures/c.py', 'b.mjs']);
  await assert.rejects(shippedFiles(bare), /cannot list the shipped files/);
});

test('the sheet says what the scan covers and what it cannot see', async () => {
  const sheet = await render();
  for (const phrase of ['Every shipped code file', '`packaging/build-release.mjs`', 'fixtures and vendored source included', 'must be declared as data', 'Files the release leaves out', 'matching its text, not by parsing it']) assert.ok(sheet.includes(phrase), phrase);
  assert.ok(!sheet.includes('test files excluded'));
  for (const file of await shippedFiles()) if (Object.hasOwn(SITES, file)) assert.ok(sheet.includes(`| \`${file}\` | ${SITES[file]} |`), file);
});
