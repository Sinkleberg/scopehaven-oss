import test from 'node:test';
import assert from 'node:assert/strict';
import { open, readFile, stat } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

// docs/demo lets a reader see the product without installing it: a short GIF of the false-success refund on the synthetic
// test support app, and two HTML exports from the same runs. The assets must exist, stay small enough for a README to
// load, and carry no path from the machine that produced them (the exports are made in a private directory).
const DEMO = fileURLToPath(new URL('../docs/demo/', import.meta.url));
const GIF = 'false-success-refund.gif', EXPORTS = ['vulnerable-run.html', 'repaired-comparison.html'];
const GIF_LIMIT = 3_000_000;
const LOCAL_PATHS = ['/Users/', '/var/folders', '/private/tmp'];

test('the demo GIF exists, is a GIF, and is under 3 MB', async () => {
  const info = await stat(DEMO + GIF);
  assert.ok(info.isFile(), `${GIF} is not a file`);
  assert.ok(info.size > 0 && info.size < GIF_LIMIT, `${GIF} is ${info.size} bytes; the limit is ${GIF_LIMIT}`);
  const handle = await open(DEMO + GIF);
  try {
    const header = Buffer.alloc(6);
    await handle.read(header, 0, 6, 0);
    assert.match(header.toString('latin1'), /^GIF8[79]a$/, `${GIF} does not start with a GIF header`);
  } finally { await handle.close(); }
});

test('both HTML exports exist, are HTML documents, and embed no local path', async () => {
  for (const name of EXPORTS) {
    const html = await readFile(DEMO + name, 'utf8');
    assert.match(html, /^<!doctype html>/i, `${name} is not an HTML document`);
    for (const needle of LOCAL_PATHS) assert.ok(!html.includes(needle), `${name} contains ${needle}`);
  }
});

test('docs/demo/README.md names the GIF and both exports', async () => {
  const readme = await readFile(DEMO + 'README.md', 'utf8');
  for (const name of [GIF, ...EXPORTS]) assert.ok(readme.includes(name), `docs/demo/README.md does not name ${name}`);
});
