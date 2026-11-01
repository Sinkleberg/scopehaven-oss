import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startServer } from '../src/server.mjs';

test('the server rejects non-integer ports before access or storage setup', async () => {
  let setupCalls = 0;
  const bad = [{ port: 0, host: '::1' }, '0', -1, 65536, 1.5, null, false, [], NaN, Infinity, 0n];
  for (const port of bad) {
    await assert.rejects(startServer({ port, env: {}, accessOptions: { now: () => { setupCalls++; throw new Error('unexpected-access-setup'); } } }), /Server port must be an integer from 0 to 65535/);
  }
  assert.equal(setupCalls, 0);
});

test('ephemeral and explicit integer ports keep the local server on 127.0.0.1', async t => {
  const dataDir = await mkdtemp(join(tmpdir(), 'scopehaven-port-'));
  t.after(() => rm(dataDir, { recursive: true, force: true }));
  const first = await startServer({ port: 0, dataDir, env: {} });
  const address = first.server.address();
  try {
    assert.equal(address.address, '127.0.0.1');
    assert.equal(address.family, 'IPv4');
    assert.match(first.origin, /^http:\/\/127\.0\.0\.1:[1-9][0-9]*$/);
  } finally { await first.close(); }
  const second = await startServer({ port: address.port, dataDir, env: {} });
  try { assert.equal(second.server.address().address, '127.0.0.1'); assert.equal(second.server.address().port, address.port); }
  finally { await second.close(); }
});
