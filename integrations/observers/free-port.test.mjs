// The test helper that gives sinks free loopback ports (fixtures/free-port.mjs): distinct ports below the OS automatic
// range, and up to RETRIES retries, on fresh ports, when a bind loses the race to another process.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:net';
import { freePorts, onFreePorts, RETRIES, QUIET_BAND, automaticPortRange } from './fixtures/free-port.mjs';

const inUse = () => Object.assign(new Error('listen EADDRINUSE'), { code: 'EADDRINUSE' });

test('freePorts: distinct loopback ports, each free to bind', async () => {
  const ports = await freePorts(3);
  assert.equal(new Set(ports).size, 3);
  for (const port of ports) await new Promise((resolve, reject) => { const s = createServer(); s.once('error', reject); s.listen(port, '127.0.0.1', () => s.close(resolve)); });
});

test('onFreePorts: retries a lost bind (EADDRINUSE or a lost race) on fresh ports up to RETRIES times; other errors are not retried', async () => {
  assert.equal(RETRIES, 5);
  const seen = [];
  assert.equal(await onFreePorts(2, async (a, b) => { seen.push([a, b]); if (seen.length < 3) throw inUse(); return 'third'; }), 'third');
  assert.equal(seen.length, 3);
  assert.ok(seen.every(ports => ports.length === 2 && ports[0] !== ports[1]), 'each attempt takes distinct ports again');
  let calls = 0;
  await assert.rejects(onFreePorts(1, async () => { calls++; throw inUse(); }), e => e.code === 'EADDRINUSE');
  assert.equal(calls, RETRIES + 1);
  calls = 0;
  await assert.rejects(onFreePorts(1, async () => { calls++; throw new Error('other'); }), /other/);
  assert.equal(calls, 1);
  calls = 0;
  assert.equal(await onFreePorts(1, async () => ++calls, result => result < 3), 3);
  calls = 0;
  assert.equal(await onFreePorts(1, async () => ++calls, () => true), RETRIES + 1, 'the last lost race is returned as it is');
});

// A sink's port is never one the OS hands out on its own (a listen on port 0, an outgoing connection), so it is never a
// number another process was given and may still be sending to: it lies below the automatic range and the suite's fixed
// ports, and a port this process handed out recently is not handed out again.
test('freePorts: ports below the OS automatic range, never one this process handed out recently', async t => {
  const high = Math.min(QUIET_BAND.high, automaticPortRange().first - 1);
  if (high - QUIET_BAND.low + 1 < 1024) return t.skip(`this host's automatic range starts at ${automaticPortRange().first}: the OS picks the ports`);
  const seen = [];
  for (let i = 0; i < 20; i++) seen.push(...await freePorts(3));
  assert.ok(seen.every(port => port >= QUIET_BAND.low && port <= high), seen.join(' '));
  assert.equal(new Set(seen).size, seen.length, 'no port is handed out twice in a row of 60');
});
