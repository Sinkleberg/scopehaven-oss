// The gate, OTel collector and MCP proxy always listen on 127.0.0.1. A non-integer
// port (for example an object from a JSON config) would make server.listen()
// ignore that host, so the constructors refuse it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHoldGate } from './gate.mjs';
import { createOtelObserver } from '../observers/otel.mjs';
import { createMcpHttpProxy } from '../observers/mcp.mjs';

const objectPort = { port: 0, host: '::1' };
const bad = [objectPort, '0', -1, 65536, 1.5, null];

test('the hold gate refuses a port that is not an integer from 0 to 65535', () => {
  for (const port of bad) assert.throws(() => createHoldGate({ upstream: 'http://127.0.0.1:9', port }), /port must be an integer/);
});

test('the OTel collector refuses a port that is not an integer from 0 to 65535', () => {
  for (const port of bad) assert.throws(() => createOtelObserver({ port, services: ['svc'] }), /port must be an integer/);
});

test('the MCP proxy refuses a port that is not an integer from 0 to 65535', () => {
  for (const port of bad) assert.throws(() => createMcpHttpProxy({ upstream: 'http://127.0.0.1:9', port }), /port must be an integer/);
});

test('an integer port still listens on 127.0.0.1 only', async () => {
  const gate = createHoldGate({ upstream: 'http://127.0.0.1:9', port: 0 });
  await gate.start();
  try { assert.match(gate.url, /^http:\/\/127\.0\.0\.1:[1-9][0-9]*$/); }
  finally { await gate.stop(); }
});
