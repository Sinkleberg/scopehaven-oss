import test from 'node:test';
import assert from 'node:assert/strict';
import { createLocalAccess, renderLaunchPage } from '../src/local-access.mjs';

const token = 'A'.repeat(32);
const request = authorization => ({ headers: { authorization } });

test('default capabilities contain 32 random bytes and differ across launches', () => {
  const first = createLocalAccess(), second = createLocalAccess();
  assert.match(first.token, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(Buffer.from(first.token, 'base64url').length, 32);
  assert.notEqual(first.token, second.token);
  assert.equal(first.authorize(request(`Bearer ${first.token}`)), true);
  assert.equal(first.authorize(request(`Bearer ${second.token}`)), false);
});

test('provided tokens accept only bounded URL-safe ASCII and validation never echoes rejected values', () => {
  for (const accepted of ['A'.repeat(32), '_-0abc'.repeat(20), 'Z'.repeat(128)]) {
    assert.equal(createLocalAccess({ token: accepted }).authorize(request(`Bearer ${accepted}`)), true);
  }
  for (const rejected of ['', 'a'.repeat(31), 'a'.repeat(129), null, 123, ['a'.repeat(32)], 'private-secret with spaces'.padEnd(40, 'a'), 'a'.repeat(32) + '\r\n', 'é'.repeat(32), 'a'.repeat(32) + '=']) {
    assert.throws(() => createLocalAccess({ token: rejected }), error => !error.message.includes('private-secret'));
  }
});

test('authorization requires an exact single Bearer header and safely rejects unknown requests', () => {
  const access = createLocalAccess({ token });
  assert.equal(access.authorize(request(`Bearer ${token}`)), true);
  for (const header of [undefined, null, 123, [`Bearer ${token}`], `bearer ${token}`, `Basic ${token}`, `Bearer  ${token}`, ` Bearer ${token}`, `Bearer ${token} `, `Bearer ${token}\n`, `Bearer ${token}, Bearer ${token}`, `Bearer ${token}\r\nX-Evil: injected`]) {
    assert.equal(access.authorize(request(header)), false);
  }
  for (const req of [undefined, null, {}, { headers: null }, { headers: [] }, { headers: { Authorization: `Bearer ${token}` } }]) assert.equal(access.authorize(req), false);
  const hostile = { get headers() { throw new Error('Do not expose request data'); } };
  assert.equal(access.authorize(hostile), false);
});

test('comparison accepts only an equal token including same-length mismatches and different lengths', () => {
  const access = createLocalAccess({ token });
  for (const candidate of ['B'.repeat(32), `${token.slice(0, -1)}B`, `B${token.slice(1)}`, `${token}A`, 'B'.repeat(128)]) assert.equal(access.authorize(request(`Bearer ${candidate}`)), false);
  assert.equal(access.authorize(request(`Bearer ${token}`)), true);
});

test('expiry is enforced at the exact boundary and invalid clocks cannot authorize', () => {
  let time = 1000;
  const access = createLocalAccess({ token, now: () => time, ttlMs: 100 });
  assert.equal(access.expiresAt, 1100);
  time = 1099; assert.equal(access.authorize(request(`Bearer ${token}`)), true);
  time = 1100; assert.equal(access.authorize(request(`Bearer ${token}`)), false);
  time = 1101; assert.equal(access.authorize(request(`Bearer ${token}`)), false);
  time = NaN; assert.equal(access.authorize(request(`Bearer ${token}`)), false);
  assert.equal(createLocalAccess({ token, now: () => 10, ttlMs: 0 }).authorize(request(`Bearer ${token}`)), false);
  const defaults = createLocalAccess({ token, now: () => 10 }); assert.equal(defaults.expiresAt, 10 + 8 * 60 * 60 * 1000);
  for (const options of [{ ttlMs: -1 }, { ttlMs: Infinity }, { now: null }, { now: () => NaN }]) assert.throws(() => createLocalAccess({ token, ...options }));
  let throwing = false;
  const changedClock = createLocalAccess({ token, now: () => { if (throwing) throw new Error('Clock failed'); return 0; } });
  throwing = true; assert.equal(changedClock.authorize(request(`Bearer ${token}`)), false);
});

test('private launch HTML has exactly the intended numeric loopback fragment link and no active external content', () => {
  const origin = 'http://127.0.0.1:4317';
  const html = renderLaunchPage(origin, token);
  assert.deepEqual([...html.matchAll(/<a\b[^>]*href="([^"]+)"/g)].map(match => match[1]), [`${origin}#access=${token}`]);
  assert.match(html, /name="referrer" content="no-referrer"/);
  assert.match(html, /referrerpolicy="no-referrer"/);
  assert.doesNotMatch(html, /<script|<iframe|<img|<form|<link\b|src=|url\(|onload=|onclick=|localStorage|sessionStorage|document\.cookie/i);
  assert.doesNotMatch(html, /certification|certified|hosted IAM/i);
  assert.match(renderLaunchPage('http://127.0.0.1:80', token), /127\.0\.0\.1:80#access=/);
});

test('launch rendering rejects origin overrides and HTML injection before constructing a link', () => {
  for (const origin of ['http://localhost:4317', 'http://127.1:4317', 'http://2130706433:4317', 'http://[::1]:4317', 'https://127.0.0.1:4317', 'http://127.0.0.1', 'http://127.0.0.1:0', 'http://127.0.0.1:65536', 'http://user@127.0.0.1:4317', 'http://127.0.0.1:4317/', 'http://127.0.0.1:4317/path', 'http://127.0.0.1:4317?redirect=external', 'http://127.0.0.1:4317#access=other', 'http://127.0.0.1:4317" onclick="evil', 'javascript:alert(1)', null]) {
    assert.throws(() => renderLaunchPage(origin, token), /Launch origin/);
  }
  assert.throws(() => renderLaunchPage('http://127.0.0.1:4317', `${token}"<script>`), /Invalid local launch capability/);
});
