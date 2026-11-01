// The shared mail address rules (src/mail-address.mjs): envelope normalization, canonical mailboxes only, and the alias
// ambiguity of declared addresses. Each allowed form next to the forbidden one beside it.
import test from 'node:test';
import assert from 'node:assert/strict';
import { recipientOf, mailboxOf, addressResource, aliasStems } from '../src/mail-address.mjs';
import { validateSmtpConfig } from '../src/smtp-rules.mjs';

const VIP = 'vip@customers.example', IDN = 'xn--bcher-kva.example';

test('envelope normalization: case, one trailing dot and a U-label reach the same address; a source route is dropped and flagged', () => {
  assert.deepEqual(mailboxOf('VIP@Customers.Example.'), { address: VIP, local: 'vip', domain: 'customers.example', literal: false, sourceRoute: false });
  assert.equal(mailboxOf('vip@bücher.example').address, `vip@${IDN}`);
  assert.deepEqual(mailboxOf('@relay.example,@relay2.example:vip@customers.example'), { address: VIP, local: 'vip', domain: 'customers.example', literal: false, sourceRoute: true });
  assert.deepEqual(mailboxOf('vip@[192.0.2.1]'), { address: 'vip@192.0.2.1', local: 'vip', domain: '192.0.2.1', literal: true, sourceRoute: false });
});

test('only a canonical mailbox is one: quoted, commented, escaped, non-ASCII, relay-routed or malformed forms are not', () => {
  for (const ok of ['vip@customers.example', 'v.i.p@customers.example', "o'neil@customers.example", 'vip+tag@customers.example', 'vip_x-y@customers.example']) assert.notEqual(mailboxOf(ok), null, ok);
  for (const bad of ['"vip"@customers.example', 'vip(x)@customers.example', '(x)vip@customers.example', 'v\\ip@customers.example', 'vïp@customers.example',
    'Kevin@customers.example', 'vip%customers.example@relay.example', 'relay!vip@customers.example', '.vip@customers.example', 'vip.@customers.example',
    'v..ip@customers.example', 'vip@customers.example..', 'vip@straße.example', 'vip@ex‍ample.example']) assert.equal(mailboxOf(bad), null, bad);
  for (const unreadable of ['Vip <vip@customers.example>', 'vip @customers.example', 'vip@', '@customers.example', 'vip', 42, null]) assert.equal(recipientOf(unreadable), null, String(unreadable));
});

test('a recipient without a canonical mailbox keeps its domain: it is still a send to that domain', () => {
  assert.deepEqual(recipientOf('"vip"@Customers.Example'), { domain: 'customers.example', literal: false, sourceRoute: false, mailbox: null });
  assert.equal(recipientOf('Kevin@customers.example').domain, 'customers.example');
  assert.equal(recipientOf('vip%customers.example@relay.example').domain, 'relay.example');
  assert.equal(recipientOf('vip@customers.example..').domain, 'customers.example.');
});

test('alias stems: "+" or "-" subaddress with dots removed, and "+" subaddress with ".", "_" and "-" removed', () => {
  assert.deepEqual(['vip', 'v.ip', 'vip+refund', 'vip-refund', 'v_ip', 'v-ip', 'first.last', 'jean-luc', '-vip', 'vipp'].map(aliasStems),
    [['vip', 'vip'], ['vip', 'vip'], ['vip', 'vip'], ['vip', 'viprefund'], ['v_ip', 'vip'], ['v', 'vip'], ['firstlast', 'firstlast'], ['jean', 'jeanluc'], ['-vip', 'vip'], ['vipp', 'vipp']]);
});

test('alias ambiguity: subaddresses, dotted and Proton-style forms of a declared address are ambiguous; a different real address stays a plain "*"', () => {
  const declared = new Set([VIP, 'first.last@customers.example']);
  for (const form of ['vip+refund@customers.example', 'vip-refund@customers.example', 'v.ip@customers.example', 'v.i.p+x@customers.example', 'v_ip@customers.example',
    'v-ip@customers.example', 'firstlast@customers.example', 'first.last-x@customers.example', 'first_last@customers.example'])
    assert.deepEqual(addressResource(mailboxOf(form), declared), { resource: '*', ambiguous: true }, form);
  for (const plain of ['vipp@customers.example', 'vi@customers.example', 'other@customers.example', 'other+tag@customers.example', 'first@customers.example'])
    assert.deepEqual(addressResource(mailboxOf(plain), declared), { resource: '*', ambiguous: false }, plain);
  // The same local part at another domain is another mailbox.
  assert.deepEqual(addressResource(mailboxOf('v.ip@other.example'), declared), { resource: '*', ambiguous: false });
});

test('addressResource: a declared address names itself, but is ambiguous when another declared address is an alias of it', () => {
  assert.deepEqual(addressResource(mailboxOf('VIP@customers.example.'), new Set([VIP])), { resource: VIP, ambiguous: false });
  assert.deepEqual(addressResource(mailboxOf('vip@customers.example'), [VIP]), { resource: VIP, ambiguous: false }, 'an array of declared addresses works too');
  assert.deepEqual(addressResource(mailboxOf('vip@customers.example'), undefined), { resource: '*', ambiguous: false }, 'a domain that declares no address');
  // vip@ and vip+refund@ both declared: a send to either may reach the other's mailbox.
  const pair = new Set([VIP, 'vip+refund@customers.example']);
  assert.deepEqual(addressResource(mailboxOf('vip+refund@customers.example'), pair), { resource: 'vip+refund@customers.example', ambiguous: true });
  assert.deepEqual(addressResource(mailboxOf('vip@customers.example'), pair), { resource: VIP, ambiguous: true });
  assert.deepEqual(addressResource(mailboxOf('vip@customers.example'), new Set([VIP, 'vipp@customers.example'])), { resource: VIP, ambiguous: false });
});

test('profile rules: a declared address must be canonical, or it could never name itself', () => {
  const base = { port: 47000, domains: [{ domain: 'customers.example', addresses: [VIP] }] };
  assert.doesNotThrow(() => validateSmtpConfig(base));
  for (const bad of ['v..ip@customers.example', '.vip@customers.example', 'vip.@customers.example', 'vip%x@customers.example', 'relay!vip@customers.example'])
    assert.throws(() => validateSmtpConfig({ ...base, domains: [{ domain: 'customers.example', addresses: [bad] }] }), /canonical/, bad);
});
