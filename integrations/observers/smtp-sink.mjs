// SMTP sink: a loopback mail server for the application's outbound mail
// (configuration and routing: src/smtp-rules.mjs). It accepts every message and
// never relays one, so no mail the app sends during a test leaves this machine
// through it. Each recipient of a completed message is one "send" effect named by
// the recipient's domain. Windows, witnesses and the quiet period are kept by the
// shared sink ledger (sink-ledger.mjs).
//
// It speaks a small ESMTP subset: HELO/EHLO, MAIL, RCPT (UTF-8 addresses; domains compared as A-labels), DATA (dot-unstuffed),
// RSET, NOOP, VRFY, QUIT, and AUTH PLAIN/LOGIN, which it accepts without keeping
// anything (so an app configured with a mail login still sends). It offers no
// STARTTLS: a client that requires TLS cannot send, and nothing reaches the sink.
// A window is partial (beyond the ledger's rules) when a message was over
// maxMessageBytes, a transaction was cut off before its message ended, a message
// had more than 100 recipients, a command was malformed or unrecognized, a
// connection was dropped at the limit, or the witness message also went to
// another recipient, or a recipient was an address literal ([198.51.100.9],
// [IPv6:...]): declared domains are names, and a literal could address one. It is
// also partial when a recipient's local part is not a plain dot-atom (quoted,
// commented, escaped or non-ASCII: another written form of a mailbox), or when a
// recipient is not declared but could be a declared mailbox under common alias rules
// (a "+" or "-" subaddress, or the same local part with dots): src/mail-address.mjs, or when a
// recipient's domain is longer than an event name (128 characters; it is no event).
// committed: the message reached the sink in full (DATA ended and was accepted).
// Nothing is delivered; the effect recorded is the app's attempt to send.
// Recipient addresses, senders, subjects and bodies are digested, never stored.
// smtp-sink/2 (FIX-02, SURPASS-BYPASS-01 A-21): the sink holds its port on both loopback addresses, 127.0.0.1 and [::1], each bound
// exclusively, with one connection handler. A mail route written with a name (localhost) may resolve to ::1 first, so a listener another
// process held on [::1] at the sink's port would take the app's mail. If either bind fails, the sink does not start; a later one cannot bind.
import { createServer } from 'node:net';
import { createHash } from 'node:crypto';
import { domainToASCII } from 'node:url';
import { makeEffect } from './events.mjs';
import { createSinkLedger } from './sink-ledger.mjs';
import { validateSmtpConfig } from '../../src/smtp-rules.mjs';
// The shared recipient rules (also the provider feed's): dot-atom local parts only, and alias ambiguity.
import { mailboxOf, addressResource } from '../../src/mail-address.mjs';

export const SMTP_LIMITS = Object.freeze({ retainedMessages: 20000, maxConnections: 64, idleMs: 30000, lineBytes: 4096, recipients: 100, dataLineFlushBytes: 1024 * 1024 });
// The loopback addresses the sink holds its port on (smtp-sink/2), each by a listener of its own with its own connection limit.
export const SMTP_SINK_ADDRESSES = Object.freeze(['127.0.0.1', '::1']);
const NONCE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;
const sha = value => createHash('sha256').update(value).digest('hex');
// The address inside <...> of a MAIL FROM or RCPT TO argument; null when unparsable. A source route
// ("@relay,@relay2:") is dropped, as RFC 5321 directs. The domain is in its ASCII form (an internationalized
// domain as its A-label, so SMTPUTF8 mail to a U-label matches the declared name); an address literal stays.
function envelopeAddress(line, verb) {
  const m = new RegExp(`^${verb}:\\s*<([^<>\\s]*)>(?:\\s|$)`, 'i').exec(line);
  if (!m) return null;
  if (m[1] === '') return { address: '', local: '', domain: '' };
  const mailbox = m[1].replace(/^@[^:,]+(?:,@[^:,]+)*:/, '');
  const at = mailbox.lastIndexOf('@');
  if (at < 1 || at === mailbox.length - 1) return null;
  const host = mailbox.slice(at + 1).replace(/\.$/, '');
  const literal = /^\[(.*)\]$/.exec(host);
  const domain = literal ? literal[1].toLowerCase() : domainToASCII(host);
  return domain ? { address: `${mailbox.slice(0, at)}@${domain}`.toLowerCase(), local: mailbox.slice(0, at), domain, literal: literal !== null, raw: m[1] } : null;
}
const utf8 = new TextDecoder('utf-8', { fatal: true });

// retainedMessages: operator code only (a profile cannot set it).
export function createSmtpSink({ instanceId = 'smtp-sink-1', retainedMessages = SMTP_LIMITS.retainedMessages, ...config }) {
  const cfg = validateSmtpConfig({ ...config, type: 'smtp-sink' }, config.witness ? { [config.witness.actorId]: {} } : undefined);
  const observer = { kind: 'smtp-sink-recorder', instanceId };
  const ledger = createSinkLedger({ prefix: 'smtp', unit: 'message', retained: retainedMessages });
  const declared = new Map(cfg.domains.map(d => [d.domain, new Set(d.addresses)]));
  const sockets = new Set();
  let servers = null;

  function onConnection(socket) {
    sockets.add(socket);
    socket.setTimeout(SMTP_LIMITS.idleMs);
    let buffer = Buffer.alloc(0), mode = 'command', tx = null, hash = null, atLineStart = true;
    const reply = line => { if (!socket.destroyed) socket.write(`${line}\r\n`); };
    // A transaction cut off before its message ended: incomplete, never committed.
    const cut = () => { if (tx && !tx.done) { tx.done = true; tx.aborted = true; } tx = null; };
    const malformed = kind => { ledger.record({ kind }); cut(); reply('500 malformed input; closing'); socket.end(); socket.destroy(); };
    socket.on('timeout', () => { cut(); socket.destroy(); });
    socket.on('error', () => {});
    socket.on('close', () => { cut(); sockets.delete(socket); });
    socket.on('data', chunk => { buffer = buffer.length ? Buffer.concat([buffer, chunk]) : chunk; drain(); });
    reply('220 scopehaven-sink ESMTP loopback capture; never relays');

    function dataLine(bytes, ended) {
      // Dot-unstuffing applies at the start of a line only.
      let line = bytes;
      if (atLineStart && line[0] === 0x2e) line = line.subarray(1);
      tx.bytes += line.length + (ended ? 2 : 0);
      if (tx.bytes > cfg.maxMessageBytes) tx.overLimit = true;
      else { hash.update(line); if (ended) hash.update('\r\n'); }
      atLineStart = ended;
    }
    function endOfData() {
      mode = 'command';
      tx.data = hash.digest('hex'); hash = null;
      if (tx.overLimit) { tx.done = true; tx = null; return reply('552 message exceeds the size limit'); }
      tx.outcome = 'committed';
      // A witness message goes to the witness only; mixed recipients are never hidden as a witness.
      if (tx.pendingNonces.length && !tx.recipients.length) tx.witnessNonces = tx.pendingNonces;
      else if (tx.pendingNonces.length) tx.mixedWitness = true;
      tx.done = true; tx = null;
      reply('250 accepted (captured, not relayed)');
    }
    function drain() {
      while (!socket.destroyed) {
        const nl = buffer.indexOf(0x0a);
        if (mode === 'data') {
          if (nl < 0) {
            // A very long body line: count it now, keep reading the same line.
            if (buffer.length > SMTP_LIMITS.dataLineFlushBytes) { const keep = buffer[buffer.length - 1] === 0x0d ? 1 : 0; dataLine(buffer.subarray(0, buffer.length - keep), false); buffer = buffer.subarray(buffer.length - keep); }
            return;
          }
          const raw = buffer.subarray(0, nl), line = raw[raw.length - 1] === 0x0d ? raw.subarray(0, raw.length - 1) : raw;
          buffer = buffer.subarray(nl + 1);
          if (atLineStart && line.length === 1 && line[0] === 0x2e) { endOfData(); continue; }
          dataLine(line, true);
          continue;
        }
        if (nl < 0) { if (buffer.length > SMTP_LIMITS.lineBytes) malformed('malformed'); return; }
        if (nl > SMTP_LIMITS.lineBytes) return malformed('malformed');
        // Commands are UTF-8 (SMTPUTF8 is offered); bytes that are not are malformed.
        let line;
        try { line = utf8.decode(buffer.subarray(0, nl)).replace(/\r$/, ''); } catch { return malformed('malformed'); }
        buffer = buffer.subarray(nl + 1);
        command(line);
      }
    }
    function command(line) {
      // AUTH continuation lines are read and dropped: credentials are never kept.
      if (mode === 'auth-one') { mode = 'command'; return reply(line === '*' ? '501 authentication cancelled' : '235 accepted'); }
      if (mode === 'auth-user') { mode = line === '*' ? 'command' : 'auth-one'; return reply(line === '*' ? '501 authentication cancelled' : '334 UGFzc3dvcmQ6'); }
      const verb = (/^[A-Za-z]+/.exec(line)?.[0] ?? '').toUpperCase();
      if (verb === 'EHLO') return reply(['250-scopehaven-sink', `250-SIZE ${cfg.maxMessageBytes}`, '250-8BITMIME', '250-SMTPUTF8', '250-PIPELINING', '250 AUTH PLAIN LOGIN'].join('\r\n'));
      if (verb === 'HELO') return reply('250 scopehaven-sink');
      if (verb === 'NOOP') return reply('250 ok');
      if (verb === 'VRFY') return reply('252 cannot verify');
      if (verb === 'QUIT') { reply('221 bye'); socket.end(); return; }
      if (verb === 'STARTTLS') return reply('454 TLS not available');
      if (verb === 'RSET') { if (tx) { tx.done = true; tx.cancelled = true; tx = null; } return reply('250 reset'); }
      if (verb === 'AUTH') {
        const [, mech, initial] = /^AUTH\s+(\S+)(?:\s+(\S+))?/i.exec(line) ?? [];
        if (/^PLAIN$/i.test(mech ?? '')) { if (initial) return reply('235 accepted'); mode = 'auth-one'; return reply('334 '); }
        if (/^LOGIN$/i.test(mech ?? '')) { mode = initial ? 'auth-one' : 'auth-user'; return reply(initial ? '334 UGFzc3dvcmQ6' : '334 VXNlcm5hbWU6'); }
        return reply('504 unsupported mechanism');
      }
      if (verb === 'MAIL') {
        if (tx) return reply('503 nested MAIL');
        const from = envelopeAddress(line, 'MAIL FROM');
        if (!from) { ledger.record({ kind: 'malformed' }); return reply('501 bad sender'); }
        tx = ledger.record({ kind: 'item', done: false, witnessNonces: [], pendingNonces: [], recipients: [], from: sha(from.address), bytes: 0, overLimit: false, outcome: 'unknown' });
        return reply('250 sender ok');
      }
      if (verb === 'RCPT') {
        if (!tx) return reply('503 need MAIL first');
        const to = envelopeAddress(line, 'RCPT TO');
        if (!to || !to.domain) { ledger.record({ kind: 'malformed' }); return reply('501 bad recipient'); }
        if (tx.recipients.length + tx.pendingNonces.length >= SMTP_LIMITS.recipients) { tx.tooManyRecipients = true; return reply('452 too many recipients'); }
        const nonce = to.domain === cfg.witness?.domain ? NONCE.exec(to.local)?.[0]?.toLowerCase() : undefined;
        if (to.domain === cfg.witness?.domain) tx.pendingNonces.push(nonce ?? 'no-nonce');
        // A domain longer than an event name can hold (128) is unusable and never an event: shortened, it could read as another
        // (declared) domain. It stays a recipient of the message, so the window is partial and a witness message to it is mixed.
        else if (to.domain.length > 128) tx.recipients.push({ domain: null, resource: '*', to: sha(to.address), literal: to.literal, unusable: true, ambiguous: false });
        else {
          // A recipient names a declared address only by the shared rules: unusable (not a plain dot-atom local part) and
          // ambiguous (an alias form of a declared address) recipients stay events, and leave the window partial.
          const mb = mailboxOf(to.raw), named = mb ? addressResource(mb, declared.get(to.domain)) : { resource: '*', ambiguous: false };
          tx.recipients.push({ domain: to.domain, resource: named.resource, to: sha(to.address), literal: to.literal, unusable: mb === null, ambiguous: named.ambiguous });
        }
        return reply('250 recipient ok');
      }
      if (verb === 'DATA') {
        if (!tx || (!tx.recipients.length && !tx.pendingNonces.length)) return reply('503 need RCPT first');
        mode = 'data'; hash = createHash('sha256'); atLineStart = true;
        return reply('354 end with <CRLF>.<CRLF>');
      }
      ledger.record({ kind: 'unrecognized' });
      return reply('502 command not implemented');
    }
  }

  return {
    kind: observer.kind, instanceId, source: 'smtp-capture', port: cfg.port,
    scope: Object.freeze({ operations: ['send'], names: cfg.domains.map(d => d.domain), actorAttribution: 'none', evidence: cfg.routing ? 'authoritative' : 'presence-only' }),
    ...(cfg.witness ? { witnessRequest: Object.freeze({ actorId: cfg.witness.actorId, method: 'GET', path: cfg.witness.path }) } : {}),
    markWitnessRequest(from) { ledger.markWitnessRequest(from); },
    async start() {
      if (servers) return;
      const bound = [];
      for (const host of SMTP_SINK_ADDRESSES) {
        const s = createServer(onConnection);
        s.maxConnections = SMTP_LIMITS.maxConnections;
        s.on('drop', () => { ledger.record({ kind: 'dropped' }); });
        try { await new Promise((resolve, reject) => { s.once('error', reject); s.listen({ port: cfg.port, host, exclusive: true }, () => { s.off('error', reject); resolve(); }); }); }
        catch (error) { await Promise.all(bound.map(b => new Promise(resolve => b.close(() => resolve())))); throw error; }
        bound.push(s);
      }
      for (const s of bound) { s.on('error', () => ledger.down()); s.on('close', () => ledger.down()); }
      servers = bound; ledger.started();
    },
    async mark() { return ledger.position(); },
    // gap: a settlement gap window (sink-ledger.mjs), an exact range collected after the run.
    async collect(from, to, { gap = false } = {}) {
      const w = await ledger.window(from, to, { witness: cfg.witness !== null, witnessWaitMs: cfg.witnessWaitMs, quietMs: cfg.quietMs, gap });
      if (w.failed) return { events: [], coverage: 'failed', reason: w.failed };
      const { problems } = w, events = [];
      for (const m of w.items) {
        if (m.cancelled) continue; // RSET before DATA: nothing was sent
        if (m.aborted) problems.add('smtp-message-incomplete');
        if (m.overLimit) problems.add('smtp-message-over-limit');
        if (m.tooManyRecipients) problems.add('smtp-too-many-recipients');
        if (m.mixedWitness) problems.add('smtp-witness-mixed');
        if (m.recipients.some(r => r.literal)) problems.add('smtp-address-literal');
        if (m.recipients.some(r => r.unusable)) problems.add('smtp-recipient-unusable');
        if (m.recipients.some(r => r.ambiguous)) problems.add('smtp-recipient-ambiguous');
        if (events.length + m.recipients.length > 5000) { problems.add('smtp-event-limit'); continue; }
        // One event per recipient, named by its full domain (an over-long one is none); sequence numbers stay strictly increasing
        // within the window.
        m.recipients.forEach((r, i) => { if (r.domain !== null) events.push(makeEffect({ source: 'smtp-capture', observer, seq: m.seq * 128 + i, actor: null, operation: 'send', name: r.domain, resource: r.resource,
          outcome: m.aborted || m.overLimit ? 'unknown' : m.outcome, correlation: {}, content: { from: m.from, to: r.to, data: m.data ?? null, bytes: m.bytes } })); });
      }
      const reason = problems.size ? [...problems].sort().join(',').slice(0, 200) : null;
      return { events, coverage: reason ? 'partial' : 'complete', reason };
    },
    async stop() {
      const list = servers ?? []; servers = null; ledger.stopped();
      for (const socket of sockets) socket.destroy();
      await Promise.all(list.map(s => new Promise(resolve => s.close(() => resolve()))));
    },
  };
}
