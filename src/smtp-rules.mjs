// SMTP sink configuration (pure; shared by src/contracts.mjs and the observer in
// integrations/observers/smtp-sink.mjs).
//
// The sink is a loopback SMTP server that the application's mail host points at
// (for example its SMTP host set to host.docker.internal:<port>). It accepts
// every message and never relays one. Its silence counts as authoritative only
// when "routing": "smtp-host" is declared and each window's witness proves the
// route was live:
//   witness: { actorId, method: "GET", path, domain } - an app request (path) that
//     makes the app send one message to "<nonce>@<domain>", where <nonce> is the
//     query parameter scopehaven_witness it was given. The witness domain is never
//     a destination, and its message is never an effect.
// Without "routing" (and "witness") the observer is presence-only.
//
// domains: [{ domain, addresses? }] - the recipient domains checks name (effect
//   name = recipient domain). addresses are full recipient addresses that name an
//   event's resource; any other recipient reads "*". Recipient addresses, senders,
//   subjects and bodies are never stored, only digested.
import { mailboxOf } from './mail-address.mjs';

export const SMTP_BOUNDS = Object.freeze({ domains: 64, addresses: 64, quietMs: [100, 10000], witnessWaitMs: [0, 30000], maxMessageBytes: [1024, 32 * 1024 * 1024], port: [1024, 65535] });
const KEYS = ['id', 'type', 'port', 'routing', 'domains', 'witness', 'witnessWaitMs', 'quietMs', 'maxMessageBytes', 'settleMs'];
const WITNESS_KEYS = ['actorId', 'method', 'path', 'domain'];
const DOMAIN = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
const ADDRESS = /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[a-z0-9.-]{1,253}$/;
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const intIn = (value, [lo, hi]) => Number.isInteger(value) && value >= lo && value <= hi;
export const smtpDomain = domain => typeof domain === 'string' && DOMAIN.test(domain);

// Throws with a profile-facing message; returns the normalized configuration.
export function validateSmtpConfig(o, actors) {
  if (!object(o) || Object.keys(o).some(key => !KEYS.includes(key))) throw new Error(`an smtp-sink observer is { ${KEYS.join(', ')} } (all but id, type, port and domains optional)`);
  if (!intIn(o.port, SMTP_BOUNDS.port)) throw new Error('"port" must be an integer from 1024 to 65535 (the sink listens on 127.0.0.1 and [::1])');
  if (!Array.isArray(o.domains) || !o.domains.length || o.domains.length > SMTP_BOUNDS.domains) throw new Error('"domains" lists 1 to 64 { domain, addresses? }');
  const domains = o.domains.map(d => {
    if (!object(d) || Object.keys(d).some(key => !['domain', 'addresses'].includes(key)) || !smtpDomain(d.domain)) throw new Error('each entry of "domains" is { domain, addresses? } with a lowercase domain name');
    if (d.addresses !== undefined && !(Array.isArray(d.addresses) && d.addresses.length <= SMTP_BOUNDS.addresses && d.addresses.every(a => typeof a === 'string' && ADDRESS.test(a) && a.endsWith(`@${d.domain}`) && mailboxOf(a)?.address === a) && new Set(d.addresses).size === d.addresses.length)) throw new Error('a domain\'s "addresses" lists up to 64 distinct lowercase addresses in that domain, each canonical (a plain dot-atom local part without % or !: src/mail-address.mjs)');
    return { domain: d.domain, addresses: [...(d.addresses ?? [])] };
  });
  if (new Set(domains.map(d => d.domain)).size !== domains.length) throw new Error('each domain is declared once');
  if ((o.routing === undefined) !== (o.witness === undefined)) throw new Error('"routing" and "witness" go together: absence is authoritative only on a declared route a witness proves');
  if (o.routing !== undefined && o.routing !== 'smtp-host') throw new Error('"routing" must be "smtp-host" (the app\'s mail host is this sink)');
  let witness = null;
  if (o.witness !== undefined) {
    const w = o.witness;
    if (!object(w) || Object.keys(w).some(key => !WITNESS_KEYS.includes(key))) throw new Error('"witness" is { actorId, method: "GET", path, domain } and nothing else');
    if (w.method !== 'GET') throw new Error('the witness must be a GET to the app');
    // A string first: Object.hasOwn coerces its key (D-01's shape; src/audit-file-rules.mjs says why).
    if (!object(actors) || typeof w.actorId !== 'string' || !Object.hasOwn(actors, w.actorId)) throw new Error('the witness "actorId" must be a declared actor');
    if (typeof w.path !== 'string' || !w.path.startsWith('/') || w.path.startsWith('//') || w.path.length > 300 || /[#\s\\]/.test(w.path)) throw new Error('the witness "path" must be an origin-form path without a fragment');
    let decoded;
    try { decoded = decodeURIComponent(w.path); } catch { throw new Error('the witness "path" must be validly percent-encoded'); }
    if (/scopehaven_witness/i.test(decoded)) throw new Error('the witness "path" cannot carry its own witness parameter');
    if (!smtpDomain(w.domain) || domains.some(d => d.domain === w.domain)) throw new Error('the witness "domain" is a lowercase domain name that is not a destination (the witness is never an effect)');
    witness = { actorId: w.actorId, method: 'GET', path: w.path, domain: w.domain };
  }
  if (o.witnessWaitMs !== undefined && !intIn(o.witnessWaitMs, SMTP_BOUNDS.witnessWaitMs)) throw new Error('"witnessWaitMs" must be an integer from 0 to 30000');
  if (o.quietMs !== undefined && !intIn(o.quietMs, SMTP_BOUNDS.quietMs)) throw new Error('"quietMs" must be an integer from 100 to 10000');
  if (o.maxMessageBytes !== undefined && !intIn(o.maxMessageBytes, SMTP_BOUNDS.maxMessageBytes)) throw new Error('"maxMessageBytes" must be an integer from 1024 to 33554432');
  return { port: o.port, routing: o.routing ?? null, domains, witness, witnessWaitMs: o.witnessWaitMs ?? 3000, quietMs: o.quietMs ?? 300, maxMessageBytes: o.maxMessageBytes ?? 10 * 1024 * 1024 };
}
