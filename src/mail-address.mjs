// Mail recipient addresses as the mail observers name them (pure; used by integrations/observers/provider-feed.mjs and
// integrations/observers/smtp-sink.mjs, and by the profile rules of both). In the HTTP evaluator identity: a change here
// changes which declared address a recorded send is named by.
//
// recipientOf(text): a recipient read by the envelope rules of smtp-sink.mjs envelopeAddress: a source route
// ("@relay,@relay2:") dropped, one trailing dot of the host stripped, the domain in its ASCII form (an internationalized
// domain as its A-label; an address literal "[...]" kept as a literal). null only when no domain can be read. Its
// mailbox is the normalized address (lowercased) when the recipient is a canonical one, and null otherwise:
//   - the local part is not a plain printable-ASCII dot-atom (quoted, commented, escaped or non-ASCII: another written
//     form of some mailbox; checked before lowercasing, since a non-ASCII letter can lowercase to an ASCII one)
//   - the local part holds "%" or "!": a relay route ("vip%customers.example@relay", a bang path) that a mail server
//     may deliver to another domain than the one named
//   - the host still ends with a dot after one is stripped, or holds an IDNA deviation character (sharp s, final sigma,
//     a zero-width joiner or non-joiner), which some resolvers map to another name
// A recipient without a mailbox stays a send to its domain; the observers leave its window partial.
//
// addressResource(mailbox, declared): the resource a send to that mailbox is named by, the address itself when the
// domain declares it and "*" otherwise, and whether it is ambiguous: it could be the same mailbox as another declared
// address under common provider alias rules. It could when, for some other declared address of the domain, either
// alias stem of the two local parts is equal:
//   - cut at the first "+" or "-" after the first character (a subaddress: "vip+tag", or "vip-tag" under Postfix's
//     recipient_delimiter), then every dot removed (providers that ignore dots, as Gmail does);
//   - cut at the first "+" after the first character, then every ".", "_" and "-" removed (Proton treats them as
//     transparent).
// A declared address is ambiguous too when another declared address shares a stem with it ("vip@" and "vip+refund@"):
// a send to either may reach the other's mailbox. A reader treats an ambiguous recipient as unusable for a
// resource-pinned decision, so the window is partial: the rule only tightens, never makes a pass, and a false ambiguity
// is limited to addresses that nearly equal a declared one ("vipp@" stays a plain "*"). declared: the declared addresses
// of the mailbox's domain (a Set or an array), or nothing. Provider rules beyond these (a catch-all, a forwarding rule,
// another domain the provider maps) are not modelled.
import { domainToASCII } from 'node:url';

// RFC 5322 atext, lowercased, in dot-separated atoms; and the raw local part must be printable ASCII.
const DOT_ATOM = /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*$/;
const PRINTABLE_ASCII = /^[\x21-\x7e]+$/;
const ROUTING = /[%!]/;
const DEVIATION = /[ßς‌‍]/u;

export function recipientOf(text) {
  if (typeof text !== 'string' || /[\s<>]/.test(text)) return null;
  const mailbox = text.replace(/^@[^:,]+(?:,@[^:,]+)*:/, ''), at = mailbox.lastIndexOf('@');
  if (at < 1 || at === mailbox.length - 1) return null;
  const rawLocal = mailbox.slice(0, at), host = mailbox.slice(at + 1).replace(/\.$/, '');
  const literal = /^\[(.*)\]$/.exec(host);
  const domain = literal ? literal[1].toLowerCase() : domainToASCII(host);
  if (!domain) return null;
  const local = rawLocal.toLowerCase(), sourceRoute = mailbox !== text;
  const canonical = PRINTABLE_ASCII.test(rawLocal) && DOT_ATOM.test(local) && !ROUTING.test(local) && !host.endsWith('.') && !DEVIATION.test(host.toLowerCase());
  return { domain, literal: literal !== null, sourceRoute, mailbox: canonical ? { address: `${local}@${domain}`, local, domain, literal: literal !== null, sourceRoute } : null };
}
// The canonical mailbox of a recipient, or null.
export const mailboxOf = text => recipientOf(text)?.mailbox ?? null;

// The two alias stems of a local part (see addressResource).
export function aliasStems(local) {
  const cut = (text, delimiters) => { const i = text.slice(1).search(delimiters); return i < 0 ? text : text.slice(0, i + 1); };
  return [cut(local, /[+-]/).replaceAll('.', ''), cut(local, /\+/).replace(/[._-]/g, '')];
}

export function addressResource(mailbox, declared) {
  const list = Array.isArray(declared) ? declared : declared instanceof Set ? [...declared] : [];
  const stems = aliasStems(mailbox.local);
  const ambiguous = list.some(address => {
    if (address === mailbox.address) return false;
    const at = address.lastIndexOf('@');
    if (address.slice(at + 1) !== mailbox.domain) return false;
    const other = aliasStems(address.slice(0, at));
    return other[0] === stems[0] || other[1] === stems[1];
  });
  return { resource: list.includes(mailbox.address) ? mailbox.address : '*', ambiguous };
}
