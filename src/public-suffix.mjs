// FIX-04 option 1 (SURPASS-BYPASS-01 A-32, egress-recorder/11): the registrable domain of a host name, its public suffix plus one label, so
// the egress recorder can tell an undeclared host that may be another name of a declared provider (api-eu.pay.example beside
// api.pay.example). It follows the Public Suffix List's rules over the subset in src/public-suffix-list.mjs (vendored data, kept in its own
// file under the MPL-2.0): a host under a listed suffix keeps that suffix, and any other suffix is the host's last label (the list's default
// rule "*"). A suffix missing there only makes the registrable domain shorter, so more hosts share it: the recorder reads more sends as
// possible siblings and more clauses as missing, never fewer, and never a pass. Each entry must be a real public suffix, so no host is made
// its own family by a suffix that is not one. Pure: no I/O, no network.
import { MULTI_LABEL_SUFFIXES } from './public-suffix-list.mjs';

const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;
// The registrable domain of a lowercase host name (no trailing dot), or null: an IP literal, a name of one label, or a name that is
// itself a public suffix has none.
export function registrableDomain(host) {
  if (typeof host !== 'string' || !host.length || host.includes(':') || IPV4.test(host)) return null;
  const labels = host.split('.');
  if (labels.some(label => !label.length)) return null;
  const suffixLabels = labels.length >= 2 && MULTI_LABEL_SUFFIXES.has(labels.slice(-2).join('.')) ? 2 : 1;
  return labels.length > suffixLabels ? labels.slice(-(suffixLabels + 1)).join('.') : null;
}
