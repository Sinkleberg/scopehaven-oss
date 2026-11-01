// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// A subset of the Public Suffix List (https://publicsuffix.org/list/public_suffix_list.dat), vendored as data only: multi-label suffixes
// from its ICANN section at publicsuffix/list commit 52b71b3c4576ff77450cc7ebcfc7f34a916af3f9 (committed 2026-10-17T18:51:57Z). Every
// entry is a rule of that section, and none is under a wildcard or exception rule there. Only this file carries the MPL-2.0; the code that
// reads it is src/public-suffix.mjs. No package dependency is added (FIX-04, SURPASS-BYPASS-01 A-32).
export const MULTI_LABEL_SUFFIXES = Object.freeze(new Set([
  'ac.jp', 'ac.uk', 'co.id', 'co.il', 'co.in', 'co.jp', 'co.ke', 'co.kr', 'co.nz', 'co.th', 'co.uk', 'co.za',
  'com.ar', 'com.au', 'com.br', 'com.cn', 'com.eg', 'com.hk', 'com.mx', 'com.my', 'com.ng', 'com.ph', 'com.pk', 'com.sa', 'com.sg', 'com.tr', 'com.tw', 'com.ua', 'com.vn',
  'go.jp', 'gov.uk', 'ltd.uk', 'me.uk', 'ne.jp', 'net.au', 'net.br', 'net.cn', 'net.in', 'net.nz', 'net.uk', 'or.jp', 'or.kr',
  'org.au', 'org.br', 'org.cn', 'org.hk', 'org.il', 'org.in', 'org.mx', 'org.nz', 'org.sg', 'org.tw', 'org.uk', 'org.za', 'plc.uk',
]));
