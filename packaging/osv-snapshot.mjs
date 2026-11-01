#!/usr/bin/env node
// Refreshes packaging/third-party-advisories.json: the OSV advisories on every package that a declared third-party list
// (packaging/third-party.mjs) names, read from the working tree. A maintainer runs it when a list changes or before a
// release, reviews the diff and commits it; build-release.mjs refuses a list whose bytes differ from the snapshot.
// It sends package names, versions and ecosystems (public lockfile data, nothing else) to api.osv.dev over HTTPS.
// It is not shipped in the release.
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ADVISORIES, ADVISORIES_SCHEMA, THIRD_PARTY_LISTS, listPackages } from './third-party.mjs';

const FOLDER = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const OSV = 'https://api.osv.dev/v1';
const call = async (path, body) => {
  const response = await fetch(`${OSV}${path}`, { method: body ? 'POST' : 'GET', redirect: 'error', signal: AbortSignal.timeout(60000),
    ...(body ? { headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) } : {}) });
  if (!response.ok) throw new Error(`OSV ${path}: HTTP ${response.status}`);
  return response.json();
};

// One advisory per group of OSV ids that alias each other; it is named by its CVE when it has one, as most scanners report.
function groups(ids, aliasesOf) {
  const parent = new Map(ids.map(id => [id, id]));
  const find = id => (parent.get(id) === id ? id : find(parent.get(id)));
  for (const id of ids) for (const alias of aliasesOf.get(id) ?? []) if (parent.has(alias)) parent.set(find(alias), find(id));
  const byRoot = new Map();
  for (const id of ids) {
    const all = new Set([id, ...(aliasesOf.get(id) ?? [])]);
    const root = find(id);
    byRoot.set(root, new Set([...(byRoot.get(root) ?? []), ...all]));
  }
  return [...byRoot.values()].map(set => {
    const all = [...set].sort();
    const name = all.find(id => id.startsWith('CVE-')) ?? all.find(id => id.startsWith('GHSA-')) ?? all[0];
    return { name, aliases: all.filter(id => id !== name) };
  }).sort((a, b) => (a.name < b.name ? -1 : 1));
}

const lists = [];
for (const list of THIRD_PARTY_LISTS) {
  const content = readFileSync(join(FOLDER, list.path));
  const packages = listPackages(list, content);
  const found = [];
  for (let i = 0; i < packages.length; i += 500) {
    const chunk = packages.slice(i, i + 500);
    const { results } = await call('/querybatch', { queries: chunk.map(p => ({ package: { name: p.name, ecosystem: list.ecosystem }, version: p.version })) });
    chunk.forEach((p, j) => found.push({ ...p, ids: (results[j].vulns ?? []).map(v => v.id) }));
  }
  const aliasesOf = new Map();
  for (const id of [...new Set(found.flatMap(p => p.ids))].sort()) {
    const vuln = await call(`/vulns/${encodeURIComponent(id)}`);
    if (!vuln.withdrawn) aliasesOf.set(id, vuln.aliases ?? []);
  }
  lists.push({ path: list.path, ecosystem: list.ecosystem, sha256: createHash('sha256').update(content).digest('hex'),
    packages: found.map(p => ({ name: p.name, version: p.version, advisories: groups(p.ids.filter(id => aliasesOf.has(id)), aliasesOf) })) });
}
const advisories = lists.reduce((n, l) => n + l.packages.reduce((m, p) => m + p.advisories.length, 0), 0);
writeFileSync(join(FOLDER, ADVISORIES), JSON.stringify({ schema: ADVISORIES_SCHEMA, queriedAt: new Date().toISOString().replace(/\.\d+Z$/, 'Z'),
  endpoint: `${OSV}/querybatch`, lists }, null, 1) + '\n');
console.log(`${ADVISORIES}: ${lists.reduce((n, l) => n + l.packages.length, 0)} packages, ${advisories} advisories`);
