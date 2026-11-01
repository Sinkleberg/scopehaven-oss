// What a release says about third-party code and package lists, for a buyer's composition scan (osv-scanner, Trivy,
// Grype, Dependabot) over the extracted tarball:
//   SBOM.cdx.json     CycloneDX 1.5: the release, what it needs to run, and the vendored code and data it carries
//   VEX.cdx.json      CycloneDX 1.5 VEX: every advisory on a package that a shipped list names but ScopeHaven never
//                     installs, analysed not_affected
//   VEX.openvex.json  the same statements as OpenVEX 0.2.0 (justification component_not_present), the form
//                     `trivy fs --vex` and `grype --vex` apply to a directory scan
// The advisories come from ADVISORIES, a reviewed OSV snapshot refreshed by packaging/osv-snapshot.mjs. A build refuses
// a shipped package list that is not declared here, and a declared list whose bytes differ from the snapshot's.
import { createHash } from 'node:crypto';

export const ADVISORIES = 'packaging/third-party-advisories.json';
export const ADVISORIES_SCHEMA = 'scopehaven-third-party-advisories/1';
export const SBOM_NAME = 'SBOM.cdx.json';
export const VEX_NAMES = Object.freeze({ cyclonedx: 'VEX.cdx.json', openvex: 'VEX.openvex.json' });

// Package lists that ship as data: none today, so a release carries no VEX. Each entry would name { path, ecosystem,
// parse, covers, why }, and a list declared here must match the reviewed snapshot in ADVISORIES.
export const THIRD_PARTY_LISTS = Object.freeze([]);
// File names composition scanners read as package lists. package.json at the folder root is ScopeHaven's own (no dependencies).
const LIST_NAME = /(^|\/)(uv\.lock|poetry\.lock|pdm\.lock|Pipfile(\.lock)?|pyproject\.toml|[^/]*requirements[^/]*\.txt|setup\.(py|cfg)|package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|package\.json|[^/]+\.package\.json|packages-[^/]*\.json|go\.(mod|sum)|Cargo\.(toml|lock)|Gemfile(\.lock)?|composer\.(json|lock)|pom\.xml|build\.gradle(\.kts)?|gradle\.lockfile|packages\.lock\.json|mix\.lock|pubspec\.lock)$/;
export const unreviewedLists = (paths, known = THIRD_PARTY_LISTS) => paths.filter(path => LIST_NAME.test(path) && path !== 'package.json'
  && !known.some(list => list.path === path || list.covers.includes(path)));

// [[package]] tables of a uv lockfile: name and version (the project itself has none and is skipped).
export function uvLockPackages(text) {
  const out = [];
  for (const block of text.split(/^\[\[package\]\]\s*$/m).slice(1)) {
    const head = block.split(/^\[/m)[0];
    const name = /^name = "([^"]+)"$/m.exec(head)?.[1], version = /^version = "([^"]+)"$/m.exec(head)?.[1];
    if (name && version) out.push({ name, version });
  }
  return out;
}
export const listPackages = (list, content) => {
  if (list.parse !== 'uv.lock') throw new Error(`no parser for ${list.parse}`);
  return uvLockPackages(content.toString('utf8'));
};
export const purl = (ecosystem, name, version) => {
  if (ecosystem !== 'PyPI') throw new Error(`no purl type for ${ecosystem}`);
  return `pkg:pypi/${name.toLowerCase().replace(/[._]+/g, '-')}@${version}`;
};

// Deterministic per commit: a UUID (RFC 9562 version 8) from a sha256 of the commit and the document kind.
const uuid = seed => {
  const h = createHash('sha256').update(seed).digest('hex').slice(0, 32).split('');
  h[12] = '8'; h[16] = ((parseInt(h[16], 16) & 0x3) | 0x8).toString(16);
  const s = h.join('');
  return `${s.slice(0, 8)}-${s.slice(8, 12)}-${s.slice(12, 16)}-${s.slice(16, 20)}-${s.slice(20)}`;
};
const sha256 = data => createHash('sha256').update(data).digest('hex');
const keyOf = p => `${p.name}@${p.version}`;

// Checks the shipped lists against the snapshot and returns, per list, its packages with their advisories.
export function reviewedLists(files, known = THIRD_PARTY_LISTS) {
  const byPath = new Map(files.map(f => [f.path, f]));
  const loose = unreviewedLists(files.map(f => f.path), known);
  if (loose.length) throw new Error(`a third-party package list ships without review: ${loose.join(', ')}; leave it out of the release or declare it in packaging/third-party.mjs`);
  const declared = known.filter(list => byPath.has(list.path));
  if (!declared.length) return { snapshot: null, lists: [] };
  const raw = byPath.get(ADVISORIES);
  if (!raw) throw new Error(`${ADVISORIES} is missing; run node packaging/osv-snapshot.mjs`);
  const snapshot = JSON.parse(raw.content.toString('utf8'));
  if (snapshot.schema !== ADVISORIES_SCHEMA) throw new Error(`${ADVISORIES}: schema ${snapshot.schema}, expected ${ADVISORIES_SCHEMA}`);
  const lists = declared.map(list => {
    const file = byPath.get(list.path), entry = snapshot.lists.find(l => l.path === list.path);
    const stale = `${ADVISORIES} does not match ${list.path}; run node packaging/osv-snapshot.mjs and review the result`;
    if (!entry || entry.sha256 !== sha256(file.content) || entry.ecosystem !== list.ecosystem) throw new Error(stale);
    const listed = listPackages(list, file.content), known = new Map(entry.packages.map(p => [keyOf(p), p]));
    if (listed.length !== entry.packages.length || listed.some(p => !known.has(keyOf(p)))) throw new Error(stale);
    return { ...list, sha256: entry.sha256, packages: listed.map(p => ({ ...p, purl: purl(list.ecosystem, p.name, p.version), advisories: known.get(keyOf(p)).advisories })) };
  });
  return { snapshot, lists };
}

export function sbom({ version, commit, commitTime, files }) {
  const at = path => files.find(f => f.path === path);
  const hash = path => [{ alg: 'SHA-256', content: sha256(at(path).content) }];
  const prop = (name, value) => ({ name: `scopehaven:${name}`, value: String(value) });
  const pkg = JSON.parse(at('package.json').content.toString());
  const deps = Object.keys({ ...pkg.dependencies, ...pkg.optionalDependencies, ...pkg.peerDependencies });
  const components = [];
  if (at('.nvmrc')) components.push({ type: 'platform', 'bom-ref': 'node', name: 'node', group: 'nodejs.org', version: at('.nvmrc').content.toString().trim(),
    scope: 'required', description: 'The Node.js runtime the launcher selects (.nvmrc); not shipped.', purl: `pkg:generic/node@${at('.nvmrc').content.toString().trim()}` });
  components.push({ type: 'platform', 'bom-ref': 'python3', name: 'python3', scope: 'optional',
    description: 'Standard library only, for the helpers written in Python; not shipped.' });
  if (at('src/public-suffix-list.mjs')) components.push({ type: 'data', 'bom-ref': 'public-suffix-list', name: 'Public Suffix List (multi-label ICANN subset)',
    group: 'publicsuffix.org', licenses: [{ license: { id: 'MPL-2.0' } }], hashes: hash('src/public-suffix-list.mjs'),
    description: 'Vendored as data at publicsuffix/list 52b71b3c; only this file carries the MPL-2.0.', properties: [prop('path', 'src/public-suffix-list.mjs')] });
  return {
    bomFormat: 'CycloneDX', specVersion: '1.5', serialNumber: `urn:uuid:${uuid(`sbom:${commit}`)}`, version: 1,
    metadata: {
      timestamp: new Date(commitTime * 1000).toISOString(), lifecycles: [{ phase: 'build' }],
      tools: { components: [{ type: 'application', name: 'scopehaven packaging/build-release.mjs', version }] },
      component: { type: 'application', 'bom-ref': 'scopehaven', name: 'scopehaven', version, purl: `pkg:generic/scopehaven@${version}`,
        properties: [prop('commit', commit), prop('npmDependencies', deps.length)] },
    },
    components,
    dependencies: [{ ref: 'scopehaven', dependsOn: components.map(c => c['bom-ref']) }],
  };
}

const notInstalled = (list, p) => `component_not_present: ${p.name} ${p.version} is named in ${list.path}, which ships as data. ${list.why}`;

export function vexCycloneDX({ version, commit, commitTime, snapshot, lists }) {
  const components = [], vulnerabilities = new Map();
  for (const list of lists) for (const p of list.packages) {
    const ref = `${list.path}#${p.purl}`;
    components.push({ type: 'library', 'bom-ref': ref, name: p.name, version: p.version, purl: p.purl, scope: 'excluded',
      properties: [{ name: 'scopehaven:listedIn', value: list.path }, { name: 'scopehaven:installed', value: 'false' }] });
    for (const a of p.advisories) {
      const v = vulnerabilities.get(a.name) ?? { id: a.name, source: { name: 'OSV', url: `https://osv.dev/vulnerability/${a.name}` },
        references: a.aliases.map(id => ({ id, source: { name: 'OSV', url: `https://osv.dev/vulnerability/${id}` } })),
        analysis: { state: 'not_affected', justification: 'code_not_present', detail: '' }, affects: [] };
      v.affects.push({ ref });
      v.analysis.detail = v.affects.length === 1 ? notInstalled(list, p) : `component_not_present: every affected package is named in a list that ships as data and is never installed (${[...new Set(lists.map(l => l.path))].join(', ')}).`;
      vulnerabilities.set(a.name, v);
    }
  }
  return {
    bomFormat: 'CycloneDX', specVersion: '1.5', serialNumber: `urn:uuid:${uuid(`vex:${commit}`)}`, version: 1,
    metadata: { timestamp: new Date(commitTime * 1000).toISOString(),
      component: { type: 'application', 'bom-ref': 'scopehaven', name: 'scopehaven', version, purl: `pkg:generic/scopehaven@${version}` },
      properties: [{ name: 'scopehaven:advisoriesQueriedAt', value: snapshot.queriedAt }, { name: 'scopehaven:advisorySource', value: snapshot.endpoint },
        { name: 'scopehaven:scope', value: 'Advisories known to OSV when queried. An advisory published later is not in this file; refresh with packaging/osv-snapshot.mjs.' }] },
    components, vulnerabilities: [...vulnerabilities.values()].sort((a, b) => (a.id < b.id ? -1 : 1)),
  };
}

export function vexOpen({ version, commit, commitTime, snapshot, lists }) {
  const statements = [];
  for (const list of lists) for (const p of list.packages) for (const a of p.advisories)
    statements.push({ vulnerability: { name: a.name, ...(a.aliases.length ? { aliases: a.aliases } : {}) }, products: [{ '@id': p.purl }],
      status: 'not_affected', justification: 'component_not_present', impact_statement: notInstalled(list, p) });
  return {
    '@context': 'https://openvex.dev/ns/v0.2.0', '@id': `urn:scopehaven:vex:${commit}`, author: 'ScopeHaven',
    role: `packaging/build-release.mjs for scopehaven ${version}; advisories from OSV at ${snapshot.queriedAt}`,
    timestamp: new Date(commitTime * 1000).toISOString(), version: 1, statements,
  };
}
