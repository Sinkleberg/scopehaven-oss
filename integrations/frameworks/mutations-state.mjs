#!/usr/bin/env node
// Mutation sweep for the state projections and the Python shim (state-projections.test.mjs and
// shim.test.mjs): one mutation per property; each must make those tests fail. A survivor is a test gap.
//   node integrations/frameworks/mutations-state.mjs [--out FILE] [--only ID,ID...]
// As mutations.mjs: a temporary copy of the modules the tests load, never the checkout; the tests run
// once unmutated (they must pass, with Python present), then once per mutation, one at a time. A
// mutation is one or more exact edits, each matching once, when a property lives in two places.
import { spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const TESTS = ['integrations/frameworks/state-projections.test.mjs', 'integrations/frameworks/shim.test.mjs'];
const m = (id, property, file, ...edits) => ({ id, property, file: `integrations/frameworks/${file}`, edits });
export const MUTATIONS = [
  m('K1', 'keepScalar keeps a scalar value', 'state.mjs', ['else if (keepScalar.includes(field)) row[field] = scalarOrDigest(value);', 'else if (keepScalar.includes(field)) row[field] = valueDigest(value);']),
  m('K2', 'a kept-where-scalar digest is an object, never a string a scalar could equal', 'state.mjs', ['scalar(value) ? value : { digest: valueDigest(value) });', 'scalar(value) ? value : valueDigest(value));']),
  m('K3', 'a field is kept one way, and the key strictly', 'state.mjs', ["  if ((p.keepScalar ?? []).some(f => f === p.key || (p.keep ?? []).includes(f))) fail('keep-scalar');\n", '']),
  m('P1', 'a pointer\'s value is kept', 'state.mjs', ['rows.push({ [p.key]: name, [p.valueField]: scalarOrDigest(at.value) });', 'rows.push({ [p.key]: name, [p.valueField]: valueDigest(at.value) });']),
  m('P2', 'a pointer that does not resolve gives no row', 'state.mjs', ['    if (!at.found) continue;', '    if (!at.found) { rows.push({ [p.key]: name, [p.valueField]: null }); continue; }']),
  m('P3', 'a pointed key is removed from the remainder, so a pointed value appearing is not collateral', 'state.mjs', ['    else delete parent[token];', "    else parent[token] = { '~pointer': name };"]),
  m('P4', 'the remainder covers everything the pointers leave out', 'state.mjs', ['  return [...rows, { [p.key]: REMAINDER_KEY, digest: valueDigest(rest) }];', '  return rows;']),
  m('P5', 'pointers need a remainder', 'state.mjs', ["      if (p.remainder !== true) fail('pointers-need-remainder');\n", '']),
  m('P6', 'an array index has no leading zero, so two pointers never name one element', 'state.mjs', ['const INDEX = /^(0|[1-9][0-9]*)$/;', 'const INDEX = /^\\d+$/;']),
  m('P7', 'pointer escapes decode ~1 before ~0', 'state.mjs', [".replace(/~1/g, '/').replace(/~0/g, '~')", ".replace(/~0/g, '~').replace(/~1/g, '/')"]),
  m('S7', 'a key subset answer holds only declared keys', 'state.mjs', ['if (!named.has(k) || seen.has(k))', 'if (seen.has(k))']),
  m('S11', 'a key subset answer holds each key once', 'state.mjs', ['if (!named.has(k) || seen.has(k))', 'if (!named.has(k))']),
  m('S12', 'declared keys differ as the diff reads them (as text)', 'state.mjs', ['new Set(p.keys.map(String)).size', 'new Set(p.keys.map(k => canonical(k))).size']),
  m('S8', 'a remainder that cannot be read fails the snapshot', 'state.mjs', ["\n    || !Number.isSafeInteger(value.remainder.rows) || value.remainder.rows < 0 || !DIGEST.test(value.remainder.digest ?? '')) throw", ') throw']),
  m('S9', 'a key subset keeps its remainder row', 'state.mjs', ['  return [...rows.map(r => projectRow(r, p)), { [p.key]: REMAINDER_KEY, rows: value.remainder.rows, digest: value.remainder.digest }];', '  return rows.map(r => projectRow(r, p));']),
  m('S10', 'a key subset needs a remainder', 'state.mjs', ["      if (p.keys !== undefined && p.remainder !== true) fail('keys-need-remainder');\n", '']),
  m('N1', 'nullAs reads null as an empty collection', 'state.mjs', ['      state[p.collection] = [];', "      throw new StateSpecError('value-null');"]),
  m('N2', 'a null value without nullAs fails the snapshot', 'state.mjs', ["      if (p.nullAs !== 'empty') throw new StateSpecError('value-null');\n", '']),
  m('N3', 'nullAs is refused beside a remainder', 'state.mjs', ["    if (p.nullAs !== undefined && p.remainder === true) fail('null-as-remainder');\n", '']),
  m('N4', 'a key named like a remainder field is refused beside a remainder', 'state.mjs', ["  if (p.remainder === true && REMAINDER_FIELDS.includes(p.key)) fail('key-is-remainder-field');\n", '']),
  m('X1', 'no expectation names the remainder row', 'state.mjs', ['    if ([e.where?.[p.key], e.after?.[p.key]].flat().includes(REMAINDER_KEY)) fail(`${where}-names-remainder`);\n', '']),
  m('X2', 'no where selects a remainder row, whatever its fields', 'state.mjs', ['const declared = (p, rows) => (rows ?? []).filter(r => r[p.key] !== REMAINDER_KEY);', 'const declared = (p, rows) => rows ?? [];']),
  m('T1', 'the snapshot request carries the declared key subset', 'state.mjs', ['...(p.keys !== undefined ? { select: { shape: p.shape, key: p.key, keys: p.keys } } : {})', '...{}']),
  m('G1', 'shim: the ledger sequence number is taken when the record is written', 'adapters/shim.py',
    ['        rec = {"tool": name, "args": safely_capped({"args": pos, "kwargs": kw})}\n        with self.lock:\n            self.running += 1\n        return rec', '        with self.lock:\n            self.running += 1\n            self.seq += 1\n            return {"seq": self.seq, "tool": name, "args": safely_capped({"args": pos, "kwargs": kw})}'],
    ['        self.seq += 1\n        self.running -= 1\n        self.channel.send({"type": "tool", "record": {"seq": self.seq, **record}})', '        self.running -= 1\n        self.channel.send({"type": "tool", "record": record})']),
  m('G2', 'shim: channel writes are serialized', 'adapters/shim.py', ['        with self.lock:\n            self.out.write(line)\n            self.out.flush()', '        self.out.write(line)\n        self.out.flush()']),
  m('G3', 'shim: the fault decision and its record are one step', 'adapters/shim.py',
    ['        with self.lock:\n            if not (f and not self.fault_used and name == f["tool"]):\n                return\n            self.fault_used = True\n            if f["kind"] != "timeout":\n                return f["kind"]\n            rec.update(status="fault-injected", exception=f"TimeoutError: {f[\'message\']}")\n            self._write(rec)',
      '        if not (f and not self.fault_used and name == f["tool"]):\n            return\n        self.fault_used = True\n        if f["kind"] != "timeout":\n            return f["kind"]\n        rec.update(status="fault-injected", exception=f"TimeoutError: {f[\'message\']}")\n        self._record(rec)']),
  m('G4', 'shim: a path through None reads None', 'adapters/shim.py', ['        if value is None:\n            return None\n        value = value.get(step, _MISSING)', '        value = value.get(step, _MISSING)']),
  m('G5', 'shim: a missing key or attribute is an error, never None', 'adapters/shim.py', ['            raise StateReadError(f"missing:{step}")', '            return None']),
  m('G6', 'shim: an integer past 2**53 is refused', 'adapters/shim.py', ['        if abs(value) > SAFE_INTEGER:\n            raise StateReadError("unsafe-integer")\n', '']),
  m('G7', 'shim: an object that is not plain data is refused, never stringified', 'adapters/shim.py', ['    raise StateReadError(f"unsupported:{type(value).__name__}")', '    return repr(value)']),
  m('G8', 'shim: every entry outside the subset is in the remainder digest', 'adapters/shim.py', ['                others.append((_key_text(k), [k, plain_data(v)]))', '                pass']),
  m('G9', 'shim: only the declared keys travel', 'adapters/shim.py', ['            if _key_text(k) in wanted:', '            if True:']),
  m('G10', 'shim: calls still running are counted', 'adapters/shim.py', ['            return self.running', '            return 0']),
  m('G11', 'shim: a dataclass attribute outside its fields is refused, never dropped', 'adapters/shim.py', ['        if any(k not in names for k in getattr(value, "__dict__", {})):\n            raise StateReadError("dataclass-extra-attribute")\n', '']),
  m('G12', 'shim: a model_dump on anything that is not a pydantic model is refused', 'adapters/shim.py', ['            raise StateReadError("model-dump-not-pydantic")', '            return plain_data(value.model_dump(), depth + 1)']),
  m('G15', 'shim: a model with private attributes is refused', 'adapters/shim.py', ['        if getattr(value, "__pydantic_private__", None):\n            raise StateReadError("pydantic-private")\n', '']),
  m('G16', 'shim: a model with an excluded field is refused', 'adapters/shim.py', ['        if any(getattr(f, "exclude", None) for f in fields.values()):\n            raise StateReadError("pydantic-excluded-field")\n', '']),
  m('G17', 'shim: a model is read by its declared fields, never by its own model_dump', 'adapters/shim.py', ['        out = {n: plain_data(held[n], depth + 1) for n in fields}', '        out = plain_data(value.model_dump(mode="json"), depth + 1)']),
  m('G18', 'shim: a dataclass is read as a dataclass even when it has a model_dump', 'adapters/shim.py', ['    if dataclasses.is_dataclass(value) and not isinstance(value, type):', '    if dataclasses.is_dataclass(value) and not isinstance(value, type) and not callable(getattr(value, "model_dump", None)):']),
  m('G19', 'shim: a slot outside the declared fields is refused', 'adapters/shim.py', ['    return [n for n in names if n not in declared and n not in _PYDANTIC_SLOTS]', '    return []']),
  m('G20', 'shim: a model holds exactly its declared fields', 'adapters/shim.py', ['        if not isinstance(held, dict) or set(held) != set(fields):', '        if not isinstance(held, dict):']),
  m('G21', 'shim: a cancelled or interrupted call still leaves its record', 'adapters/shim.py',
    ['                except BaseException as error:\n                    # Cancelled or interrupted (CancelledError, KeyboardInterrupt): recorded, then let through.\n                    ledger._raised(rec, error, "cancelled")\n                    raise\n', ''],
    ['            except BaseException as error:\n                ledger._raised(rec, error, "cancelled")\n                raise\n', '']),
  m('G22', 'shim: a list, tuple or dict subclass holding an attribute beside its items is refused', 'adapters/shim.py', ['    if getattr(value, "__dict__", None):\n        raise StateReadError("container-attributes")\n', '']),
  m('G23', 'shim: a list, tuple or dict subclass with a slot is refused', 'adapters/shim.py', ['    if _undeclared_slots(value, ()):\n', '    if False:\n']),
  m('G24', 'shim: a key subset read refuses a container subclass holding anything beside its items', 'adapters/shim.py', ['        return None\n    _items_only(value)\n', '        return None\n']),
  m('C10', 'the contract accepts a cancelled ledger record', 'contract.mjs', ["['returned', 'exception', 'cancelled', 'fault-injected']", "['returned', 'exception', 'fault-injected']"]),
  m('S13', 'two object projections on one path are refused', 'state.mjs', ["  if (new Set(paths).size !== paths.length) fail('path-repeated');\n", '']),
  m('J29', 'a pass with a key subset says it rests on the adapter\'s remainder digest', 'judge.mjs', ["? '; entries outside the declared keys compared by the remainder digest computed in process by the adapter' : '';", "? '' : '';"]),
  m('G13', 'shim: a call\'s record is never lost to a result it cannot capture', 'adapters/shim.py', ['    try:\n        return capped(value)\n    except Exception as error:\n        return {"unrecordable": type(error).__name__}', '    return capped(value)']),
  // Re-applied from mutations.mjs (J10, J12): the new tests depend on these guards too.
  m('J10', 'an app-supplied snapshot never passes (re-applied)', 'judge.mjs', ["const guarded = r => (appSupplied && r.status === 'pass'", "const guarded = r => (false && r.status === 'pass'"]),
  m('J12', 'goal mode: the goal decides, so doing nothing never passes (re-applied)', 'judge.mjs', ["scenario.decide === 'goal' ? ['COLLATERAL-01', 'COLLATERAL-GOAL', 'FW-CONTENT',", "scenario.decide === 'goal' ? ['COLLATERAL-01', 'FW-CONTENT',"]),
];

function runTests(root) {
  const out = spawnSync(process.execPath, ['--test', '--test-concurrency=1', ...TESTS], { cwd: root, encoding: 'utf8', timeout: 300000 });
  const lines = (out.stdout ?? '').split('\n');
  const failed = [...new Set(lines.filter(l => /^✖ /.test(l)).map(l => l.slice(2).replace(/ \([\d.]+ms\)$/, '')))];
  return { code: out.status, failed, skipped: Number(lines.find(l => /^ℹ skipped /.test(l))?.split(' ').pop() ?? 0) };
}

async function main() {
  const arg = flag => (process.argv.includes(flag) ? process.argv[process.argv.indexOf(flag) + 1] : null);
  const outFile = arg('--out'), only = arg('--only')?.split(',') ?? null;
  const tmp = mkdtempSync(join(tmpdir(), 'scopehaven-state-mutations-'));
  try {
    for (const dir of ['src', 'integrations/collateral', 'integrations/observers', 'integrations/evid-subject', 'integrations/frameworks']) cpSync(join(ROOT, dir), join(tmp, dir), { recursive: true });
    const base = runTests(tmp);
    if (base.code !== 0) throw new Error(`Unmutated tests fail: ${base.failed.join('; ')}`);
    // A skipped Python test would let a shim mutation survive unseen.
    if (base.skipped) throw new Error(`Unmutated run skipped ${base.skipped} tests (no Python 3 at a fixed path).`);
    const results = [];
    for (const mu of MUTATIONS.filter(x => !only || only.includes(x.id))) {
      const path = join(tmp, mu.file), original = readFileSync(path, 'utf8');
      const counts = mu.edits.map(([find]) => original.split(find).length - 1);
      if (counts.some(c => c !== 1)) { results.push({ id: mu.id, property: mu.property, status: 'not-applied', reason: `finds matched ${counts.join(', ')} times` }); continue; }
      writeFileSync(path, mu.edits.reduce((text, [find, replace]) => text.replace(find, () => replace), original));
      try {
        const r = runTests(tmp);
        results.push({ id: mu.id, property: mu.property, file: mu.file, status: r.code === 0 ? 'SURVIVED' : 'killed', killedBy: r.failed.slice(0, 3) });
      } finally { writeFileSync(path, original); }
      process.stderr.write(`${mu.id} ${results.at(-1).status}\n`);
    }
    const summary = { schema: 'scopehaven-framework-mutations/1', at: new Date().toISOString(), node: process.version, test: TESTS.join(' '), total: results.length, killed: results.filter(r => r.status === 'killed').length, results };
    if (outFile) writeFileSync(outFile, `${JSON.stringify(summary, null, 1)}\n`);
    process.stdout.write(`${JSON.stringify({ total: summary.total, killed: summary.killed, survivors: results.filter(r => r.status !== 'killed').map(r => `${r.id} ${r.status}`) })}\n`);
    if (summary.killed !== summary.total) process.exitCode = 1;
  } finally { rmSync(tmp, { recursive: true, force: true }); }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main().catch(error => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
