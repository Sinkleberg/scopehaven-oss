import { readFileSync, realpathSync, statSync } from 'node:fs';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

// A deliberately narrow parser for the launcher-forced Node 24 TAP reporter.
// It does not interpret arbitrary TAP/YAML, spec output, or matching log text as
// proof. Unsupported shapes stay red. Console output is escaped by Node's TAP
// reporter, while test results, diagnostics, plans and final counters are not.
const keys = ['tests', 'suites', 'pass', 'fail', 'cancelled', 'skipped', 'todo', 'duration_ms'];
const integer = /^(0|[1-9]\d*)$/;
const decimal = /^(0|[1-9]\d*)(\.\d+)?$/;
function scalar(value) {
  if (value.startsWith('"')) return JSON.parse(value);
  if (value.startsWith("'") && value.endsWith("'")) return value.slice(1, -1).replaceAll("''", "'");
  throw new Error('unsupported diagnostic scalar');
}
function invalid(reason) { return { outcome: 'invalid', reason, files: [] }; }

export function parseSuiteLog(text, status) {
  try {
    if (!Number.isInteger(status) || status < 0 || status > 255) return invalid('invalid process status');
    if (!text.endsWith('\n') || text.includes('\r') || text.includes('\0')) return invalid('truncated or malformed log');
    const lines = text.trimEnd().split('\n');
    if (lines[0] !== 'TAP version 13') return invalid('missing forced TAP header');
    if (lines.length < 10) return invalid('missing final summary');
    const start = lines.length - keys.length;
    const summary = {};
    for (let i = 0; i < keys.length; i++) {
      const prefix = `# ${keys[i]} `;
      const value = lines[start + i].startsWith(prefix) ? lines[start + i].slice(prefix.length) : '';
      if (!(i === keys.length - 1 ? decimal : integer).test(value) || !Number.isFinite(Number(value)) ||
          (i !== keys.length - 1 && !Number.isSafeInteger(Number(value)))) return invalid('missing or malformed final summary');
      summary[keys[i]] = Number(value);
    }
    if (!/^1\.\.(0|[1-9]\d*)$/.test(lines[start - 1])) return invalid('missing final root plan');
    const results = [];
    const counts = new Map();
    const pending = [];
    let rootPlan;
    for (let i = 1; i < start; i++) {
      const line = lines[i];
      if (line === '') continue;
      const subtest = /^( *)# Subtest: (.*)$/.exec(line);
      if (subtest) {
        const depth = subtest[1].length;
        const parent = pending.at(-1);
        if (depth % 4 || (parent ? depth !== parent.depth + 4 || parent.childPlan : depth !== 0)) {
          return invalid('orphan or misplaced subtest');
        }
        if (parent) parent.hasChildren = true;
        pending.push({ depth, name: subtest[2], hasChildren: false, childPlan: false });
        continue;
      }
      const plan = /^( *)1\.\.(0|[1-9]\d*)(?: # SKIP(?: .*)?)?$/.exec(line);
      if (plan) {
        const depth = plan[1].length;
        if (depth % 4 || Number(plan[2]) !== (counts.get(depth) ?? 0)) return invalid('contradictory plan');
        counts.delete(depth);
        if (depth === 0) {
          if (i !== start - 1 || rootPlan !== undefined || pending.length) return invalid('duplicate or misplaced root plan');
          rootPlan = Number(plan[2]);
        } else {
          const parent = pending.at(-1);
          if (!parent || parent.depth + 4 !== depth || parent.childPlan) return invalid('orphan child plan');
          parent.childPlan = true;
        }
        continue;
      }
      const result = /^( *)(ok|not ok) ([1-9]\d*) - (.*)$/.exec(line);
      if (result) {
        const depth = result[1].length;
        const number = Number(result[3]);
        const directiveMatch = / # (SKIP|TODO)(?: |$)/.exec(result[4]);
        const name = directiveMatch ? result[4].slice(0, directiveMatch.index) : result[4];
        const started = pending.pop();
        if (!started || started.depth !== depth || started.name !== name ||
            (started.hasChildren && !started.childPlan)) return invalid('result contradicts subtest structure');
        if (depth % 4 || number !== (counts.get(depth) ?? 0) + 1) return invalid('malformed result sequence');
        counts.set(depth, number);
        const indent = `${result[1]}  `;
        if (lines[++i] !== `${indent}---`) return invalid('missing result diagnostics');
        const fields = {};
        const fieldNames = [];
        let complete = false;
        for (++i; i < start; i++) {
          if (lines[i] === `${indent}...`) { complete = true; break; }
          if (!lines[i].startsWith(indent)) return invalid('truncated result diagnostics');
          const anyField = /^([A-Za-z_][\w]*): /.exec(lines[i].slice(indent.length));
          if (anyField) fieldNames.push(anyField[1]);
          const field = /^(duration_ms|type|location|failureType): (.*)$/.exec(lines[i].slice(indent.length));
          if (field) {
            if (Object.hasOwn(fields, field[1])) return invalid('duplicate diagnostic field');
            fields[field[1]] = field[2];
          }
        }
        if (!complete || !decimal.test(fields.duration_ms ?? '') || !Number.isFinite(Number(fields.duration_ms))) {
          return invalid('missing or malformed diagnostic completion');
        }
        const type = scalar(fields.type ?? '');
        if (type !== 'test' && type !== 'suite') return invalid('unsupported test type');
        if (result[2] === 'ok' && fieldNames.some(key => key !== 'duration_ms' && key !== 'type')) {
          return invalid('passing result has failure diagnostics');
        }
        // AbortSignal failures carry error/stack but no failureType in Node 24.
        if (result[2] === 'not ok' && !fieldNames.includes('error')) {
          return invalid('missing failure diagnostics');
        }
        if (fields.failureType !== undefined && !scalar(fields.failureType)) return invalid('malformed failure type');
        const directive = directiveMatch?.[1];
        const failed = result[2] === 'not ok' && !directive;
        const location = fields.location === undefined ? undefined : scalar(fields.location);
        if (location !== undefined && typeof location !== 'string') return invalid('invalid failure location');
        results.push({ type, directive, failed, location });
        continue;
      }
      // Final counter lines are allowed only in the one completion block above.
      if (/^ *#/.test(line) && !/^# (tests|suites|pass|fail|cancelled|skipped|todo|duration_ms)(?: |$)/.test(line)) continue;
      return invalid('unsupported or contradictory reporter output');
    }
    if (rootPlan === undefined || counts.size || pending.length) return invalid('incomplete plans');
    const tests = results.filter(r => r.type === 'test');
    const suites = results.filter(r => r.type === 'suite');
    const count = predicate => tests.filter(predicate).length;
    if (summary.tests !== tests.length || summary.suites !== suites.length ||
        summary.pass !== count(r => !r.failed && !r.directive) ||
        summary.skipped !== count(r => r.directive === 'SKIP') ||
        summary.todo !== count(r => r.directive === 'TODO') ||
        summary.fail + summary.cancelled !== count(r => r.failed) ||
        summary.tests !== summary.pass + summary.fail + summary.cancelled + summary.skipped + summary.todo) {
      return invalid('contradictory summary counts');
    }
    if (summary.tests === 0) return invalid('run reported zero tests');
    const failed = results.filter(r => r.failed);
    const red = summary.fail + summary.cancelled > 0 || failed.length > 0;
    if ((status === 0) === red) return invalid('process status contradicts test results');
    if (!red) return { outcome: 'pass', reason: 'complete successful run', summary, files: [] };
    if (status !== 1 || summary.cancelled > 0) return { outcome: 'fail', reason: 'abnormal exit or cancelled tests', summary, files: [] };
    const files = [];
    for (const failure of failed) {
      const match = /^(.*):[1-9]\d*:[1-9]\d*$/.exec(failure.location ?? '');
      if (!match || !match[1] || /[\r\n\0]/.test(match[1])) return { outcome: 'fail', reason: 'unidentified failure location', summary, files: [] };
      files.push(match[1]);
    }
    const unique = [...new Set(files)].sort();
    if (!unique.length || unique.length > 8) return { outcome: 'fail', reason: `${unique.length} failed files; retry limit is 1..8`, summary, files: [] };
    return { outcome: 'retry', reason: 'complete run with identified failed files', summary, files: unique };
  } catch {
    return invalid('malformed result diagnostics');
  }
}

export function localRetryFiles(files, cwd) {
  const root = realpathSync(cwd);
  return [...new Set(files.map(file => {
    const path = realpathSync(resolve(root, file));
    const rel = relative(root, path);
    if (!rel || rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel) ||
        !statSync(path).isFile() || /[\r\n\0]/.test(path)) throw new Error('failed file is missing or outside the suite directory');
    return path;
  }))].sort();
}

function isEntrypoint() {
  try { return realpathSync(process.argv[1]) === fileURLToPath(import.meta.url); }
  catch { return false; }
}

if (isEntrypoint()) {
  try {
    if (process.argv.length !== 4 || !integer.test(process.argv[3])) throw new Error('usage: parse-suite-log.mjs LOG PROCESS_STATUS');
    const result = parseSuiteLog(readFileSync(process.argv[2], 'utf8'), Number(process.argv[3]));
    if (result.outcome === 'pass') process.exitCode = 0;
    else if (result.outcome === 'retry') {
      const files = localRetryFiles(result.files, process.cwd());
      process.stdout.write(`${files.join('\n')}\n`);
      process.exitCode = 10;
    } else {
      process.stderr.write(`No rerun: ${result.reason}.\n`);
      process.exitCode = 1;
    }
  } catch (error) {
    process.stderr.write(`No rerun: ${error.message}.\n`);
    process.exitCode = 1;
  }
}
