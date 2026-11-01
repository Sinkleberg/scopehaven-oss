// node integrations/revocation-clock/cli.mjs run [--hold 1|2|3] [--delay <ms>] [--recheck] [--budget <ms>] [--settle <ms>] --out <file>
// node integrations/revocation-clock/cli.mjs sweep [--k 5] [--delay <ms>] [--recheck] [--settle <ms>] --out <file>
// node integrations/revocation-clock/cli.mjs --validate <file> [--gate]
// --validate takes a run record (scopehaven-revocation-clock/1) or a sweep
// (scopehaven-revocation-clock-sweep/1) and recomputes it; anything else is refused.
// Runs on the owned agent desk over loopback; writes JSON (never overwrites). Exit codes:
// 0 done (or validated), 1 a record that does not validate, 2 usage or file error.
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { runRevocationClock, runClockSweep, validateClockRecord, validateClockSweep, CLOCK_SCHEMA, CLOCK_SWEEP_SCHEMA, CLOCK_DEFAULTS } from './clock.mjs';

const usage = 'usage: cli.mjs run|sweep [--hold N] [--k N] [--delay MS] [--recheck] [--budget MS] [--settle MS] --out <file> | cli.mjs --validate <file> [--gate]';
const json = v => `${JSON.stringify(v, null, 1)}\n`;
async function main(argv) {
  const flag = name => { const i = argv.indexOf(name); return i === -1 ? null : argv[i + 1] ?? ''; };
  const int = (name, fallback) => { const v = flag(name); if (v === null) return fallback; if (!/^\d+$/.test(v)) throw new Error(`${name} needs a whole number`); return Number(v); };
  if (argv[0] === '--validate') {
    const file = argv[1];
    if (!file || !existsSync(file)) { process.stderr.write(`${usage}\n`); return 2; }
    const doc = JSON.parse(readFileSync(file, 'utf8')), custody = argv.includes('--gate') ? 'gate' : 'tag';
    try {
      if (doc?.schema === CLOCK_SCHEMA) { const d = validateClockRecord(doc, { custody }); process.stdout.write(json({ validated: 'record', reading: d.reading, ...(d.verdict ? { verdict: d.verdict } : {}) })); return 0; }
      if (doc?.schema === CLOCK_SWEEP_SCHEMA) { const points = validateClockSweep(doc, { custody }); process.stdout.write(json({ validated: 'sweep', points: points.map(p => ({ holdAt: p.holdAt, successes: p.successes, n: p.n, passHatK: p.passHatK, control: p.control, readings: p.readings })) })); return 0; }
      throw new Error('Not a revocation-clock record or sweep.');
    } catch (error) { process.stdout.write(json({ validated: false, error: error.message })); return 1; }
  }
  const out = flag('--out');
  if (!['run', 'sweep'].includes(argv[0]) || !out || !isAbsolute(out)) { process.stderr.write(`${usage}\n`); return 2; }
  if (existsSync(out)) { process.stderr.write('--out exists; nothing is overwritten\n'); return 2; }
  const common = { commitDelayMs: int('--delay', 0), recheckEachStep: argv.includes('--recheck'), settleMs: int('--settle', CLOCK_DEFAULTS.settleMs), profile: flag('--budget') === null ? {} : { budgetMs: int('--budget') } };
  const result = argv[0] === 'run' ? await runRevocationClock({ holdAt: int('--hold', 3), ...common }) : await runClockSweep({ k: int('--k', 5), ...common });
  writeFileSync(out, json(result), { flag: 'wx' });
  process.stdout.write(json(argv[0] === 'run' ? result.derived : result.points.map(p => ({ holdAt: p.holdAt, successes: p.successes, n: p.n, passHatK: p.passHatK, control: p.control, exposures: p.exposures }))));
  return 0;
}
main(process.argv.slice(2)).then(code => { process.exitCode = code; }, error => { process.stderr.write(`${error.message}\n`); process.exitCode = 2; });
