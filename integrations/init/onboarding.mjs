// Timed onboardings: `./scopehaven init start|review|receipt|table`. They read and append the stamps file init writes in
// its --out folder (clocks.mjs); none of them sends a request or reads a credential.
//
//   init start   --out DIR --label LABEL --owned yes|no --operator-role ROLE
//                starts the clock before the operator opens the docs; one folder is one onboarding. LABEL is a neutral
//                internal label (letters, digits, - or _), never a company or person's name; ROLE is a role, never a name.
//                The patterns cannot tell a name from a label: keeping names out is the operator's job.
//   init review  --out DIR --run RUN_ID --check CHECK_ID --holds yes|no --reviewer-role ROLE
//                records whether a FAIL row of a starter run holds on review (the second clock; "no" is a false FAIL).
//   init receipt --out DIR
//                writes onboarding-receipt.json (0600): both clocks, every init run's outcome, the reviews.
//   init table   DIR [DIR ...] [--json]
//                the timing table over several onboardings and the onboarding done condition, ending with its limits
//                (`limits` in --json).
//
// Exit status: 0 done; 2 refused (a missing or invalid answer, or stamps that do not add up).
import { constants } from 'node:fs';
import { mkdir, open, readFile, rename, unlink } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { join, resolve } from 'node:path';
import { InitError } from './envfile.mjs';
import { appendStamps, readStamps, computeReceipt, timingTable, tableMarkdown, productHead, realDir, STAMP_SCHEMA, RECEIPT_FILE, LABEL, RUN_ID, CHECK_ID, ROLE } from './clocks.mjs';

// The help text is this file's header comment.
const HELP = () => { const lines = readFileSync(fileURLToPath(import.meta.url), 'utf8').split('\n'); return lines.slice(0, lines.findIndex(l => !l.startsWith('//'))).map(l => l.replace(/^\/\/ ?/, '')).join('\n').trimEnd(); };

export const ONBOARDING_COMMANDS = Object.freeze(['start', 'review', 'receipt', 'table']);

function flags(argv, allowed, { json = false } = {}) {
  const o = {}; const rest = [];
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (!flag.startsWith('--')) { rest.push(flag); continue; }
    if (json && flag === '--json') { o[flag] = true; continue; }
    if (!allowed.includes(flag)) throw new InitError('usage', `unknown option ${flag.slice(0, 40)}`);
    const value = argv[i + 1];
    if (typeof value !== 'string' || value.startsWith('--')) throw new InitError('usage', `${flag} needs a value`);
    if (Object.hasOwn(o, flag)) throw new InitError('usage', `${flag} is given twice`);
    o[flag] = value; i += 1;
  }
  return { o, rest };
}
const need = (o, list) => { const missing = list.filter(f => o[f] === undefined); if (missing.length) throw new InitError('missing', `needs ${missing.join(', ')}`); };
const yesNo = (flag, v) => { if (v !== 'yes' && v !== 'no') throw new InitError('usage', `${flag} is yes or no`); return v === 'yes'; };
const role = (flag, v) => { if (!ROLE.test(v)) throw new InitError('usage', `${flag} is a role of 1 to 80 letters, digits, spaces or ,.()/_- (a role, never a person's name)`); return v; };

async function writePrivateReplace(path, content) {
  const temporary = `${path}.${randomBytes(8).toString('hex')}.tmp`;
  try {
    const handle = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    try { await handle.writeFile(content); } finally { await handle.close(); }
    await rename(temporary, path);
  } finally { await unlink(temporary).catch(() => {}); }
}

export async function onboardingCommand(argv, { stdout = process.stdout, env = process.env, now = () => new Date(), head, root } = {}) {
  const say = line => stdout.write(`${line}\n`);
  const [command, ...args] = argv;
  const here = env.SCOPEHAVEN_INIT_CWD || process.cwd();
  const currentHead = () => (head !== undefined ? head : productHead(root ?? here));
  try {
    if (args.includes('--help')) { say(HELP()); return 0; }
    if (command === 'start') {
      const { o } = flags(args, ['--out', '--label', '--owned', '--operator-role']);
      need(o, ['--out', '--label', '--owned', '--operator-role']);
      if (!LABEL.test(o['--label'])) throw new InitError('usage', '--label is 1 to 40 letters, digits, - or _ (a neutral internal label, never a company or person\'s name)');
      const owned = yesNo('--owned', o['--owned']), operatorRole = role('--operator-role', o['--operator-role']);
      const dir = resolve(here, o['--out']);
      await mkdir(dir, { recursive: true, mode: 0o700 });
      if ((await readStamps(dir)).length) throw new InitError('stamps', 'this folder already has stamps; one folder is one onboarding, so choose a new --out');
      const at = now().toISOString();
      await appendStamps(dir, [{ schema: STAMP_SCHEMA, run: randomBytes(6).toString('hex'), stage: 'onboarding-start', at, label: o['--label'], owned, operatorRole, head: currentHead() }]);
      say(`Onboarding clock started for ${o['--label']} at ${at}. Give init the same folder: ./scopehaven init --out ${/\s/.test(o['--out']) ? `'${o['--out']}'` : o['--out']} ...`);
      return 0;
    }
    if (command === 'review') {
      const { o } = flags(args, ['--out', '--run', '--check', '--holds', '--reviewer-role']);
      need(o, ['--out', '--run', '--check', '--holds', '--reviewer-role']);
      if (!RUN_ID.test(o['--run']) || !CHECK_ID.test(o['--check'])) throw new InitError('usage', '--run is a run id and --check a check id, as init printed them');
      const holds = yesNo('--holds', o['--holds']), reviewerRole = role('--reviewer-role', o['--reviewer-role']);
      const dir = resolve(here, o['--out']);
      const saved = (await readStamps(dir)).find(s => s.stage === 'run-saved' && s.runId === o['--run']);
      if (!saved) throw new InitError('review', `no starter run ${o['--run']} was stamped in this folder`);
      if (!(saved.failChecks ?? []).includes(o['--check'])) throw new InitError('review', `${o['--check']} is not a FAIL row of run ${o['--run']}; only FAIL rows are reviewed`);
      // The run file must still say FAIL: the stamp alone is not enough to review against.
      let run;
      try { run = JSON.parse(await readFile(join(dir, 'evidence', 'runs', `${o['--run']}.json`), 'utf8')); } catch { throw new InitError('review', `the run file for ${o['--run']} could not be read under evidence/runs`); }
      if (!(run?.core?.results ?? []).some(r => r.id === o['--check'] && r.status === 'fail')) throw new InitError('review', `the run file does not hold ${o['--check']} as a FAIL row`);
      await appendStamps(dir, [{ schema: STAMP_SCHEMA, run: randomBytes(6).toString('hex'), stage: 'review', at: now().toISOString(), runId: o['--run'], check: o['--check'], holds, reviewerRole }]);
      say(`Review recorded: ${o['--check']} in run ${o['--run']} ${holds ? 'holds' : 'does not hold (a false FAIL)'}.`);
      return 0;
    }
    if (command === 'receipt') {
      const { o } = flags(args, ['--out']);
      need(o, ['--out']);
      const dir = resolve(here, o['--out']);
      const receipt = computeReceipt(await readStamps(dir));
      await writePrivateReplace(join(dir, RECEIPT_FILE), `${JSON.stringify(receipt, null, 2)}\n`);
      const c = receipt.clocks;
      say(`Clock from ${receipt.clockStart.from} (${receipt.clockStart.at}); ${receipt.initRuns.length} init run${receipt.initRuns.length === 1 ? '' : 's'}.`);
      say(`  first decided row: ${c.firstDecidedRow ? `${c.firstDecidedRow.minutes} min (${c.firstDecidedRow.verdict} ${c.firstDecidedRow.check})` : 'not reached'}`);
      say(`  first held FAIL:   ${c.firstHeldFail ? `${c.firstHeldFail.minutes} min (${c.firstHeldFail.check})` : 'none'}`);
      say(`  FAIL rows: ${receipt.fails.total}; held ${receipt.fails.held}; false ${receipt.fails.falseFails.length}; unreviewed ${receipt.fails.unreviewed.length}${receipt.fails.unreviewed.length ? ' (./scopehaven init review ...)' : ''}`);
      say(`Wrote ${join(o['--out'], RECEIPT_FILE)}.`);
      return 0;
    }
    if (command === 'table') {
      const { o, rest } = flags(args, [], { json: true });
      if (!rest.length) throw new InitError('missing', 'needs one or more onboarding folders');
      const receipts = [];
      const dirs = rest.map(d => realDir(resolve(here, d)));
      if (new Set(dirs).size !== dirs.length) throw new InitError('usage', 'a folder is given twice; each onboarding counts once');
      for (const d of dirs) receipts.push(computeReceipt(await readStamps(d)));
      const table = timingTable(receipts);
      say(o['--json'] ? JSON.stringify(table, null, 2) : tableMarkdown(table));
      return 0;
    }
    throw new InitError('usage', `unknown command ${String(command).slice(0, 20)}`);
  } catch (error) {
    say(`init ${command} stopped (${error instanceof InitError ? error.code : 'error'}): ${error instanceof InitError ? error.message : String(error?.message ?? error).slice(0, 300)}`);
    return 2;
  }
}
