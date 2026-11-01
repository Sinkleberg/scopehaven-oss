// Model identity CLI. Local operator only; no provider calls of its own.
//   node integrations/model-identity/cli.mjs tap --upstream http://127.0.0.1:11434 --log ABSOLUTE_NEW_FILE [--port N] [--no-ollama-tags]
//       --upstream may also be https://api.openai.com or https://api.anthropic.com (no model list is asked for).
//       Runs until SIGINT or SIGTERM. Point the application's model base URL at the
//       printed URL. Writes one new log (mode 0600); never overwrites one.
//   node integrations/model-identity/cli.mjs identity --log FILE [--from SEQ --to SEQ]
//   node integrations/model-identity/cli.mjs attribute --store DIR --baseline RUN_ID --candidate RUN_ID --baseline-log FILE --candidate-log FILE
//       [--baseline-window FROM:TO --candidate-window FROM:TO] [--locus FILE]
//       Core compareRuns on the two stored runs (integrity checked by the core
//       store), then each flip credited to the application or put down to the model.
//       The logs given here decide; a modelIdentity the stored runs carry is set aside.
//       One log for both runs is refused unless two windows that do not overlap are given.
//       --locus: a JSON list of { check, observations } (locus.mjs classifyLocus inputs: the check's
//       declared action and the observations read from the application's records). credit-basis.mjs
//       computes each reading itself, and each repair credited to the application then says what it rests
//       on (creditBasis), bound to the candidate run's targetBuildHash.
// Exit codes:
//   identity   0 observed or mixed, 1 partial or not-observed, 2 usage or file error
//   attribute  0 compatible, controls passing, and every flip credited to the application (or no flips),
//              1 incompatible, controls failing, any flip not credited to the application, or a locus reading
//                that recorded the action committing on the candidate build (contradicted, or a commit outside
//                the credit); 2 usage or file error
//   tap        0 stopped on a signal with its log intact, 2 usage, file or log-write error
import { pathToFileURL } from 'node:url';
import { isAbsolute } from 'node:path';
import { realpathSync, readFileSync } from 'node:fs';
import { createModelTap, TapLog } from './tap.mjs';
import { readTapLog, modelIdentity } from './identity.mjs';
import { attributeComparison, appChangedBetween } from './attribute.mjs';

const USAGE = 'Usage: cli.mjs tap --upstream http://127.0.0.1:PORT|https://api.openai.com|https://api.anthropic.com --log ABSOLUTE_NEW_FILE [--port N] [--no-ollama-tags] | identity --log FILE [--from SEQ --to SEQ] | attribute --store DIR --baseline RUN_ID --candidate RUN_ID --baseline-log FILE --candidate-log FILE [--baseline-window FROM:TO --candidate-window FROM:TO] [--locus FILE]';
const FLAGS = { tap: ['upstream', 'log', 'port'], identity: ['log', 'from', 'to'], attribute: ['store', 'baseline', 'candidate', 'baseline-log', 'candidate-log', 'baseline-window', 'candidate-window', 'locus'] };
const SWITCHES = { tap: ['no-ollama-tags'], identity: [], attribute: [] };

export function parseArgs(argv) {
  const [command, ...rest] = argv;
  if (!Object.hasOwn(FLAGS, command)) throw new Error(USAGE);
  const options = {};
  for (let i = 0; i < rest.length; i++) {
    const flag = rest[i];
    if (!flag.startsWith('--')) throw new Error(USAGE);
    const key = flag.slice(2);
    if (SWITCHES[command].includes(key)) { options[key] = true; continue; }
    if (!FLAGS[command].includes(key) || Object.hasOwn(options, key) || i + 1 >= rest.length) throw new Error(USAGE);
    options[key] = rest[++i];
  }
  const need = { tap: ['upstream', 'log'], identity: ['log'], attribute: ['store', 'baseline', 'candidate', 'baseline-log', 'candidate-log'] }[command];
  if (need.some(k => !options[k])) throw new Error(USAGE);
  for (const k of ['log', 'store', 'baseline-log', 'candidate-log', 'locus']) if (options[k] !== undefined && !isAbsolute(options[k])) throw new Error('Paths must be absolute.');
  const integer = (k, min) => { if (options[k] === undefined) return undefined; const n = Number(options[k]); if (!/^[0-9]+$/.test(options[k]) || !Number.isSafeInteger(n) || n < min) throw new Error(`--${k} must be an integer of at least ${min}.`); return n; };
  if (command === 'tap') options.port = integer('port', 0) ?? 0;
  if (command === 'identity') { options.from = integer('from', 0); options.to = integer('to', 0); if ((options.from === undefined) !== (options.to === undefined)) throw new Error('Give --from and --to together.'); }
  if (command === 'attribute') {
    const windowOf = k => { if (options[k] === undefined) return undefined; const m = /^([0-9]{1,15}):([0-9]{1,15})$/.exec(options[k]); if (!m || Number(m[1]) > Number(m[2])) throw new Error(`--${k} must be FROM:TO with FROM <= TO.`); return { from: Number(m[1]), to: Number(m[2]) }; };
    options.baselineWindow = windowOf('baseline-window'); options.candidateWindow = windowOf('candidate-window');
    if ((options.baselineWindow === undefined) !== (options.candidateWindow === undefined)) throw new Error('Give --baseline-window and --candidate-window together.');
  }
  return { command, options };
}

// The locus inputs; credit-basis.mjs computes every reading from them and never takes one ready-made.
const locusEntries = path => JSON.parse(readFileSync(realpathSync(path), 'utf8'));

export async function main(argv, { stdout = process.stdout, stderr = process.stderr, signals = process } = {}) {
  let parsed;
  try { parsed = parseArgs(argv); } catch (error) { stderr.write(`${error.message}\n`); return 2; }
  const { command, options } = parsed;
  try {
    if (command === 'tap') {
      const tap = createModelTap({ upstream: options.upstream, port: options.port, log: new TapLog({ path: options.log }), ...(options['no-ollama-tags'] ? { ollamaTags: false } : {}) });
      // The stop handlers are in place before the URL is printed, so a caller that stops the tap
      // as soon as it reads the URL always gets an orderly stop (and the log's closing frame).
      const stopped = new Promise(resolve => { const done = () => { signals.off?.('SIGINT', done); signals.off?.('SIGTERM', done); resolve(); }; signals.on('SIGINT', done); signals.on('SIGTERM', done); });
      await tap.start();
      stdout.write(`${JSON.stringify({ tap: tap.url, upstream: options.upstream, log: options.log })}\n`);
      await stopped;
      await tap.stop();
      if (tap.log.writeError) { stderr.write(`The tap log could not be written (${tap.log.writeError}); the log is incomplete.\n`); return 2; }
      return 0;
    }
    if (command === 'identity') {
      const window = options.from === undefined ? {} : { from: options.from, to: options.to };
      const id = modelIdentity(readTapLog(options.log), window);
      stdout.write(`${JSON.stringify(id, null, 2)}\n`);
      return ['observed', 'mixed'].includes(id.state) ? 0 : 1;
    }
    const { createStore } = await import('../../src/store.mjs');
    const { compareRuns } = await import('../../src/runner.mjs');
    const [baselineLog, candidateLog] = [realpathSync(options['baseline-log']), realpathSync(options['candidate-log'])];
    if (baselineLog === candidateLog && !options.baselineWindow) throw new Error('The same tap log was given for both runs; give two logs, or two windows of it that do not overlap.');
    const store = createStore(options.store);
    const baselineRun = await store.get(options.baseline), candidateRun = await store.get(options.candidate);
    // Attribute once, on the core comparison: the identities come from the tap logs given here, so a
    // modelIdentity the stored runs carry is set aside instead of being attributed a second time.
    const core = ({ modelIdentity: _stored, ...run }) => run;
    const comparison = compareRuns(core(baselineRun), core(candidateRun));
    const inputs = {
      baselineIdentity: modelIdentity(readTapLog(baselineLog), options.baselineWindow ?? {}), candidateIdentity: modelIdentity(readTapLog(candidateLog), options.candidateWindow ?? {}),
      app: appChangedBetween(baselineRun, candidateRun),
    };
    const result = options.locus
      ? (await import('./credit-basis.mjs')).attributeWithCreditBasis(comparison, { ...inputs, locus: locusEntries(options.locus), candidateBuild: candidateRun.targetBuildHash })
      : attributeComparison(comparison, inputs);
    // Say so when the stored runs carried an identity that the logs given here replaced.
    const setAside = ['baseline', 'candidate'].filter((_, i) => [baselineRun, candidateRun][i]?.modelIdentity !== undefined);
    stdout.write(`${JSON.stringify(setAside.length ? { ...result, storedIdentitySetAside: setAside } : result, null, 2)}\n`);
    const flips = result.rows.filter(r => !['no-change', 'incompatible', 'held-across-model-change', 'failed-across-model-change'].includes(r.attribution));
    const withdrawn = result.creditBasis && (result.creditBasis.counts.contradicted > 0 || result.creditBasis.commitsOutsideCredit.length > 0);
    return result.compatible && result.controlsPass !== false && flips.every(r => r.attribution === 'app') && !withdrawn ? 0 : 1;
  } catch (error) {
    stderr.write(`${error?.code === 'EEXIST' ? 'The log file already exists; the tap never reuses a log.' : error?.message ?? 'error'}\n`);
    return 2;
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) process.exitCode = await main(process.argv.slice(2));
