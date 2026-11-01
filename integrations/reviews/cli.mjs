// node integrations/reviews/cli.mjs record --data ABSOLUTE_STORE --run UUID --finding CHECK_ID --decision agree|dispute [--reason TEXT] --reviewer NAME --key PRIVATE_PEM
// node integrations/reviews/cli.mjs summary --data ABSOLUTE_STORE --run UUID --pub PUBLIC_PEM
// Records a signed review beside a saved run, or prints the review counts and disputes.
// Local files only; the run store and its evidence are only read.
import { readFileSync } from 'node:fs';
import { isAbsolute, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createStore } from '../../src/store.mjs';
import { createReviewStore, makeReview, reviewSummary } from './reviews.mjs';

export async function main(args) {
  const [command, ...rest] = args, opts = {};
  for (let i = 0; i < rest.length; i += 2) { if (!rest[i]?.startsWith('--') || rest[i + 1] === undefined || Object.hasOwn(opts, rest[i])) throw new Error('Invalid options.'); opts[rest[i]] = rest[i + 1]; }
  if (!isAbsolute(opts['--data'] ?? '')) throw new Error('Invalid options.');
  const store = createStore(opts['--data']); await store.ready;
  const run = await store.get(opts['--run']), reviews = createReviewStore(opts['--data']);
  if (command === 'record') {
    const review = makeReview({ reviewer: opts['--reviewer'], runId: run.id, findingId: opts['--finding'], decision: opts['--decision'], reason: opts['--reason'] ?? '' });
    return (await reviews.record(run, review, { privateKey: readFileSync(opts['--key'], 'utf8') })).review;
  }
  if (command === 'summary') return reviewSummary(run, await reviews.read(run.id, { publicKey: readFileSync(opts['--pub'], 'utf8') }));
  throw new Error('Invalid options.');
}
if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try { console.log(JSON.stringify(await main(process.argv.slice(2)), null, 2)); }
  catch (error) { console.error(`Review failed: ${error?.code ? error.message : 'use record or summary with the options in the header'}`); process.exitCode = 2; }
}
