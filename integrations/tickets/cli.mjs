// node integrations/tickets/cli.mjs --run UUID --format jira-csv|github-md --out ABSOLUTE_NEW_FILE [--data ABSOLUTE_STORE] [--baseline UUID]
// Exports a saved run (or, with --baseline, the candidate compared with the baseline exactly
// as the local API compares them) as Jira CSV or GitHub-issue markdown. Local files only:
// the output parent must exist with mode 0700 and belong to you, and an existing file is
// never overwritten. No network.
import { constants } from 'node:fs';
import { lstat, open, link, unlink } from 'node:fs/promises';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createHash, randomUUID } from 'node:crypto';
import { createStore } from '../../src/store.mjs';
import { compareRuns } from '../../src/runner.mjs';
import { idValid } from '../../src/http.mjs';
import { renderTickets, TICKET_FORMATS } from './tickets.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
export async function exportTickets({ runId, format, outputFile, dataDir = join(root, 'data'), baselineRunId }) {
  if (!idValid(runId) || !TICKET_FORMATS.includes(format) || (baselineRunId !== undefined && !idValid(baselineRunId)) || !isAbsolute(outputFile || '') || !isAbsolute(dataDir)) throw new Error('Invalid export options.');
  const parent = dirname(outputFile), stat = await lstat(parent);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid() || (stat.mode & 0o7777) !== 0o700) throw new Error('Export directory must be private, owned and not a symlink.');
  const store = createStore(dataDir); await store.ready;
  const run = await store.get(runId);
  let baseline = null, comparison = null;
  if (baselineRunId !== undefined) {
    baseline = await store.get(baselineRunId);
    comparison = compareRuns(baseline, run);
  }
  // The export checks the comparison against a fresh compareRuns.
  const content = Buffer.from(baseline === null ? renderTickets(run, { format }) : renderTickets(run, { format, baseline, comparison }));
  if (content.length > 8 * 1024 * 1024) throw new Error('Export exceeds its limit.');
  const temporary = join(parent, `.${randomUUID()}.tickets.tmp`);
  try {
    const handle = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    try { await handle.writeFile(content); await handle.sync(); } finally { await handle.close(); }
    await link(temporary, outputFile); // Exclusive publication; never overwrite.
  } finally { await unlink(temporary).catch(() => {}); }
  return { saved: true, runId, ...(baseline ? { baselineRunId } : {}), format, bytes: content.length, sha256: createHash('sha256').update(content).digest('hex') };
}

export async function main(args) {
  const names = { '--run': 'runId', '--format': 'format', '--out': 'outputFile', '--data': 'dataDir', '--baseline': 'baselineRunId' }, options = {};
  for (let i = 0; i < args.length; i += 2) {
    const key = names[args[i]], value = args[i + 1];
    if (!key || Object.hasOwn(options, key) || !value || value.startsWith('--')) throw new Error('Invalid export options.');
    options[key] = value;
  }
  return exportTickets(options);
}
if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try { console.log(JSON.stringify(await main(process.argv.slice(2)), null, 2)); }
  catch { console.error('Ticket export failed. Use --run UUID --format jira-csv|github-md --out ABSOLUTE_NEW_FILE [--data ABSOLUTE_STORE] [--baseline UUID]. The output parent must exist with mode 0700 and belong to you. Existing files are preserved.'); process.exitCode = 2; }
}
