// Policy import CLI. Reads local files only; never connects to a database or service.
//   node integrations/policy-import/cli.mjs import rls --app ID [--roles a,b] [--bypass-roles x,y] (--catalog FILE | FILE_OR_DIR...) --out NEW_FILE
//   node integrations/policy-import/cli.mjs import openapi --app ID [--role-map FILE] FILE --out NEW_FILE
//   node integrations/policy-import/cli.mjs import openwebui --app ID FILE --out NEW_FILE
//   node integrations/policy-import/cli.mjs summary MATRIX
//   node integrations/policy-import/cli.mjs diff BEFORE_MATRIX AFTER_MATRIX [--out NEW_FILE]
//   node integrations/policy-import/cli.mjs draft MATRIX --binding FILE --out NEW_FILE
//   node integrations/policy-import/cli.mjs confirm DRAFT --matrix MATRIX --binding FILE --profile FILE --confirmed-by "NAME" --out-profile NEW_FILE --out-record NEW_FILE
//   node integrations/policy-import/cli.mjs explain RUN_JSON --record CONFIRMATION --profile PROFILE
//   node integrations/policy-import/cli.mjs statement propose MATRIX... --app ID --out NEW_FILE
//   node integrations/policy-import/cli.mjs statement seal STATEMENT [MATRIX...] --stated-by "NAME" --out NEW_FILE
//   node integrations/policy-import/cli.mjs statement check STATEMENT [MATRIX...] [--out NEW_FILE]
//   node integrations/policy-import/cli.mjs write-plan STATEMENT --binding WRITE_BINDING [MATRIX...] --out NEW_FILE
//   node integrations/policy-import/cli.mjs write-confirm PLAN --statement STATEMENT --binding WRITE_BINDING [MATRIX...] --confirmed-by "LABEL" --out NEW_FILE
//   node integrations/policy-import/cli.mjs write-draft MATRIX --binding WRITE_DRAFT_BINDING [--document OPENAPI_FILE] --out NEW_FILE
//   node integrations/policy-import/cli.mjs write-draft-confirm DRAFT --matrix MATRIX --binding FILE [--document OPENAPI_FILE] --profile FILE --confirmed-by "NAME" [--check-ids a,b] [--reset FILE] --out-profile NEW_FILE --out-record NEW_FILE
//   node integrations/policy-import/cli.mjs reset DECLARATION [--record NEW_FILE] [--skip-reset]
//   node integrations/policy-import/cli.mjs seed-hash DECLARATION
// A directory of migrations is read in file-name order (*.sql, not recursive). Outputs are
// new files (never overwritten), mode 0600. Exit codes: 0 done; 1 diff found a gated change
// (widened, added open, became unknown or became undeclared, a new gap, or any gap of the after matrix
// when the gaps can't be compared by identity) or explain found a mismatch; 2 usage, file or
// validation error; 3 explain could not verify every check (not run, no verdict, a different
// check, or a run without a checksum). statement check exits 1 when a stated rule disagrees with a
// matrix's declaration for the same cell (stricter or wider); that is a question for a test, not a verdict. It exits 3
// when no cell disagrees but some cell is unresolved (a conditional declaration it did not evaluate), so an incomplete
// comparison never reads as agreement. Precedence: 2 > 1 > 3 > 0.
// reset exits 0 when the seed matches its recorded hash (or was just recorded into --record), 1 when it differs.
// --stated-by and --confirmed-by are labels the caller supplies: they authenticate no one.
import { createHash } from 'node:crypto';
import { lstat, readdir, readFile, writeFile } from 'node:fs/promises';
import { basename, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { diffMatrices, summarize } from './matrix.mjs';
import { importRls } from './rls.mjs';
import { importOpenApi } from './openapi.mjs';
import { importOpenWebUi } from './openwebui.mjs';
import { confirmDraft, draftChecks, explainRun } from './draft.mjs';
import { checkStatement, proposeStatement, sealStatement } from './statement.mjs';
import { buildWritePlan } from './write-plan.mjs';
import { confirmWritePlan } from './write-confirm.mjs';
import { confirmWriteDraft, draftWriteChecks } from './write-draft.mjs';
import { ensureSeed, seedHash } from './reset.mjs';

const MAX_BYTES = 8 * 1024 * 1024;
const LABEL_NOTE = '--stated-by and --confirmed-by are free-text labels the caller supplies; they authenticate no one, and "verified" means local checks only.';
const USAGE = 'Usage: cli.mjs import (rls|openapi|openwebui) ... | summary MATRIX | diff BEFORE AFTER | draft MATRIX --binding FILE --out NEW | confirm DRAFT --matrix MATRIX --binding FILE --profile FILE --confirmed-by NAME --out-profile NEW --out-record NEW | explain RUN --record FILE --profile FILE | statement propose MATRIX... --app ID --out NEW | statement seal STATEMENT [MATRIX...] --stated-by NAME --out NEW | statement check STATEMENT [MATRIX...] [--out NEW] | write-plan STATEMENT --binding FILE [MATRIX...] --out NEW | write-confirm PLAN --statement FILE --binding FILE [MATRIX...] --confirmed-by LABEL --out NEW | write-draft MATRIX --binding FILE [--document FILE] --out NEW | write-draft-confirm DRAFT --matrix MATRIX --binding FILE [--document FILE] --profile FILE --confirmed-by NAME [--check-ids a,b] [--reset FILE] --out-profile NEW --out-record NEW | reset DECLARATION [--record NEW] [--skip-reset] | seed-hash DECLARATION';

// Flags that take no value.
const BOOLEAN_FLAGS = new Set(['--skip-reset']);
function parse(argv) {
  const flags = {}, positional = [];
  for (let i = 0; i < argv.length; i++) {
    if (BOOLEAN_FLAGS.has(argv[i])) { flags[argv[i].slice(2)] = true; continue; }
    if (argv[i].startsWith('--')) { const value = argv[i + 1]; if (value === undefined || value.startsWith('--')) throw new Error(`${argv[i]} needs a value.`); flags[argv[i].slice(2)] = value; i++; }
    else positional.push(argv[i]);
  }
  return { flags, positional };
}
async function readRegular(path) {
  const stat = await lstat(path);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`${path} must be a regular file, not a link or directory.`);
  if (stat.size > MAX_BYTES) throw new Error(`${path} is larger than ${MAX_BYTES} bytes.`);
  return readFile(path);
}
const readJson = async path => { try { return JSON.parse(await readRegular(path)); } catch (error) { throw new Error(error instanceof SyntaxError ? `${path} is not valid JSON.` : error.message); } };
const list = value => value ? value.split(',').map(s => s.trim()).filter(Boolean) : [];
async function writeNew(path, value) {
  if (!path) throw new Error('An output path is required.');
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
}
async function migrationFiles(paths) {
  const files = [];
  for (const path of paths) {
    const stat = await lstat(path);
    if (stat.isDirectory()) {
      const names = (await readdir(path)).filter(n => n.endsWith('.sql')).sort();
      if (!names.length) throw new Error(`${path} has no .sql files.`);
      for (const name of names) files.push({ id: name, content: await readRegular(join(path, name)), kind: 'sql' });
    } else files.push({ id: basename(path), content: await readRegular(path), kind: 'sql' });
  }
  return files;
}

export async function main(argv, { out = console.log, err = console.error } = {}) {
  if (argv.includes('--help') || argv[0] === 'help') { out(`${USAGE}\n${LABEL_NOTE}`); return 0; }
  const [command, ...rest] = argv;
  const { flags, positional } = parse(rest);
  if (command === 'import') {
    const [kind, ...inputs] = positional;
    if (!flags.app) throw new Error('--app names the application.');
    let matrix;
    if (kind === 'rls') {
      const files = flags.catalog ? [{ id: basename(flags.catalog), content: await readRegular(flags.catalog), kind: 'catalog-json' }] : await migrationFiles(inputs);
      if (!files.length) throw new Error('Give migration files, a migrations directory or --catalog.');
      matrix = importRls(files, { application: flags.app, roles: list(flags.roles), bypassRoles: list(flags['bypass-roles']) });
    } else if (kind === 'openapi' && inputs.length === 1) matrix = importOpenApi({ id: basename(inputs[0]), content: await readRegular(inputs[0]) }, { application: flags.app, roleMap: flags['role-map'] ? await readJson(flags['role-map']) : undefined });
    else if (kind === 'openwebui' && inputs.length === 1) matrix = importOpenWebUi({ id: basename(inputs[0]), content: await readRegular(inputs[0]) }, { application: flags.app });
    else throw new Error(USAGE);
    await writeNew(flags.out, matrix);
    out(JSON.stringify(summarize(matrix)));
    return 0;
  }
  if (command === 'summary' && positional.length === 1) { out(JSON.stringify(summarize(await readJson(positional[0])), null, 2)); return 0; }
  if (command === 'diff' && positional.length === 2) {
    const result = diffMatrices(await readJson(positional[0]), await readJson(positional[1]));
    if (flags.out) await writeNew(flags.out, result);
    out(JSON.stringify(result.comparable ? { comparable: true, gated: result.gated, counts: result.counts, gapComparison: result.gapComparison, gapCounts: result.gapCounts,
      ...(result.gapNote ? { gapNote: result.gapNote } : {}) } : result));
    if (!result.comparable) return 2;
    return result.gated ? 1 : 0;
  }
  if (command === 'draft' && positional.length === 1) {
    const draft = draftChecks(await readJson(positional[0]), await readJson(flags.binding));
    await writeNew(flags.out, draft);
    out(JSON.stringify({ draftId: draft.draftId, checks: draft.checks.length, notDrafted: draft.notDrafted.length, warnings: draft.warnings.length, confirmed: false }));
    return 0;
  }
  if (command === 'confirm' && positional.length === 1) {
    if (!flags.matrix || !flags.binding) throw new Error('confirm needs --matrix and --binding (the files the draft came from).');
    // confirmDraft validates the profile with the product's own validator before returning it.
    const { profile, record } = confirmDraft(await readJson(positional[0]), await readJson(flags.profile), { confirmedBy: flags['confirmed-by'], matrix: await readJson(flags.matrix), binding: await readJson(flags.binding) });
    if (!flags['out-profile'] || !flags['out-record']) throw new Error('--out-profile and --out-record are required.');
    await writeNew(flags['out-profile'], profile);
    await writeNew(flags['out-record'], record);
    out(JSON.stringify({ confirmedBy: record.confirmedBy, addedChecks: record.checks.length, requiredControlsAdded: record.requiredControlsAdded.length }));
    return 0;
  }
  if (command === 'explain' && positional.length === 1) {
    if (!flags.profile) throw new Error('explain needs --profile (the profile the run used).');
    const result = explainRun(await readJson(positional[0]), await readJson(flags.record), { profile: await readJson(flags.profile) });
    out(JSON.stringify(result, null, 2));
    return result.mismatches.length ? 1 : result.verified ? 0 : 3;
  }
  if (command === 'statement') {
    const [sub, first, ...more] = positional;
    if (!first) throw new Error(`${USAGE}\n${LABEL_NOTE}`);
    const matrices = await Promise.all(more.map(readJson));
    if (sub === 'propose') {
      const proposal = proposeStatement({ application: flags.app, matrices: [await readJson(first), ...matrices] });
      await writeNew(flags.out, proposal);
      out(JSON.stringify({ rules: 0, candidates: proposal.candidates.length, notProposed: proposal.notProposed.length, warnings: proposal.warnings }));
      return 0;
    }
    if (sub === 'seal') {
      // --stated-by is a label the caller supplies (it authenticates no one); adoptions are checked against the matrices given.
      const sealed = sealStatement(await readJson(first), { statedBy: flags['stated-by'], matrices });
      await writeNew(flags.out, sealed);
      out(JSON.stringify({ statementId: sealed.statementId, statedBy: sealed.statedBy, rules: sealed.rules.length,
        adopted: sealed.rules.filter(r => r.confidence === 'adopted-declaration').length, candidates: sealed.candidates.length, defaultUnlisted: sealed.defaults.unlisted ?? null }));
      return 0;
    }
    if (sub === 'check') {
      const result = checkStatement(await readJson(first), { matrices });
      if (flags.out) await writeNew(flags.out, result);
      out(JSON.stringify({ statementId: result.statementId, verified: result.verified, counts: result.counts, disagreements: result.disagreements.length, warnings: result.warnings }));
      return result.disagreements.length ? 1 : result.counts.unresolved ? 3 : 0;
    }
  }
  if (command === 'write-plan' && positional.length >= 1) {
    if (!flags.binding) throw new Error('write-plan needs --binding (a scopehaven-policy-write-binding/1 file).');
    const [statementPath, ...matrixPaths] = positional;
    const plan = buildWritePlan({ statement: await readJson(statementPath), binding: await readJson(flags.binding), matrices: await Promise.all(matrixPaths.map(readJson)) });
    await writeNew(flags.out, plan);
    out(JSON.stringify({ planId: plan.planId, cases: plan.cases.length, variants: plan.variants.length, unexecuted: plan.variants.filter(v => v.reason).length, warnings: plan.warnings.length, confirmed: false }));
    return 0;
  }
  if (command === 'write-confirm' && positional.length >= 1) {
    if (!flags.statement || !flags.binding) throw new Error('write-confirm needs --statement and --binding (the files the plan came from).');
    const [planPath, ...matrixPaths] = positional;
    const record = confirmWritePlan(await readJson(planPath), { statement: await readJson(flags.statement), binding: await readJson(flags.binding),
      matrices: await Promise.all(matrixPaths.map(readJson)), confirmedBy: flags['confirmed-by'] });
    await writeNew(flags.out, record);
    out(JSON.stringify({ planId: record.planId, confirmedBy: record.confirmedBy, cases: record.cases.length, recordDigest: record.recordDigest }));
    return 0;
  }
  if (command === 'write-draft' && positional.length === 1) {
    if (!flags.binding) throw new Error('write-draft needs --binding (a scopehaven-write-draft-binding/1 file).');
    const draft = draftWriteChecks(await readJson(positional[0]), await readJson(flags.binding), { document: flags.document ? await readRegular(flags.document) : undefined });
    await writeNew(flags.out, draft);
    out(JSON.stringify({ draftId: draft.draftId, checks: draft.checks.length, counts: draft.counts, notDrafted: draft.notDrafted.length, warnings: draft.warnings.length, confirmed: false }));
    return 0;
  }
  if (command === 'write-draft-confirm' && positional.length === 1) {
    if (!flags.matrix || !flags.binding || !flags.profile) throw new Error('write-draft-confirm needs --matrix, --binding and --profile.');
    if (!flags['out-profile'] || !flags['out-record']) throw new Error('--out-profile and --out-record are required.');
    const reset = flags.reset ? { declaration: flags.reset, sha256: createHash('sha256').update(await readRegular(flags.reset)).digest('hex') } : null;
    const { profile, record } = confirmWriteDraft(await readJson(positional[0]), await readJson(flags.profile), { confirmedBy: flags['confirmed-by'], matrix: await readJson(flags.matrix), binding: await readJson(flags.binding),
      document: flags.document ? await readRegular(flags.document) : undefined, checkIds: flags['check-ids'] ? list(flags['check-ids']) : undefined, reset });
    await writeNew(flags['out-profile'], profile);
    await writeNew(flags['out-record'], record);
    out(JSON.stringify({ confirmedBy: record.confirmedBy, addedChecks: record.checks.length, notConfirmed: record.notConfirmed.length, requiredControlsAdded: record.requiredControlsAdded.length, warnings: record.warnings }));
    return 0;
  }
  if (command === 'reset' && positional.length === 1) {
    const decl = await readJson(positional[0]);
    if (decl?.seed?.expected === null && !flags.record) throw new Error('this declaration has no recorded seed yet: pass --record NEW_FILE to write the declaration with the seed hash it records.');
    let receipt;
    try { receipt = await ensureSeed(decl, { skipReset: flags['skip-reset'] === true }); }
    catch (error) { if (/seed state differs/.test(error.message)) { err(error.message); out(JSON.stringify({ matches: false })); return 1; } throw error; }
    if (receipt.recorded) await writeNew(flags.record, receipt.declaration);
    out(JSON.stringify({ targetId: receipt.targetId, reset: receipt.reset.skipped ? 'skipped' : `ok in ${receipt.reset.durationMs} ms`, hash: receipt.seed.hash, recorded: receipt.recorded, matches: receipt.seed.matches ?? true, sources: receipt.seed.parts.length }));
    return 0;
  }
  if (command === 'seed-hash' && positional.length === 1) {
    const { hash, parts } = await seedHash(await readJson(positional[0]));
    out(JSON.stringify({ hash, parts }));
    return 0;
  }
  throw new Error(`${USAGE}\n${LABEL_NOTE}`);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  main(process.argv.slice(2)).then(code => { process.exitCode = code; }, error => { console.error(error.message); process.exitCode = 2; });
}
