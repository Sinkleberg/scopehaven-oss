#!/usr/bin/env node
import { parseArgs, runGate } from './gate.mjs';

let summary;
try { summary = await runGate(parseArgs(process.argv.slice(2)), { env: process.env }); }
catch {
  summary = { schemaVersion: 1, outcome: 'config-or-runtime-error', exitCode: 2, reasons: ['invalid-options'], current: null, comparison: null };
}
process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
// Report-only: the process exit is the window's (0 for an assessment-failed verdict while it applies); the summary keeps the verdict's.
process.exitCode = summary.reportOnly?.exitCode ?? summary.exitCode;
