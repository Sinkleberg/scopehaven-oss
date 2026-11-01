#!/usr/bin/env node
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runGate } from './gate.mjs';
import { createStore } from '../../src/store.mjs';

// An isolated one-shot demonstration. The owned runner closes every fixture.
// Only non-content summaries and core integrity hashes are printed; temp data
// is removed even on failure. No credentials or provider calls are used.
const outputDirectory = await mkdtemp(join(tmpdir(), 'scopehaven-gate-demo-'));
try {
  const baseline = await runGate({ targetId: 'demo-vulnerable', outputDirectory });
  assert.equal(baseline.exitCode, 1);
  const repaired = await runGate({ targetId: 'demo-repaired', outputDirectory, baselineRunId: baseline.current.runId });
  assert.equal(repaired.exitCode, 0);
  assert.equal(repaired.comparison.compatibility, 'compatible');
  assert.equal(repaired.comparison.labels.fixed, baseline.current.counts.fail);
  assert.equal(repaired.comparison.labels['contract-restored'], 0);
  const store = createStore(outputDirectory);
  const savedBaseline = await store.get(baseline.current.runId), savedRepaired = await store.get(repaired.current.runId);
  process.stdout.write(`${JSON.stringify({ schemaVersion: 1, demonstration: 'owned-isolated-loopback', baseline, repaired,
    coreSha256: { baseline: savedBaseline.integrity.sha256, repaired: savedRepaired.integrity.sha256 },
    retention: 'Temporary core evidence and gate summaries removed on exit; this receipt retains summaries and their source core hashes only.' }, null, 2)}\n`);
} finally { await rm(outputDirectory, { recursive: true, force: true }); }
