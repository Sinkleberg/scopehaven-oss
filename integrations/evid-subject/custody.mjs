// EVID-SUBJECT (scopehaven-custody/1). The pure custody core moved to
// src/custody.mjs (SURPASS-CUSTODY-01), where it now decides HTTP effect
// verdicts and sequence assertions. This module re-exports it so existing
// importers (the forging subject, its cases and tests, the ledger) keep working.
export * from '../../src/custody.mjs';
