// The allowed-use guard (FIX-07, src/http-pairing.mjs allowedUseGuards) reads an unguarded absence's pass inconclusive
// (allowed-use-not-declared) where a frozen main connector read it pass. A differential test against main expects exactly those
// moves: main's rows with each such clause's pass, and the row pass it leaves, read inconclusive; every other verdict stays main's.
const GUARD = 'allowed-use-not-declared';
const movedOf = row => (row?.trace?.[1]?.data?.effects ?? []).map(e => e?.pairing === GUARD);
// mainRun's results as head's guard reads them (the effect clauses head marked, in row order).
export function guardAdjusted(headRun, mainRun) {
  return mainRun.results.map(row => {
    const moved = movedOf(headRun.results.find(r => r.id === row.id));
    if (!moved.some(Boolean)) return row;
    let k = -1, changed = false;
    const assertions = row.assertions.map(a => {
      if (!/^Observed effect \d+ /.test(a?.name ?? '')) return a;
      k++;
      if (!moved[k] || a.status !== 'pass') return a;
      changed = true;
      return { ...a, status: 'inconclusive' };
    });
    return { ...row, assertions, status: changed && row.status === 'pass' ? 'inconclusive' : row.status };
  });
}
// How many effect clauses the guard withheld in a run.
export const guardMoves = run => run.results.reduce((n, row) => n + movedOf(row).filter(Boolean).length, 0);
