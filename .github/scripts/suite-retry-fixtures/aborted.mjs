import test from 'node:test';
test('aborted', {signal: AbortSignal.abort()}, () => {});
