// Promptfoo javascript assertion (assert: [{ type: javascript, value: file://.../records-assertion.mjs,
// metric: scopehaven-records, weight: 0 }]): after the response, seal the test's window and
// return the records verdict next to Promptfoo's own grade, never merged into it. It always
// passes and carries no weight, so the grade is exactly what the other assertions decide; the
// records verdict travels in the reason: "scopehaven-records: <clean|commit|unsupported> ...".
// The var scopehavenSelect names one of the service's declared forbidden selectors (default).
// A response flagged cached (context.providerResponse.cached, any value but false or absent; the
// provider or the application can set it) is still sealed and judged; the flag is recorded and
// decides nothing. The records decide: a window without a record of the call never reads clean,
// and a commit stands.
import { post } from './records-hook.mjs';

export const cachedFlag = response => response?.cached !== undefined && response?.cached !== false;

export default async function recordsAssertion(output, context) {
  const window = context?.vars?.scopehavenWindow;
  if (typeof window !== 'string') return { pass: true, score: 0, reason: 'scopehaven-records: unsupported (no window was marked before the provider call)' };
  try {
    const r = await post('/seal', { window, select: context.vars.scopehavenSelect ?? 'default', cached: cachedFlag(context.providerResponse) });
    return { pass: true, score: r.records === 'clean' ? 1 : 0, reason: `scopehaven-records: ${r.records} (${r.verdict}; custody ${r.custody}; ${r.selector}): ${r.basis}` };
  } catch (error) {
    return { pass: true, score: 0, reason: `scopehaven-records: unsupported (${String(error?.message ?? error).slice(0, 120)})` };
  }
}
