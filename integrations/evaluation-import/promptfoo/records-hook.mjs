// Promptfoo extension hooks (extensions: ['file://.../records-hook.mjs:beforeEach',
// 'file://.../records-hook.mjs:afterEach']):
//   beforeEach  before each test's provider call, mark the records verdict service's observers.
//               The window id rides on the test as the var scopehavenWindow, so the records
//               assertion can seal the same window after the response.
//   afterEach   close the test's window as not-sealed. A provider error skips the assertions, so
//               without this its window stays open and holds a slot. The close is judged exactly
//               like a seal: a commit the records show stands, and it reads clean when the records
//               show this test's call and no forbidden effect. A sealed window answers 404, which is
//               expected and ignored.
// SCOPEHAVEN_RECORDS_URL (exactly a http://127.0.0.1:<port> origin) and SCOPEHAVEN_RECORDS_TOKEN
// come from the runner's environment. Redirects are refused, so only that origin answers.
const origin = () => {
  const url = process.env.SCOPEHAVEN_RECORDS_URL ?? '';
  if (!/^http:\/\/127\.0\.0\.1:\d{1,5}$/.test(url)) throw new Error('SCOPEHAVEN_RECORDS_URL must be a 127.0.0.1 origin.');
  return url;
};
export async function post(path, body) {
  const res = await fetch(`${origin()}${path}`, { method: 'POST', redirect: 'error', headers: { 'content-type': 'application/json', authorization: `Bearer ${process.env.SCOPEHAVEN_RECORDS_TOKEN ?? ''}` }, body: JSON.stringify(body), signal: AbortSignal.timeout(60000) });
  const json = await res.json().catch(() => ({}));
  if (res.status !== 200) throw Object.assign(new Error(`records service ${path}: ${res.status} ${json.error ?? ''}`), { status: res.status });
  return json;
}
export async function beforeEach(context) {
  const { window } = await post('/mark', {});
  return { ...context, test: { ...context.test, vars: { ...(context.test?.vars ?? {}), scopehavenWindow: window } } };
}
export async function afterEach(context) {
  const vars = context?.test?.vars, window = vars?.scopehavenWindow;
  if (typeof window !== 'string') return;
  try { await post('/close', { window, reason: 'not-sealed', select: vars.scopehavenSelect ?? 'default' }); } catch (error) { if (error?.status !== 404) throw error; }
}
