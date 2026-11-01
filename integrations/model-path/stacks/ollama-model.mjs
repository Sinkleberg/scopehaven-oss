// The derived model the live runs use: the installed qwen3.5:9b-q4_K_M weights with
// num_ctx 8192 set in the model, because an app's OpenAI-compatible call cannot pass
// num_ctx and this machine's Ollama default (262144) loads the 9B at about 15 GB.
// It adds a manifest that points at the same weights (no download) and changes no
// default; remove it when the runs are done.
//   node ollama-model.mjs create|remove|show
const OLLAMA = 'http://127.0.0.1:11434', NAME = 'sh-sup2-qwen9b-8k', FROM = 'qwen3.5:9b-q4_K_M';
const call = async (method, path, body) => { const r = await fetch(`${OLLAMA}${path}`, { method, redirect: 'error', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }); return { status: r.status, text: (await r.text()).slice(-400) }; };
const action = process.argv[2];
if (action === 'create') {
  // Never a download: the base weights must already be installed.
  const tags = await (await fetch(`${OLLAMA}/api/tags`, { redirect: 'error' })).json();
  if (!tags.models?.some(m => m.name === FROM)) { console.error(`${FROM} is not installed; not creating (this script never pulls).`); process.exit(3); }
  console.log(await call('POST', '/api/create', { model: NAME, from: FROM, parameters: { num_ctx: 8192 }, stream: false }));
}
else if (action === 'remove') console.log(await call('DELETE', '/api/delete', { model: NAME }));
else if (action === 'show') { const r = await fetch(`${OLLAMA}/api/show`, { method: 'POST', redirect: 'error', body: JSON.stringify({ model: NAME }) }); const d = await r.json(); console.log({ status: r.status, parameters: d.parameters, details: d.details }); }
else { console.error('usage: ollama-model.mjs create|remove|show'); process.exit(2); }
