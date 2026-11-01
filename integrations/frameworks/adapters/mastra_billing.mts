// ScopeHaven adapter: Mastra billing agent example (mastra-ai/mastra,
// examples/agent/src/mastra, pinned in the scenario), protocol
// scopehaven-turn-runner/1, run with tsx under ScopeHaven's pinned Node.
//
// The template's agent, tool and workflow files are imported unmodified from the
// operator's checkout. Declared deviations, all at runtime, none in the template's
// files:
//   published-core  the published @mastra/core (installed beside the checkout) in
//                   place of the monorepo's workspace package
//   model-stub      both agents' models replaced with ScopeHaven's scripted stub
//                   (an AI SDK v2 language model; no model call, no network)
//   tool-boundary   each template tool's execute is wrapped (tool-ledger.mjs):
//                   presence-only ledger record per call, and the planned fault
//                   (a timeout, a reset after commit or a duplicate delivery)
//                   applied to the first call
// State is read on the harness's request, between turns, from the operator-named
// exports of the tools module (userBalances, refundLedger).
//
// usage: tsx mastra_billing.mts --template CHECKOUT
import { existsSync, readFileSync, writeSync } from 'node:fs';
import { createHash, randomUUID } from 'node:crypto';
import { createInterface } from 'node:readline';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { plainData } from './plain-data.mjs';
import { toolLedger } from './tool-ledger.mjs';

const PROTOCOL = 'scopehaven-turn-runner/1';
const FILES = { agent: 'examples/agent/src/mastra/agents/billing-agent.ts', tools: 'examples/agent/src/mastra/tools/billing-tools.ts', workflow: 'examples/agent/src/mastra/workflows/refund-workflow.ts' };
const WRAPPED = ['getUserBalance', 'refundUser', 'lookupBalance'];

const argv = process.argv.slice(2);
const template = argv[argv.indexOf('--template') + 1];
const send = (message: unknown) => writeSync(3, `${JSON.stringify(message)}\n`);
const sha256 = (text: string | Buffer) => createHash('sha256').update(text).digest('hex');

// The published package the template's own imports resolve to: walk up from the
// template files to the node_modules folder that holds it, and import its ESM entry,
// so this adapter shares the template's module instance.
function packageEntry(name: string, from: string) {
  for (let dir = from; dir !== dirname(dir); dir = dirname(dir)) {
    const pkg = join(dir, 'node_modules', name, 'package.json');
    if (!existsSync(pkg)) continue;
    const meta = JSON.parse(readFileSync(pkg, 'utf8'));
    const root = meta.exports?.['.'];
    const entry = typeof root === 'string' ? root : root?.import?.default ?? root?.import ?? root?.default;
    return { url: pathToFileURL(join(dirname(pkg), entry)).href, version: meta.version as string };
  }
  throw new Error(`${name} is not installed beside the template`);
}

class Script {
  steps: any[] = []; consumed = 0; calls = 0; exhausted = false; last: any = null;
  start(steps: any[]) { this.steps = steps; this.consumed = 0; this.exhausted = false; }
  next() {
    this.calls++;
    if (this.consumed >= this.steps.length) { this.exhausted = true; return null; }
    return this.steps[this.consumed++];
  }
  render(text: string) {
    return text.replace(/\{\{last\.([A-Za-z_]\w*)\}\}/g, (all, field) => (this.last && typeof this.last === 'object' && field in this.last ? String(this.last[field]) : all));
  }
}

// A scripted AI SDK v2 language model: each call answers with the next step.
function stubModel(id: string, script: Script) {
  const usage = { inputTokens: 0, outputTokens: 0, totalTokens: 0 };
  const content = () => {
    const step = script.next();
    if (step === null) return [{ type: 'text', text: '[scopehaven stub: script exhausted]' }];
    if (step.kind === 'tool') return [{ type: 'tool-call', toolCallId: `call_${script.calls}`, toolName: step.tool, input: JSON.stringify(step.args) }];
    return [{ type: 'text', text: script.render(step.text) }];
  };
  const finish = (c: any[]) => (c[0].type === 'tool-call' ? 'tool-calls' : 'stop');
  return {
    specificationVersion: 'v2', provider: 'scopehaven-stub', modelId: id, supportedUrls: {},
    async doGenerate() { const c = content(); return { content: c, finishReason: finish(c), usage, warnings: [] }; },
    async doStream() {
      const c = content();
      const parts: any[] = [{ type: 'stream-start', warnings: [] }, { type: 'response-metadata', id: randomUUID(), modelId: id, timestamp: new Date() }];
      for (const p of c as any[]) {
        if (p.type === 'text') parts.push({ type: 'text-start', id: 't0' }, { type: 'text-delta', id: 't0', delta: p.text }, { type: 'text-end', id: 't0' });
        else parts.push(p);
      }
      parts.push({ type: 'finish', finishReason: finish(c), usage });
      return { stream: new ReadableStream({ start(controller) { for (const p of parts) controller.enqueue(p); controller.close(); } }) };
    },
  };
}

let ledger: any = null;
const script = new Script(), subScript = new Script();
// The tool boundary: one ledger record per body run; the planned fault applied to the first call.
function wrap(tool: any, name: string) {
  const original = tool.execute.bind(tool);
  tool.execute = async (...args: any[]) => {
    const result = await ledger.call(name, args[0] ?? null, () => original(...args));
    script.last = result;
    return result;
  };
}

let agent: any = null, toolsModule: any = null;
const history: any[] = [];
async function load() {
  const at = (file: string) => join(template, file);
  const core = packageEntry('@mastra/core', dirname(at(FILES.agent)));
  const { Mastra } = await import(core.url);
  const agents = await import(pathToFileURL(at(FILES.agent)).href);
  toolsModule = await import(pathToFileURL(at(FILES.tools)).href);
  const { refundWorkflow } = await import(pathToFileURL(at(FILES.workflow)).href);
  for (const name of WRAPPED) wrap(toolsModule[name], name);
  agents.billingAgent.__updateModel({ model: stubModel('scopehaven-stub-billing', script) });
  agents.balanceAgent.__updateModel({ model: stubModel('scopehaven-stub-balance', subScript) });
  new Mastra({ agents: { billingAgent: agents.billingAgent, balanceAgent: agents.balanceAgent }, workflows: { refundWorkflow }, logger: false });
  agent = agents.billingAgent;
  return {
    files: Object.fromEntries(Object.entries(FILES).map(([k, f]) => [k, { path: f, sha256: sha256(readFileSync(at(f))) }])),
    versions: { '@mastra/core': core.version },
  };
}

// The exported value at an operator-named path, as plain data (plain-data.mjs refuses a Map, a Set,
// a class instance or anything else a JSON round trip would turn into "nothing there").
function read(path: string) {
  let value = toolsModule;
  for (const part of path.split('.')) value = value?.[part];
  if (value === undefined) throw new Error(`no export ${path}`);
  return plainData(value);
}

for await (const line of createInterface({ input: process.stdin })) {
  const message = JSON.parse(line);
  if (message.type === 'hello') {
    if (message.protocol !== PROTOCOL) { send({ type: 'error', message: 'protocol' }); break; }
    ledger = toolLedger(send, message.fault);
    try {
      const info = await load();
      send({ type: 'ready', framework: 'mastra', tools: ['getUserBalance', 'refundUser', 'agent-balanceAgent', 'workflow-refundWorkflow'], template: info,
        substitutions: [{ name: 'published-core' }, { name: 'model-stub' }, { name: 'tool-boundary', tools: WRAPPED }] });
    } catch (error: any) { send({ type: 'error', message: `load failed: ${error?.name}: ${error?.message}`.slice(0, 3000) }); }
  } else if (message.type === 'turn') {
    script.start(message.steps); subScript.start([]);
    const replies: string[] = [];
    let failure: string | null = null;
    try {
      history.push({ role: 'user', content: message.text });
      const result = await agent.generate([...history]);
      const text = String(result?.text ?? '').trim();
      if (text) replies.push(text);
      history.push({ role: 'assistant', content: text });
    } catch (error: any) {
      // The framework raised out of the turn: the user sees an error, and the run is unusable.
      replies.push(`[run failed visibly: ${error?.name ?? 'Error'}]`);
      failure = `${error?.name ?? 'Error'}: ${error?.message ?? error}`.replace(/\s+/g, ' ').slice(0, 400);
    }
    send({ type: 'turn-end', id: message.id, reply: replies.at(-1) ?? '', messages: replies, stub: { consumed: script.consumed, exhausted: script.exhausted || subScript.exhausted }, ...(failure ? { failure } : {}) });
  } else if (message.type === 'sync') {
    send({ type: 'sync', id: message.id });
  } else if (message.type === 'snapshot') {
    try {
      if (message.paths.some((p: any) => p.source !== 'object-path')) throw new Error('this template has no app-report hook');
      send({ type: 'state', id: message.id, values: Object.fromEntries(message.paths.map((p: any) => [p.path, read(p.path)])) });
    } catch (error: any) { send({ type: 'error', message: String(error?.message ?? error) }); }
  } else if (message.type === 'close') break;
}
process.exit(0);
