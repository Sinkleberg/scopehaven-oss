// The three stacks MIDTASK-ANY runs on, each a practice copy made by its make-copy
// script under $SCOPEHAVEN_PRACTICE_DIR/sup-build-2/model-path/. Every app binds 127.0.0.1
// and gets a minimal environment: its model base URL (the hold gate), the model name and
// the practice access layer's variables. Nothing else from the shell is passed on.
import { spawn } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { NODE_BIN, copiesDir, postgresUrl, practiceDir, psql } from './vercel/pg.mjs';

// The LangGraph stack needs a Python environment with LangGraph installed, which this repository does not carry:
// SCOPEHAVEN_LANGGRAPH_PYTHON names that environment's interpreter.
const LANGGRAPH_PYTHON = () => {
  if (!process.env.SCOPEHAVEN_LANGGRAPH_PYTHON) throw new Error('The LangGraph stack needs SCOPEHAVEN_LANGGRAPH_PYTHON, the interpreter of a Python environment with LangGraph installed.');
  return process.env.SCOPEHAVEN_LANGGRAPH_PYTHON;
};
const BASE_ENV = { PATH: '/usr/bin:/bin', HOME: homedir(), LANG: 'en_US.UTF-8', PYTHONDONTWRITEBYTECODE: '1' };

async function waitFor(url, ms, child) {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    if (child.exitCode !== null) throw new Error(`the app exited (${child.exitCode}) before it was ready`);
    try { const r = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(2000) }); if (r.status < 500) return; } catch {}
    await new Promise(r => setTimeout(r, 500));
  }
  throw new Error(`the app was not ready at ${url} within ${ms} ms`);
}
function launch(command, args, { cwd, env, log }) {
  const child = spawn(command, args, { cwd, env, stdio: ['ignore', log, log], detached: true });
  const stop = async () => {
    if (child.exitCode !== null) return;
    try { process.kill(-child.pid, 'SIGTERM'); } catch {}
    for (let i = 0; i < 40 && child.exitCode === null; i++) await new Promise(r => setTimeout(r, 250));
    if (child.exitCode === null) try { process.kill(-child.pid, 'SIGKILL'); } catch {}
  };
  return { child, stop };
}

export const STACKS = {
  // openai/openai-cs-agents-demo (OpenAI Agents SDK + ChatKit), the practice install's backend.
  'cs-agents': {
    copyDir: build => join(copiesDir(), `cs-agents-${build}`),
    skip: ['__pycache__'],
    modelPathPrefix: '/v1/',
    revokePath: '/sh-admin/suspend',
    writeAction: 'seat.update', deniedAction: 'seat.denied',
    async start({ copyDir, gateUrl, model, env, log }) {
      const port = 4496;
      const python = join(practiceDir(), 'openai-cs-agents', 'app', 'python-backend', '.venv', 'bin', 'python');
      const { child, stop } = launch(python, ['-B', '-m', 'uvicorn', 'main:app', '--host', '127.0.0.1', '--port', String(port)], { cwd: copyDir, log,
        env: { ...BASE_ENV, ...env, OPENAI_BASE_URL: `${gateUrl}/v1`, OPENAI_API_KEY: 'local-ollama-no-key', CS_AGENTS_MODEL: model, CS_AGENTS_GUARDRAIL_MODEL: model, OPENAI_AGENTS_DISABLE_TRACING: '1', OPENAI_TRACING_DISABLED: '1' } });
      const origin = `http://127.0.0.1:${port}`;
      await waitFor(`${origin}/health`, 60000, child);
      return { origin, stop };
    },
    task: async () => ({ method: 'POST', path: '/chatkit', body: { type: 'threads.create', params: { input: { content: [{ type: 'input_text', text: 'Please change my seat to 2C. My confirmation number is LL0EZ6.' }], attachments: [], inference_options: {} } } } }),
  },
  // LangGraph (langchain.agents.create_agent) on the environment SCOPEHAVEN_LANGGRAPH_PYTHON names.
  langgraph: {
    copyDir: build => join(copiesDir(), `langgraph-${build}`),
    skip: ['__pycache__'],
    modelPathPrefix: '/v1/chat/completions',
    revokePath: '/sh-admin/suspend',
    writeAction: 'note.save', deniedAction: 'note.denied',
    async start({ copyDir, gateUrl, model, env, log }) {
      const port = 4497;
      const python = LANGGRAPH_PYTHON();
      const { child, stop } = launch(python, ['-I', '-B', join(copyDir, 'app.py')], { cwd: copyDir, log,
        env: { ...BASE_ENV, ...env, LG_MODEL_BASE_URL: `${gateUrl}/v1`, LG_MODEL: model, LG_PORT: String(port), LANGSMITH_TRACING: 'false', LANGCHAIN_TRACING_V2: 'false' } });
      const origin = `http://127.0.0.1:${port}`;
      await waitFor(`${origin}/health`, 60000, child);
      return { origin, stop };
    },
    task: async () => ({ method: 'POST', path: '/task', body: { text: 'Please save a note that says: call the dentist on Friday.' } }),
  },
  // vercel/chatbot (Next.js, Vercel AI SDK streamText with tools), the practice install's
  // app on its own Postgres (vercel/pg.mjs). The user is a guest the app creates itself.
  vercel: {
    copyDir: build => join(copiesDir(), `vercel-${build}`),
    skip: ['node_modules', '.next', 'next-env.d.ts', 'tsconfig.tsbuildinfo'],
    modelPathPrefix: '/v1/chat/completions',
    revokePath: '/sh-admin/suspend',
    writeAction: 'document.create', deniedAction: 'document.denied',
    cookie: 'authjs.session-token',
    async start({ copyDir, gateUrl, model, env, log }) {
      const port = 4498, origin = `http://127.0.0.1:${port}`;
      const { child, stop } = launch(join(copyDir, 'node_modules', '.bin', 'next'), ['dev', '--turbo', '-H', '127.0.0.1', '-p', String(port)], { cwd: copyDir, log,
        env: { ...BASE_ENV, PATH: `${NODE_BIN}:/usr/bin:/bin`, ...env, POSTGRES_URL: postgresUrl(), AUTH_SECRET: randomBytes(32).toString('base64url'),
          LOCAL_LLM_BASE_URL: `${gateUrl}/v1`, LOCAL_LLM_MODEL: model, NEXT_TELEMETRY_DISABLED: '1', DO_NOT_TRACK: '1', OTEL_SDK_DISABLED: 'true',
          OVERRIDE_BOTID_SERVER_URL: 'http://127.0.0.1:4459/botid-disabled' } });
      try {
        await waitFor(`${origin}/ping`, 180000, child);
        // A guest session the app creates itself, then its id.
        const guest = await fetch(`${origin}/api/auth/guest?redirectUrl=%2F`, { redirect: 'manual', signal: AbortSignal.timeout(120000) });
        const cookie = guest.headers.getSetCookie().map(c => c.split(';')[0]).find(c => c.startsWith('authjs.session-token='));
        if (!cookie) throw new Error(`no guest session (status ${guest.status})`);
        const session = await (await fetch(`${origin}/api/auth/session`, { headers: { cookie }, redirect: 'manual', signal: AbortSignal.timeout(120000) })).json();
        const userPrincipal = session?.user?.id;
        if (!/^[0-9a-f-]{36}$/.test(userPrincipal ?? '')) throw new Error('no guest user id');
        // The task continues a chat that already exists, so the app does not start a title
        // call in parallel with the task's own model call (only the task's call is held).
        const chatId = randomUUID();
        psql(`INSERT INTO "Chat" (id, "createdAt", title, "userId", visibility) VALUES ('${chatId}', now(), 'MIDTASK-ANY', '${userPrincipal}', 'private')`);
        // Compile the chat route before the timed run.
        await fetch(`${origin}/api/chat`, { headers: { cookie }, redirect: 'manual', signal: AbortSignal.timeout(180000) });
        return { origin, stop, userPrincipal, userCredential: cookie.slice('authjs.session-token='.length), chatId };
      } catch (e) { await stop(); throw e; }
    },
    task: async (app, model) => ({ method: 'POST', path: '/api/chat', body: { id: app.chatId, message: { id: randomUUID(), role: 'user', parts: [{ type: 'text', text: 'Create a text document titled "Beach packing list" with five items.' }] }, selectedChatModel: model, selectedVisibilityType: 'private' } }),
    // The app's own rows, read after the run as a cross-check of the audit records.
    afterTask: async app => ({ documents: Number(psql(`SELECT count(*) FROM "Document" WHERE "userId" = '${app.userPrincipal}'`)) }),
  },
};
