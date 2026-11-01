// World launcher protocol: how the sweep CLI starts one fresh copy of the application per run from a command.
// The command runs with only PATH (and TMPDIR) in its environment and talks JSON lines over its stdio:
//   1. it starts the application's upstream (model, tools, delivery) and prints {"upstream": "http://127.0.0.1:PORT"};
//   2. the sweep starts a hold gate in front of it and writes {"gate": "http://127.0.0.1:PORT"} to its stdin;
//   3. it starts the application with that URL as its upstream base URL and prints
//      {"origin": "http://127.0.0.1:PORT", "credentials": {"SCOPEHAVEN_TARGET_...": "..."}};
//   4. when stdin closes or it receives SIGTERM, it stops everything it started.
// The command runs in its own process group: stopping it signals the whole group, so an application it started in the
// background stops too, and the stop waits for the command's exit, not for every holder of its output.
// Lines that are not JSON objects are ignored. Every URL must be literal loopback HTTP; credential names must be in
// the SCOPEHAVEN_TARGET_ namespace. The launcher's output is never written to a report.
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { CREDENTIAL_ENV } from '../../observers/events.mjs';

const LOOPBACK = /^http:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})$/;
const loopback = url => typeof url === 'string' && LOOPBACK.test(url) && Number(LOOPBACK.exec(url)[1]) <= 65535;
export const LAUNCHER_DEFAULTS = Object.freeze({ startTimeoutMs: 20000, stopTimeoutMs: 5000 });

export function commandWorld({ command, startTimeoutMs = LAUNCHER_DEFAULTS.startTimeoutMs }, { env = { PATH: '/usr/bin:/bin', ...(process.env.TMPDIR ? { TMPDIR: process.env.TMPDIR } : {}) } } = {}) {
  return async function startWorld(gateFor) {
    const child = spawn(command[0], command.slice(1), { env, stdio: ['pipe', 'pipe', 'ignore'], detached: true });
    // A launcher that cannot start, or exits early, ends its stdout: the reads below then fail instead of waiting.
    const exited = new Promise(resolve => { child.once('exit', resolve); child.once('error', () => resolve(null)); });
    child.stdin.on('error', () => {});
    const group = signal => { try { process.kill(-child.pid, signal); } catch {} };
    const stop = async () => {
      child.stdin.end();
      group('SIGTERM');
      const timer = setTimeout(() => group('SIGKILL'), LAUNCHER_DEFAULTS.stopTimeoutMs);
      await exited; clearTimeout(timer);
      // Whatever of the group outlived the command is not part of a world any more.
      group('SIGKILL');
    };
    const lines = createInterface({ input: child.stdout });
    const messages = (async function* () { for await (const line of lines) { let m = null; try { m = JSON.parse(line); } catch {} if (m && typeof m === 'object' && !Array.isArray(m)) yield m; } })();
    const next = async key => { for (;;) { const { value, done } = await messages.next(); if (done) throw new Error('The world launcher exited before it was ready.'); if (Object.hasOwn(value, key)) return value; } };
    let timer;
    const timeout = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`The world launcher was not ready within ${startTimeoutMs} ms.`)), startTimeoutMs); });
    try {
      const ready = await Promise.race([timeout, (async () => {
        const { upstream } = await next('upstream');
        if (!loopback(upstream)) throw new Error('The world launcher\'s upstream must be literal loopback HTTP.');
        child.stdin.write(`${JSON.stringify({ gate: await gateFor(upstream) })}\n`);
        return next('origin');
      })()]);
      if (!loopback(ready.origin)) throw new Error('The world launcher\'s origin must be literal loopback HTTP.');
      const credentials = ready.credentials ?? {};
      if (credentials === null || typeof credentials !== 'object' || Array.isArray(credentials) || !Object.entries(credentials).every(([name, value]) => CREDENTIAL_ENV.test(name) && typeof value === 'string' && value.length <= 4096))
        throw new Error('The world launcher\'s credentials must map SCOPEHAVEN_TARGET_ names to strings.');
      // Keep reading its output so a chatty launcher never blocks on a full pipe.
      (async () => { try { for await (const _ of messages) {} } catch {} })();
      return { origin: ready.origin, credentials: { ...credentials }, stop };
    } catch (error) { await stop(); throw error; }
    finally { clearTimeout(timer); }
  };
}
