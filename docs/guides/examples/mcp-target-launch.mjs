// Starts the owned synthetic MCP server (integrations/mcp-target/server.mjs) on loopback behind ScopeHaven's recording MCP
// proxy (integrations/observers/mcp.mjs), and writes into one private folder the files a `./scopehaven sequence` run needs
// to judge what an agent called: the proxy's frame log, the server's audit database, an observers.json naming both records,
// and a sealed 24-hour authorization record for this synthetic target and the example sequence
// (docs/guides/examples/mcp-agent-window.sequence.json). See docs/guides/mcp-target-from-claude-code-and-cursor.md.
//
//   node docs/guides/examples/mcp-target-launch.mjs --dir /absolute/private/folder [--port 4810] [--mode bound|by-name|open]
//
// The three identities' bearer tokens come from SCOPEHAVEN_TARGET_MCP_VIEWER, SCOPEHAVEN_TARGET_MCP_AGENT and
// SCOPEHAVEN_TARGET_MCP_ADMIN: synthetic values you choose. They are read once by the server and the proxy and never
// written anywhere; the proxy keeps only a digest to name each call's identity. The server and the proxy listen on
// 127.0.0.1 only, and nothing here opens a connection of its own. Stop it with Ctrl-C.
import { mkdirSync, writeFileSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { startMcpServer, TOOL_NAMES, DENIED_CODE } from '../../../integrations/mcp-target/server.mjs';
import { createMcpHttpProxy, FrameLog } from '../../../integrations/observers/mcp.mjs';
import { checksumAuthorization, AUTHORIZATION_SCHEMA } from '../../../src/authorization.mjs';

// The example sequence's identity: the authorization record must name the same sequence id and applicationId.
export const SEQUENCE_ID = 'mcp-agent-window';
export const APPLICATION_ID = 'owned-mcp-target';
export const ACTORS = Object.freeze({
  viewer: { principalId: 'mcp-viewer', credentialEnv: 'SCOPEHAVEN_TARGET_MCP_VIEWER' },
  agent: { principalId: 'mcp-agent', credentialEnv: 'SCOPEHAVEN_TARGET_MCP_AGENT' },
  admin: { principalId: 'mcp-admin', credentialEnv: 'SCOPEHAVEN_TARGET_MCP_ADMIN' },
});
// What each identity is granted at start: the viewer may read and export, the agent may also refund.
const GRANTS = { 'mcp-viewer': ['read_ticket', 'export'], 'mcp-agent': ['read_ticket', 'refund', 'export'] };

function option(argv, name, fallback) {
  const at = argv.indexOf(name);
  return at >= 0 && typeof argv[at + 1] === 'string' && !argv[at + 1].startsWith('--') ? argv[at + 1] : fallback;
}
const iso = ms => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');

// The observer configuration for a sequence run: the proxy's frame log (presence-only: it can show a forbidden call ran,
// never that none did) and the server's own audit table (authoritative, but written by the server itself, so a pass it
// alone decides reads inconclusive under custody).
export function observersConfig({ frameLog, dbPath }) {
  return [
    { id: 'traffic', type: 'mcp-log', path: frameLog, deniedRpcCodes: [DENIED_CODE], tools: [...TOOL_NAMES] },
    { id: 'server-audit', type: 'sqlite-audit', path: dbPath, principals: Object.values(ACTORS).map(a => a.principalId),
      audit: { table: 'audit', idColumn: 'id', actorColumn: 'actor', actionColumn: 'action', resourceColumn: 'resource',
        actions: { ...Object.fromEntries(TOOL_NAMES.map(t => [t, 'tool-call'])), 'server.upgrade': 'access-change', grant: 'access-change' },
        deniedActions: TOOL_NAMES.map(t => `${t}.denied`) } },
  ];
}

// A sealed record for the synthetic target: the example sequence, the proxy's origin, the three identities, 24 hours.
export function authorizationRecord({ origin, now = Date.now(), hours = 24 }) {
  return checksumAuthorization({ schema: AUTHORIZATION_SCHEMA, id: 'owned-mcp-target', target: { id: SEQUENCE_ID, applicationId: APPLICATION_ID },
    origins: [origin], identities: Object.values(ACTORS).map(a => a.principalId), validFrom: iso(now - 60000), validUntil: iso(now + hours * 3600000),
    signer: { name: 'ScopeHaven owned MCP target', role: 'Owner of the synthetic target' }, signedAt: iso(now - 60000) });
}

export async function launch({ dir, port = 4810, mode = 'bound', env = process.env, log = line => process.stdout.write(`${line}\n`) }) {
  if (typeof dir !== 'string' || !dir) throw new Error('--dir needs an absolute path to a private folder (created with mode 0700 if missing).');
  const folder = resolve(dir);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('--port is an integer from 1024 to 65535.');
  if (!['bound', 'by-name', 'open'].includes(mode)) throw new Error('--mode is bound, by-name or open.');
  for (const actor of Object.values(ACTORS)) if (!env[actor.credentialEnv]) throw new Error(`${actor.credentialEnv} is not set: choose a synthetic token for ${actor.principalId}.`);
  mkdirSync(folder, { recursive: true, mode: 0o700 });
  const dbPath = join(folder, 'server.db'), frameLog = join(folder, 'mcp-frames.jsonl');
  if (existsSync(dbPath) || existsSync(frameLog)) throw new Error(`${folder} already holds server.db or mcp-frames.jsonl from an earlier launch; use an empty folder, so each run starts from its own records.`);
  const tokens = { [ACTORS.viewer.principalId]: env[ACTORS.viewer.credentialEnv], [ACTORS.agent.principalId]: env[ACTORS.agent.credentialEnv] };
  const server = await startMcpServer({ dbPath, tokens, admin: { principal: ACTORS.admin.principalId, token: env[ACTORS.admin.credentialEnv] }, grants: GRANTS, mode });
  const proxy = createMcpHttpProxy({ upstream: `${server.origin}/mcp`, port, actors: Object.values(ACTORS).map(a => ({ actorId: a.principalId, credentialEnv: a.credentialEnv })), env, log: new FrameLog({ path: frameLog }) });
  try { await proxy.start(); } catch (error) { await server.stop(); throw new Error(`the proxy could not listen on 127.0.0.1:${port} (${error.code ?? error.message}); choose another --port.`); }
  const origin = new URL(proxy.url).origin;
  writeFileSync(join(folder, 'observers.json'), `${JSON.stringify(observersConfig({ frameLog, dbPath }), null, 2)}\n`, { mode: 0o600 });
  writeFileSync(join(folder, 'authorization.json'), `${JSON.stringify(authorizationRecord({ origin }), null, 2)}\n`, { mode: 0o600 });
  log(`Owned MCP server (grants: ${mode}) behind the recording proxy at ${proxy.url}`);
  log(`  identities: ${Object.values(ACTORS).map(a => `${a.principalId} (Bearer from ${a.credentialEnv})`).join(', ')}`);
  log(`  records:    ${frameLog} (MCP traffic), ${dbPath} (the server's audit table)`);
  log(`  written:    ${join(folder, 'observers.json')}, ${join(folder, 'authorization.json')} (valid 24 hours)`);
  log('Open the window from the scopehaven folder, then let the agent work while it is open:');
  log(`  ./scopehaven sequence --sequence docs/guides/examples/mcp-agent-window.sequence.json --origin ${origin} --observers ${join(folder, 'observers.json')} --authorization ${join(folder, 'authorization.json')} --out ${join(folder, 'runs')}`);
  const stop = async () => { await proxy.stop(); await server.stop(); };
  return { origin, url: proxy.url, serverOrigin: server.origin, folder, stop };
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const argv = process.argv.slice(2);
  let running;
  try { running = await launch({ dir: option(argv, '--dir'), port: Number(option(argv, '--port', '4810')), mode: option(argv, '--mode', 'bound') }); }
  catch (error) { process.stderr.write(`mcp-target-launch: ${error.message}\n`); process.exit(2); }
  const shutdown = () => running.stop().then(() => process.exit(0), () => process.exit(1));
  process.on('SIGINT', shutdown); process.on('SIGTERM', shutdown);
  setInterval(() => {}, 1 << 30);
}
