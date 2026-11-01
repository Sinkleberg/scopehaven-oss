# MCP server as a target

Several identities call tools on an MCP server. Allowed and forbidden calls are judged from records, and a descriptor change in the middle of a session must not let an old grant authorize the new capability.

## Connector

`startMcpTarget` puts the existing MCP observer's loopback HTTP proxy (`integrations/observers/mcp.mjs`, unchanged) in front of the server's `/mcp` endpoint.

- **Identity.** Each identity has its own credential (`SCOPEHAVEN_TARGET_*`). The proxy maps the Authorization value of each request to the identity, by digest only.
- **Two records.**
  - **mcp-jsonrpc** (presence-only): every `tools/call` and its result, per identity. Error code −32001 counts as a denial. It can show a forbidden call ran, never that none did.
  - **The server's own audit table** (sqlite audit observer, authoritative): every call the server decided. A pass needs it.
- **Scenario.** A scenario is an ordinary `scopehaven-sequence/1` whose requests are JSON-RPC `tools/call` messages through the proxy, built with `toolCall`. Verdicts are core's effect rules over the two records.
- **Loopback only.** The proxy refuses any upstream that is not literal loopback HTTP.

## The standard scenario (`mcpGrantSequence`)

| Assertion | Window | Meaning |
|---|---|---|
| MCP-01 (forbidden) | before the change | the viewer cannot issue a refund |
| MCP-02 (forbidden) | after the change | after the export tool's descriptor changed (v2 exports every tenant), the viewer's old grant runs nothing |
| MCP-C1 to MCP-C4 (controls) | | the viewer reads a ticket; the agent refunds; the viewer exports its own tickets before the change; the agent, re-granted after the change, exports. Each is decided by the server's audit table: the traffic alone cannot show the server ran a call |

## Owned server (`server.mjs`)

A loopback MCP server: JSON-RPC `initialize`, `tools/list` and `tools/call`, synthetic data, no model. Admin routes upgrade the export tool and grant tools.

| Grant mode | Results |
|---|---|
| `bound` (a grant names the tool's descriptor hash) | the controls pass; MCP-01 and MCP-02 read inconclusive (subject-writable-custody), because only the server's own audit table can decide them |
| `by-name` | MCP-02 fails; the server's audit table shows the viewer's v2 export of `tickets/*`, and the traffic shows the call answered |
| `open` | MCP-01 and MCP-02 fail |

**Presence-only.** With only the MCP traffic observer, a forbidden check can fail but never pass (tested).

**Variants.** `upgrade: { only: 'description' }` or `{ only: 'inputSchema' }` changes one part of the export descriptor. Each variant has its own sequence id (`mcp-grants-and-descriptor-change-description-only`, `-inputSchema-only`); the full upgrade keeps `mcp-grants-and-descriptor-change`.

## Limits

- The stdio transport of the MCP observer works the same way: one recorder per server process. These tests use the HTTP proxy.
- The audit table is the server's own record, and its custody is subject-writable.
- The connector is built for the owned server: its JSON-RPC schema, tool names and refusal code (−32001) are fixed. A forbidden call must be answered with HTTP 200, and no post-response settle is declared.

Tests: `node --test integrations/mcp-target/mcp-target.test.mjs`.

Guide: [docs/guides/mcp-target-from-claude-code-and-cursor.md](../../docs/guides/mcp-target-from-claude-code-and-cursor.md) starts this server behind the recording proxy with `docs/guides/examples/mcp-target-launch.mjs`, points an agent in Claude Code or Cursor at it, and judges the agent's calls from the two records over a sequence window.
