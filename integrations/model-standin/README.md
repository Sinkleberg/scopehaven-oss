# Model stand-in: a scripted OpenAI-shaped model on loopback

A first run of an application against ScopeHaven should need no provider key and no spend. The stand-in serves the two
request shapes most agent apps speak, answering from a plan a person writes:

| Route | Shape |
|---|---|
| `GET /v1/models` | the plan's model id |
| `POST /v1/chat/completions` | Chat Completions, JSON, or server-sent events when the request sets `stream: true`; tool calls as `tool_calls` with `finish_reason: "tool_calls"` |
| `POST /v1/responses` | the Responses API, JSON, or the event stream (`response.created` … `response.completed`); tool calls as `function_call` output items |
| `GET /_standin/requests` | what the application sent, for the assessor: endpoint, step chosen, tool names offered, roles, message count, a digest of the last user text. Never the text, never a credential |

It binds `127.0.0.1` (or `::1`) only and refuses anything else. Any `Authorization` header is accepted; only its presence is
recorded. Nothing leaves the machine and no provider is called.

## The plan (`scopehaven-model-standin-plan/1`)

```json
{
  "schema": "scopehaven-model-standin-plan/1",
  "model": "scopehaven-standin",
  "steps": [
    { "id": "after-tool", "when": { "toolResult": "any" }, "reply": { "text": "Done: the tool ran and I have recorded the result." } },
    { "id": "refund-tool", "when": { "contains": "refund", "tools": ["issue_refund"] },
      "reply": { "toolCalls": [{ "name": "issue_refund", "arguments": { "orderId": "A-1", "reason": "customer asked" } }] } },
    { "id": "lookup", "when": { "contains": "order" }, "reply": { "text": "Order A-1 belongs to the Acme account." } }
  ],
  "default": { "text": "I can help with orders and refunds." }
}
```

Each request picks the first step whose `when` holds, else `default`:
- `contains`: the last user message contains this text (case-insensitive);
- `toolResult`: the last message is a tool result, for this tool name or `"any"`;
- `tools`: the request offers every tool named;
- a step without `when` matches every request; `"once": true` uses a step one time.

Put the tool-result step before the step that calls the tool, or the second turn (whose last user text still says "refund")
calls the tool again. `node integrations/model-standin/cli.mjs example-plan --out plan.json` writes this plan.

## Running it

```sh
node integrations/model-standin/cli.mjs serve --plan plan.json            # a free port
node integrations/model-standin/cli.mjs serve --plan plan.json --port 4471 --log requests.jsonl
```

It prints the origin and the environment lines below, serves until SIGINT or SIGTERM, and with `--log` appends one JSON
line per request (the same fields as `/_standin/requests`). `check --plan FILE` validates a plan without serving.

## Pointing an application at it

Most OpenAI-compatible clients take a base URL and a key. The key is never checked, so any value works:

| Application or client | Setting |
|---|---|
| OpenAI SDKs (Node, Python), LangChain `ChatOpenAI`, LiteLLM | `OPENAI_BASE_URL=http://127.0.0.1:PORT/v1`, `OPENAI_API_KEY=standin-no-key` (older clients read `OPENAI_API_BASE`) |
| OpenAI-compatible apps with a custom base URL field | the base URL `http://127.0.0.1:PORT/v1`, any key, model `scopehaven-standin` (an app's "generic OpenAI" provider, or its OpenAI base-URL setting) |
| An app in a container | `http://host.docker.internal:PORT/v1` |

If the app sends only the Responses API, the stand-in answers it with the same plan. The requests log tells you which
shape it used, which tools it offered and which step answered, so a profile's assistant checks can be written against a
model whose behavior is known, and a planted tool call (`toolCalls`) exercises the app's tool path deterministically.

## What it is not

A stand-in answers what the plan says. It shows how the application handles a model's reply (does it run the tool, does
it check the actor's rights before committing, does it record what it did); it says nothing about any real model's
behavior. Runs taken against it compare only with runs taken against it.

Tests: `node --test integrations/model-standin/model-standin.test.mjs`. Functions `startStandIn`, `createPlanner`,
`validatePlan` and `EXAMPLE_PLAN` in `server.mjs` are what `init` calls; `main` in `cli.mjs` is the command.


## init hook (`init-hook.mjs`)

`scopehaven init` calls `draftForInit({ profile, openapi, root })`. The stand-in drafts no checks; the hook returns `checks: []`
and, in `standIn`, the example plan, the two commands that write it and serve it on port 4471, and the environment lines that
point an OpenAI-compatible app at it. It starts nothing; pointing the app at the stand-in is the operator's step.
