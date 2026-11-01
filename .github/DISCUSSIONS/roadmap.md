# Roadmap

What's open here, what isn't and why, and the next two things I'm working toward. No dates: I'm one person, and I'd rather say what comes next than when. I'll update this post when one of them lands, and comments here are the place to argue for a different order.

## What is open

The open edition is the whole checking engine: the five verdicts and their rules (custody, attribution, settlement, allowed-use controls), every observer (`sqlite-audit`, `sqlite-snapshot`, `pg-snapshot`, `pg-wal`, `mysql-snapshot`, `http-audit`, `audit-file`, `egress-recorder`, `smtp-sink`, `provider-feed`, `dns-stub`, MCP and OpenTelemetry sources), every check family under `integrations/`, the synthetic support-agent fixture and the HTTP lab, `init` and `watch-first`, the regression gate, signed exports and the evidence pack with its standard-library verifiers, SARIF with its standards tags, the GitHub Action, the MCP target, the Promptfoo import, the payments pack with its loopback stand-in, the framework adapters for LangGraph and Mastra, and the dashboard. Five sample check packs ship under `integrations/packs-v2/packs`.

## What is not, and why

- **The check-pack library beyond the five samples, the class templates and the incident replays.** These are the accumulated, reviewed knowledge of which agent actions go wrong in which kinds of app. They are what I sell, and what pays for the time that keeps the engine free.
- **The adversarial carrier fixtures.** They were built to harden the pass semantics against evidence that looks right and is not. Publishing them would hand the exact shapes to whatever they are meant to catch, so they stay private.
- **The assessor and insurer pack.** It bundles the above with reporting and terms for third parties who sign off on other people's systems, which needs support and liability I can't offer in an open repository.
- **Hosted services**: shared run history, team dashboards, signed-evidence custody, support. Each needs an operator who holds something for you, and the whole point of the open edition is that nobody but you holds anything.

Nothing in the open edition is a trial or a stub for these. A result here is decided exactly as it would be with them.

## The next two things

1. **An install story that isn't `git clone`.** A published package so `npx scopehaven doctor` works, and a verified run on WSL 2 written into the limits pages so Windows developers know what to expect. Native Windows stays unverified until someone runs it there.
2. **Machine-readable output you can rely on.** One `--json` shape across the command-line entry points, with a `schema` field on every document, and `helpUri` links on SARIF rules and taxonomies so a finding in code scanning leads somewhere.

After those: a light theme for the dashboard, example profiles for webhook-driven apps, and a guide for running the Postgres observers against a disposable server. Each has a draft issue; take one if it's yours.

## What I will not add

Runtime enforcement, monitoring or alerting; anything that sends data off your machine by default; a dependency, in Node or in the Python verifiers; a verdict that a model takes part in. Ask in Discussions if you think one of these is wrong; I'll explain or change my mind in public.
