# Welcome

I'm the maintainer. This post says what ScopeHaven is, what this repository is and is not, where its limits are, how to ask for things, and what to expect from me.

## What it is

ScopeHaven checks what an AI agent actually did in your application, not what it said. It runs an agent's tasks against a local copy of your app as different users, then decides every check from the app's own records when you declare an observer, or from the HTTP responses when you don't, and says which one it used. No model takes part in a verdict, and nothing leaves your machine. It is for teams whose agents write into their own product: refunds, credits, plan changes, account updates, exports.

## What this repository is, and is not

This is the open edition, under Apache-2.0: the engine, the observers, the check families, the synthetic fixture and the HTTP lab, signing and verification, the GitHub Action, the MCP target and the Promptfoo import. Nothing in it is crippled, and it will stay free.

Kept separate and commercial: the check-pack library beyond the five bundled samples under `integrations/packs-v2/packs`, the class templates and incident replays, the adversarial carrier fixtures used to harden pass semantics, the assessor and insurer pack, and every hosted service. Please don't open issues or pull requests that add those here; I'll close them with a link to this post. Everything else is fair game.

## Limits worth knowing before you rely on a result

- It tests a local copy of your app over loopback, or a staging origin you name in a signed authorization record. It never tests production, never follows redirects, never retries on its own.
- Without a declared observer, a check on an outside app is response-level: the result says "response contracts restored", not "backend effects verified".
- Inconclusive is not a pass. A green result that checked nothing is reported as inconclusive, and the coverage report says beforehand what the suite cannot see.
- It checks the policies you declare and the checks you run. A passing run is evidence about those checks on that build, not a security certification, and it finds no defect you did not write a check for.

`docs/KNOWN-LIMITS.md` and `docs/SUPPORTED-MODES.md` have the full list.

## How to ask

- **Pointing it at your app**: a Q&A discussion. Say what the app is (stack, how it takes a session), what you ran, and what `./scopehaven doctor` printed. Redact everything: never paste a credential, a token, or data from a real customer or production system. A redacted `run.json` or gate summary is the most useful thing you can attach.
- **A check you'd like before you build it**: an Ideas discussion, with the agent behaviour and the record it should be decided from. A concrete example beats a category.
- **Something wrong**: a bug report issue, using the template. Security problems in ScopeHaven itself go through `SECURITY.md`, never a public issue or discussion.
- **Taking a good first issue**: comment on it. Nobody is assigned silently.

## What to expect from me

I'm one person. I read everything that comes in and aim for a first reply within about a week, longer for a large pull request. Reviews here ask about the failing case and about limits; that is normal and not a sign the change is unwelcome. CI runs the whole suite on a pull request marked ready; a flaky file gets one automatic rerun, and two failures are a real failure. Every commit needs a DCO sign-off (`git commit -s`), the repository takes no dependencies, and every behaviour change comes with its test. `CONTRIBUTING.md` has the rest.

Thanks for being here.
