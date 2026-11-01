# Multi-turn, multi-identity scripts judged from records

**What was already on main, and the gap.**
- `integrations/conversations` runs multi-turn chats per proven identity, and captures values from one turn for use in later ones. It judges replies, GET state checks and surface snapshots.
- `integrations/sequences` judges declared effect observers (audit tables, database snapshots, sinks) over marked windows. Its request bodies are fixed, so a later request cannot use an id an earlier one created.

Neither covered both, so this module joins them without changing either.

## Scenario (`scopehaven-multiturn/1`)

- **`actors`:** as in a sequence. Credentials come from `SCOPEHAVEN_TARGET_*` variables.
- **`turns`, in order:** each turn is `{ actor, method, path, body?, capture?: { name: JSON pointer }, expect: [statuses] }`.
  - A turn may use an earlier turn's capture as `{{name}}` in its path or in a body value (never a body key). Using a name before a turn captures it is refused.
  - A captured value must be a plain identifier of at most 200 characters (letters, digits, `_ . : -`, and not only dots), so a response can never add a path segment, a query or a placeholder.
  - A capture that misses clears the name, even one an earlier turn (or another identity) captured. The next turn that needs it is never sent, and the run stops.
  - `expect` lists every status the turn may end with. For a forbidden attempt, list both the success and the refusal statuses (`[200, 403]`), or a refusal the scenario did not list stops the run.
- **`assertions`:** each covers a window of turns, `turn-a..turn-b`, and is judged by core's effect rules (`effect.none`, `effect.exists`, `effect.count`) from the declared observers.
  - Every forbidden assertion names its paired allowed-use control (`control: <id>`). The control must be a positive check: `effect.exists`, or `effect.count` of at least 1. A control that asserts an absence could pass on a target that does nothing. The control selects the same effect as its forbidden row in every selector field but the actor (source, operation, name, resource, outcome, trace id): B's own note backs "no note by B on A's ticket", while a control of another action, another record, or a broader resource cannot back a narrower forbidden row. The pairing stays in the run record (`control` on each forbidden assertion), and `runScenario` returns `pairs`: each forbidden row with its control, holding only when both pass.
  - Every identity an assertion can judge has at least 3 turns: its selector's actor, or every actor when the selector names none.
- **Size:** at most 21 turns (each turn is three sequence steps, within the sequence's 64).

## How it runs

- **Compile.** `compileScenario` turns the scenario into an ordinary `scopehaven-sequence/1`: a request, a status precondition and a mark for each turn.
- **Run.** `runScenario` runs it through the unchanged sequence runner. A capture-aware transport fills the placeholders.
- **Missing captures.** A capture that is missing stops the run at the next turn that needs it: the forbidden checks read missing, never pass.
- **Pairs.** `runScenario` returns each forbidden row with its control. A pair holds only when both pass. A pair that does not hold lists why, in order (`why` codes, with a sentence each in `reasons`):
  - `forbidden-failed`: an observer recorded the forbidden effect.
  - `cannot-hold-custody`: only records the target can write decided the forbidden row, so it can never pass on them. The sentence names what could decide it.
  - `forbidden-<status>`: the forbidden row was not decided for another reason.
  - `control-not-passed`: the paired control did not pass.
- **Replay.** `replayDigest` covers the verdicts and every window's events without their observation times. Two runs on fresh targets give the same replay digest (tested). The sealed run digest also covers observation times, so it differs from run to run.

## Owned target (`desk.mjs`)

- A two-identity ticket desk: create, note, close and read, each written to an audit row.
- With `downstream` (a loopback base URL), the desk also calls a tool service for every committed note and close (`POST /tool/ticket-note`, `POST /tool/ticket-close`). It waits for the answer before replying.
- The `unchecked` build skips the owner check (the planted defect).
- The example scenario in the tests is B noting and closing A's ticket by A's captured id.
  - On the `checked` build, both forbidden checks read inconclusive (subject-writable-custody): only the desk's own audit table decides them.
  - On the `unchecked` build, both fail.
  - On both builds, the three paired controls pass: A's own note, B's own note, and A closing its own ticket afterwards.
- The `do-nothing` build answers every write as if it worked and records nothing. Its forbidden checks read inconclusive (subject-writable-custody) and its controls fail, so no pair holds.
- So on the audit table alone, no pair can hold on any build. On the checked desk each pair says `cannot-hold-custody`; on the unchecked desk, `forbidden-failed`.

**On the request path, a pair holds.** The tests put a hold gate (`integrations/sequences/gate.mjs`) in front of the desk's tool service. The gate holds nothing, and records each call as a `tool-call` effect, committed when the service answers 2xx. That record is held outside the desk (custody `independent`). The same turns are then judged by `{ source: "hold-proxy", operation: "tool-call", name: "ticket-note" | "ticket-close" }`:
- **Checked:** both forbidden rows pass with independent custody, and both pairs hold.
- **Unchecked:** both fail.
- **Do-nothing:** the absences pass, but every control fails, so no pair holds.

The gate records no acting principal, so these selectors name none. They are sound here because only B acts in the forbidden window (turns 5 and 6).

The gate sees the desk's calls, not its tables, and nothing proves the desk routes its calls through the gate. A forbidden write passes there when the desk:
- (a) writes the note without calling the service;
- (b) calls the service directly, around the gate;
- (c) calls it after its own window has closed.

The gate has no witness and no settle of its own. The request-path harness declares a 250 ms post-response settle, and its last controls are exact counts: A's close in turn 7 counts one close, and a final turn 8 (MT-C4) counts exactly one note. The settle catches a call up to 250 ms late. A later call can land in a window that counts the other tool, or after the last mark, and MT-C4 backs no pair, so its failure does not stop a pair from holding.

A drill desk that calls the service 150 ms after replying (`unchecked-late-call`) holds no pair. Without the gate, the same selectors see nothing and no forbidden row passes.

## Not done

**pass^k.** pass^k exists (`integrations/pass-k/`), but a sequence run is not one of its trial sources: it reads conversation, saved HTTP and single-run records, and supplied observation tables. For a scenario, repeat it with `runScenario` and give each assertion's outcome per run to `checksFromObservations` (a success only when the assertion passed). That table is supplied input, not a validated run: the gate never emits it and `normalizePassK` refuses it.

Tests: `node --test integrations/multiturn/multiturn.test.mjs`. Scripts contain legitimate requests only.
