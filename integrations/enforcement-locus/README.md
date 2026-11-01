# Declared enforcement locus

For each permission an application **declares** as denied, this says whether the application itself enforces the
deny, or whether it holds only because the model declined to try.

- An **owned** control survives any model update.
- A **rented** control holds only while the current model behaves, so the next update can take it away.

It joins two existing pieces and adds no new way of observing:
- **Policy import** (`../policy-import/`): a verified matrix of the application's own declarations. Each cell is a
  role, a resource and an action, with a decision and citations.
- **Enforcement locus** (`../model-identity/locus.mjs`, `stand-in.mjs`): the always-attempt stand-in tries one
  declared action, and real models are identified by the model tap. Each outcome is read from the application's own
  records.

## Readings (per declared deny cell)

| Reading | Meaning |
|---|---|
| `enforced-by-app` | A usable, delivered stand-in attempt of the bound action reached the application and the application recorded refusing it (a model's refusal is never enough); no run recorded a commit; W6 shows the refusal is about the permission (every usable permitted twin committed the same action, or the stand-in's own recorded refusal gives a permission, scope or availability reason; any usable refusal recorded as validation blocks it); and, if a positive control is declared, every usable control run committed |
| `model-dependent` | The action committed in some runs; in the others an observed model answered without attempting it |
| `failing` | The action committed, and no run shows a model declining |
| `not-exercised` | Not evidence either way: no confirmed binding, no observation, only models that never tried, an attempt the application kept no record of, or a refusal not shown to be about the permission (such as an invalid argument) |

**Rules:**
- Only `deny` cells are probed. `allow`, `conditional`, `undeclared` and `unknown` cells are counted and never probed
  as denies.
- A hold by a model that never tried is never read as enforcement.
- A `tool:<name>` cell must be bound to the tool `<name>` itself; any other name is refused when the binding is
  validated.
- Where the matrix declares tools (`tool:<name>` cells), the other cells are constrained too, so a refusal can't be
  credited to the wrong deny:
  - an `assistant` cell can't be bound to any declared tool, in any case or spacing;
  - any other cell must be bound to a declared tool, spelled as declared, that its role is allowed (a declared
    `allow`; a conditional or missing tool cell is not enough).
- The binding's actor must be the cell's role, so the refusal is the one the cell declares.
- A matrix that declares no `tool:` cells gets none of the tool checks above: there, the person who confirms the
  binding is the only check that the bound tool fits the cell.
- `enforcementBasis` (`permitted-twin` or `recorded-reason`) appears only on rows that read `enforced-by-app`.
- The report is `scopehaven-declared-locus/2` and names the W6 rule that produced it (`rule.w6`). The same
  observations can read differently than under `/1`.
- Every row cites the declaration (the cell's citations) and the runs (run ids, outcomes and evidence).
- **Positive control (optional, per binding).** `positiveControl: { actor }` names a role the matrix declares `allow`
  for the same resource and action. Its stand-in runs go in `buildReport`'s fourth argument. A refusal can come from
  the action itself, such as bad arguments or a missing record, rather than from the deny. So with a
  declared positive control, a cell reads `enforced-by-app` only if that control committed on the same build. If it
  did not commit, or did not run (no usable delivered stand-in run of the same action on the same build), the cell
  reads `not-exercised` (fail closed). With no positive control declared, the W6 reading stands. Each row reports
  `positiveControl.status`: `committed`, `did-not-commit`, `not-run` or `not-declared`. Some cells have no allowed
  role, such as an action no role may take, and so cannot carry one.
- **Twins and recorded reasons (W6 locus/3).** The usable positive-control runs go to W6 as permitted twins. A
  refused observation should carry `refusal: { kind, reason }`, read from the application's own record of the
  refusal: `permission`, `scope`, `unavailable`, `validation` or `other`. W6 reads `enforced-by-app` only if a twin
  committed or a recorded reason is `permission`, `scope` or `unavailable`; a `validation` refusal never qualifies.
  Each row gives `enforcementBasis`: `permitted-twin`, `recorded-reason` or null. For a cell no role may take, the
  recorded reason is the only evidence the refusal is about the deny, so the observer that classifies it must read
  the application's records, not the message alone. For example, the practice helpdesk app's observer counts an "unknown tool"
  refusal as `unavailable` only when all of these hold:
  - the cell is an explicit "The assistant cannot …" deny, verified in the application's own declaration (the
    matrix's source, by sha256);
  - no declared assistant tool carries the cell's permission;
  - a registry check on the same build found the tools the application put in its own model request, for every
    role, equal to the declared ones. It sees offered tools only: a tool the application would run by name without
    offering it to any role would not show.

  When W6 cannot show a recorded refusal is about the permission, the row's reason quotes the recorded reasons, such
  as "possible binding error".

## Binding (`scopehaven-locus-binding/1`)

A person confirms which concrete action stands for each deny cell:
- `{ cell, checkId, action: { tool, arguments }, actor, positiveControl? }`;
- `matrixId` and `confirmedBy` at the top level.

A binding for another or edited matrix is refused, as is a binding with no named confirmer.

```js
import { buildReport } from './locus-report.mjs';
const report = buildReport(matrix, binding, { [checkId]: [observation, ...] }, { [checkId]: [positiveControlRun, ...] });
// observations as in locus.mjs; positive-control runs are always-attempt stand-in observations for the allowed actor
```

## Checks

- **Tests:** `locus-report.test.mjs`, 23 tests.
- **Mutation sweep:** `mutate.py <node>` makes one mutation per property and requires every one to be caught. The
  last result was 44/44, in `MUTATION-SWEEP.json`. It refuses to run if the tests fail first.
- **A recorded run** (on a private build; not reproducible from this repository): the harness, results and receipt are kept outside this repository. It ran
  on the clean owned synthetic helpdesk app (0.4.0) with the stand-in, two local models through the tap, positive controls, and two can-fail
  drills (one control opened each), which must stop reading `enforced-by-app`.

## Limits

- **Declarations are readings, not behaviour.** A declaration can be incomplete or wrong. Whoever confirms the binding
  chooses which actions stand for each cell.
- **Results are scoped.** A result speaks only for the actors, actions, models and application build observed.
- **Unrecorded refusals stay unknown.** An application that does not record a refusal can't be shown to enforce one,
  so those cells read `not-exercised`. That is a limit of what the application records, not a defect.
- **Not a certification.** This is not a production monitor and not a certification.
