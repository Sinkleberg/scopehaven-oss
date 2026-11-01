#!/usr/bin/env python3
"""One-mutation-per-property sweep for locus-report.mjs. Each mutation breaks exactly one promised property;
the test file must fail for every one. A surviving mutation is a test gap. Restores the original afterwards.
usage: python3 mutate.py <node>"""
import json, pathlib, subprocess, sys

HERE = pathlib.Path(__file__).resolve().parent
SRC = HERE / 'locus-report.mjs'
NODE = sys.argv[1]
MUTATIONS = [
    ('only deny cells can be bound', "if (cell.decision !== 'deny') throw", "if (false && cell.decision !== 'deny') throw"),
    ('never-attempted is not enforcement', "'never-attempted': 'not-exercised'", "'never-attempted': 'enforced-by-app'"),
    ('inconclusive is not enforcement', "inconclusive: 'not-exercised' }", "inconclusive: 'enforced-by-app' }"),
    ('committed reads as failing', "'not-enforced': 'failing'", "'not-enforced': 'not-exercised'"),
    ('model-dependent stays model-dependent', "'model-dependent': 'model-dependent'", "'model-dependent': 'enforced-by-app'"),
    ('an unbound cell is not exercised', "if (!b) return { declaration, reading: 'not-exercised'", "if (!b) return { declaration, reading: 'enforced-by-app'"),
    ('no observation is not exercised', "if (!observations.length) return { ...base, reading: 'not-exercised'", "if (!observations.length) return { ...base, reading: 'enforced-by-app'"),
    ('an edited matrix is refused', "if (!matrix || !verifyMatrixId(matrix)) throw", "if (!matrix) throw"),
    ('a binding for another matrix is refused', "if (binding.matrixId !== matrix.matrixId) throw", "if (false) throw"),
    ('a binding names its confirmer', "if (typeof binding.confirmedBy !== 'string' || !binding.confirmedBy.trim()) throw", "if (false) throw"),
    ('a cell is bound once', "if (keys.has(cellKey(cell))) throw", "if (false) throw"),
    ('rows cite the declaration', "const declaration = { role: cell.role, resource: cell.resource, action: cell.action, basis: cell.basis, citations: cell.citations };", "const declaration = { role: cell.role, resource: cell.resource, action: cell.action, basis: cell.basis, citations: [] };"),
    ('rows cite the runs', "runs: locus.observations.map(o => ({ runId: o.runId,", "runs: [].map(o => ({ runId: o.runId,"),
    ('non-deny cells are counted as not probed', "matrix.cells.filter(c => c.decision === d).length", "0"),
    ('a failed positive control blocks enforced-by-app', "const blocked = locus.locus === 'enforced-by-app' && ", "const blocked = false && "),
    ('a declared positive control that never ran fails closed', "positiveControl.status !== 'not-declared' && positiveControl.status !== 'committed'", "positiveControl.status === 'did-not-commit'"),
    ('a committed positive control keeps enforced-by-app', " && positiveControl.status !== 'committed';", ";"),
    ('no declared positive control leaves the W6 reading', "&& positiveControl.status !== 'not-declared' &&", "&&"),
    ('usable control runs go to W6 as permitted twins', "[...observations, ...positiveControl.twins]", "[...observations]"),
    ('only usable control runs become twins', "const twins = usable.map(", "const twins = runs.map("),
    ('a twin carries the bound action', "action: b.action }, outcome: o.outcome", "action: { tool: 'other_tool', arguments: {} } }, outcome: o.outcome"),
    ('rows carry the enforcement basis', "(locus.enforcementBasis ?? null) : null", "(null) : null"),
    # Not swept here: W7's own "enforced-by-app needs a usable refused stand-in attempt" guard. Since W6 locus/3 at
    # 9f71ec6, W6 never reads enforced-by-app without one (twin and recorded-reason routes alike), so reverting W7's
    # copy changes no reading; W6's own sweep catches reverting W6's. The guard stays as a second line.
    ('a tool: cell is bound to its own tool', "if (cell.resource.startsWith('tool:') && b.action?.tool !== cell.resource.slice('tool:'.length)) throw", "if (false) throw"),
    ('an incomplete control run is unusable', "o.actor.delivered === true && o.recordsComplete && ", "o.actor.delivered === true && "),
    ('a validation refusal states its recorded reason', "['refusal-not-shown-to-be-permission', 'validation-refusal-recorded']", "['refusal-not-shown-to-be-permission']"),
    ('the report names the W6 rule', "rule: RULE, application:", "application:"),
    ('review: control status from all runs', "status: usable.every(o => o.outcome === 'committed')", "status: runs.every(o => o.outcome === 'committed')"),
    ('review: control build when builds differ', "builds.size === 1 ? [...builds][0] : null", "[...builds][0]"),
    ('an assistant cell is never bound to a declared tool', "        if (named) throw new Error(`${where}: an assistant cell", "        if (false) throw new Error(`${where}: an assistant cell"),
    ('declared tool names compare normalized', ".normalize('NFKC').replace(/[\\s\\u200B-\\u200D\\uFEFF]/g, '').toLowerCase()", ""),
    ('another cell binds a declared tool as spelled', "if (!named || named !== b.action?.tool) throw", "if (!named) throw"),
    ('another cell binds a tool its role is allowed', "action: 'invoke' }))?.decision !== 'allow') throw", "action: 'invoke' }))?.decision === 'never') throw"),
    ('the actor is the cell\'s role', "    if (b.actor !== cell.role) throw", "    if (false) throw"),
    ('review r4: actor check on tool: cells too', "    if (b.actor !== cell.role) throw", "    if (!cell.resource.startsWith('tool:') && b.actor !== cell.role) throw"),
    ('review r4: actor check where the matrix declares no tools', "    if (b.actor !== cell.role) throw", "    if (declaredTools.size && b.actor !== cell.role) throw"),
    ('review r4: actor check is exact, not case-insensitive', "    if (b.actor !== cell.role) throw", "    if (b.actor.toLowerCase() !== cell.role.toLowerCase()) throw"),
    ('only a declared allow lets another cell bind a tool', "action: 'invoke' }))?.decision !== 'allow') throw", "action: 'invoke' }))?.decision === 'deny') throw"),
    ('a control commits only if every usable run did', "status: usable.every(o => o.outcome === 'committed')", "status: usable.some(o => o.outcome === 'committed')"),
    ('a basis shows only on enforced-by-app', "enforcementBasis: reading === 'enforced-by-app' ? (locus.enforcementBasis ?? null) : null", "enforcementBasis: locus.enforcementBasis ?? null"),
    ('an unshown refusal states its recorded reason', ": recorded.length ? `${locus.basis}; recorded: ${recorded.join('; ')}` : locus.basis", ": locus.basis"),
    ('a positive control actor is declared allowed', "if (pc?.decision !== 'allow') throw", "if (false) throw"),
    ('a positive control runs on the same build', "o.recordsComplete && o.appBuild === appBuild", "o.recordsComplete"),
    ('a positive control attempt was delivered', "o.actor.delivered === true && ", ""),
    ('a positive control carries the bound action', "&& o.actor.scriptSha256 === scriptSha256(attemptScript(b.action, s.at(-1)?.content ?? 'Done.'))", ""),
]

original = SRC.read_text()
# A sweep over failing tests would read every mutation as caught: the tests must pass first.
if subprocess.run([NODE, '--test', str(HERE / 'locus-report.test.mjs')], capture_output=True, text=True).returncode != 0:
    sys.exit('The tests fail before any mutation; fix them first.')
results = []
try:
    for name, find, repl in MUTATIONS:
        if original.count(find) != 1:
            results.append({'property': name, 'status': 'mutation-site-not-unique', 'count': original.count(find)}); continue
        SRC.write_text(original.replace(find, repl))
        p = subprocess.run([NODE, '--test', str(HERE / 'locus-report.test.mjs')], capture_output=True, text=True)
        results.append({'property': name, 'status': 'caught' if p.returncode != 0 else 'SURVIVED'})
finally:
    SRC.write_text(original)
caught = sum(r['status'] == 'caught' for r in results)
print(json.dumps({'mutations': len(MUTATIONS), 'caught': caught, 'results': results}, indent=1))
sys.exit(0 if caught == len(MUTATIONS) else 1)
