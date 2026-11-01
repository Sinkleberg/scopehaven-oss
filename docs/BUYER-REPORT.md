# Report exports

`--format html` exports the full report. Browser printing uses a cover with run identities and claim counts, the findings (each with its claim type: exact, risk-bound or descriptive), a "Coverage and residual" section, and a closing limits section. Its coverage part lists, per actor with a boundary check, the required allowed-use controls that ran as that actor, with an actor that has none in red; the full pre-run coverage report appears only when the export is given the operator's coverage files ([ONBOARDING](ONBOARDING.md#a-first-engagement-end-to-end)). Coverage changes no verdict or count. The residual lists the declared channels not observed or carrying an unaccounted effect (or "channels undeclared"), the checks that read inconclusive with their reason codes, the allowed-use pairing that did not hold and the declared observers that did not run, or ran incomplete, in a window; nothing in it is a pass. Record custody disclosures and all limitations remain in the full report. The comparison export keeps its compatibility, allowed-use and model attribution rules.

`--format summary` exports a compact HTML summary. It includes target metadata, scope, counts of listed checks and their statuses, check ids, limitations, identities and custody tags. Listed checks include not-applicable and never-sent rows; the total does not claim they were executed. It also prints the claim counts and the residual in brief (check ids, observer and channel ids, reason codes and counts), which the export computes from the run and hands to the page; the page itself never reads traces, and prints no assertion name from the residual. It omits check titles, observed values, traces, assertion evidence, request and response bodies and human notes. It is not anonymized: review the retained metadata and limitations before sharing.

```sh
./scopehaven export --run RUN_ID --format html --out /ABSOLUTE/exports/report.html
./scopehaven export --run RUN_ID --format summary --out /ABSOLUTE/exports/summary.html
./scopehaven export --run RUN_ID --format residual --out /ABSOLUTE/exports/residual.json
```

Each command also writes a signature envelope beside its file (`report.html.dsse.json`, `summary.html.dsse.json`, `residual.json.dsse.json`) with the local key in `~/.config/scopehaven/signing`, unless `--unsigned`. The HTML report carries a "Signed evidence" paragraph naming the key id and both verifiers; the summary's bytes are unchanged and its Verify section already names them.

`--format residual` writes every row's claim type and the residual as JSON (`scopehaven-residual/1`), with the run id and its evidence integrity sha256. The JSON export (`--format json`) stays the sealed run record and carries neither; the comparison JSON carries each side's claims and residual.

The output parent must be owned, nonsymlink and mode 0700. The export writes private 0600 files and refuses existing destinations. Open an exported HTML file and use the browser's print dialog when a PDF is needed. There is no automatic browser or PDF helper in this change. Printing hides the collapsed observed traces; they stay in the HTML file and the exported JSON. Browser page counts, visual layout and PDF file permissions have not been verified for this release; long metadata or custody disclosures can use more than one page.

The summary shows whole limitations in order. Its 6000-character budget fits every shipped run's limitations, so the synthetic scope and the unsupported behaviour are always stated; longer input is counted with a pointer to the full report. Not-applicable and unsettled check ids are listed up to 12 per group; the rest are counted. The summary accompanies the full report rather than replacing it.

Observed-effect clause custody is counted from the run's own assertion tags, with the number of clause verdicts custody held at inconclusive. The boundary rule and allowed-use control rule remain explicit. `renderSummary(run, { custody })` can also show caller-supplied ledger anchors separately; these do not change any run verdict or upgrade the custody of its assertions. An unrecognized or malformed supplied anchor prevents an aggregate ledger custody grade; the summary counts such entries without printing their unrecognized strings. The export CLI supplies no ledger anchors.

To sign a summary together with the run in one envelope, include their exact bytes as attest subjects (export them with `--unsigned` if you do not want the envelope per file):

```sh
node integrations/attest/cli.mjs sign --key KEY.pem --out /ABSOLUTE/exports/evidence.dsse.json /ABSOLUTE/exports/run.json /ABSOLUTE/exports/summary.html
```

Verify either kind of envelope with the public key and subject files using the attest verifier. A valid signature shows that the key holder produced those exact bytes; it does not show that the results are correct. These are observed checks, not a safety certification.
