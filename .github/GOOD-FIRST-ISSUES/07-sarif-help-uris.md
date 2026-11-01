# SARIF: give each rule a `helpUri` and each taxonomy its source URL

`./scopehaven export --format sarif` writes one SARIF rule per check with `shortDescription`, `fullDescription` and `help.text`, but no `helpUri`, and its `taxonomies` list identifiers without a `helpUri` either, although `src/standards-map.json` already records a `source` URL for OWASP LLM 2026, OWASP Agentic 2026 and MITRE ATLAS. In GitHub code scanning and in SARIF viewers the help link on a finding is therefore empty, and a reviewer who sees `OWASP-LLM06:2026` on a rule has nowhere to click.

In `src/sarif.mjs`, set each rule's `helpUri` to a page inside this repository, built from `package.json`'s `repository.url`: the check family's README when the rule's `category` maps to one, otherwise `README.md`. Add `helpUri` to each taxonomy, and to each of its `taxa`, from the map's `source` field where one exists, and nothing where it does not (CWE and OWASP LLM 2025 have no `source` in the map; do not invent one). The URL is a pointer to documentation, never a statement about the finding, and the tool description sentence stays exactly as `test/claims-wording.test.mjs` pins it. The map is read only by the exporter, so this changes no run identity.

## Pointers

- `src/sarif.mjs`: the `rules` map (`shortDescription`, `fullDescription`, `help`) and the `taxonomies` array with its `taxa`.
- `src/standards-map.json`: `taxonomies.*.source`, and the `purpose` note that the file never enters a hash.
- `package.json`: `repository.url`.
- `test/sarif-export.test.mjs`: line 45 asserts the rule fields that exist today.
- `test/claims-wording.test.mjs`: the pinned `fullName` of the tool driver.

## Acceptance

Every rule in an exported SARIF carries an absolute `https` `helpUri` inside this repository, every taxonomy with a `source` in the map carries it as `helpUri`, and the export still validates as SARIF 2.1.0.

## Test

Extend `test/sarif-export.test.mjs`.

## Labels

`good first issue`, `check`

## Effort

2 to 3 hours.
