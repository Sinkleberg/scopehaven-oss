# Notices for src/standards-vocabularies.json

`src/standards-vocabularies.json` copies identifier lists only, no descriptive text, from two MITRE sources. `src/sarif.mjs` reads them to check that every standards-map identifier exists in the pinned release. The notices below go with every copy of that file.

## MITRE ATLAS 2026.09 technique identifiers

- Source: https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/v6/ATLAS-2026.09.yaml (ATLAS data version 2026.09, format 6.0.0, file dated 2026-09-15), sha256 935efa93e28294432d3e2f537eb94991ef8d1f8c58341cd360ea3321ddb66688.
- Repository: https://github.com/mitre-atlas/atlas-data at commit 3259f388d19cbcca11bacf12a0ef97f4198f711b (2026-09-10), retrieved 2026-10-19.
- What is copied: the 208 technique and sub-technique IDs (for example AML.T0053), parsed from the file's `techniques` section.
- Licence: Apache License, Version 2.0. The data repository's LICENSE file (sha256 fa6c92ab3dc75d41413884e8b38cc54cd4e72f4c8f68fc7e77824e48e3047d40) reads, in full:

```
Copyright 2021-2026 MITRE

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

- Release statement from the data repository's README: "©2021-2026 The MITRE Corporation. ALL RIGHTS RESERVED. Approved for Public Release; Distribution Unlimited. Public Release Case Numbers 21-2363, 26-1162."
- Change made: the identifiers were extracted from the YAML into a JSON array; nothing else was copied.

## CWE 4.20 weakness identifiers

- Source: https://cwe.mitre.org/data/csv/1000.csv.zip (view 1000, Research Concepts; the CWE List's current version, 4.20, on the retrieval date), sha256 6a3d52a7d164d98eb24ca3228039dcd98461379d225dfd395474c0d007537791, retrieved 2026-10-19.
- What is copied: the 944 weakness ID numbers in that view. Categories and views are not in it.
- Copyright designation, as shown on cwe.mitre.org: "Copyright © 2006-2026, The MITRE Corporation. CWE, CWSS, CWRAF, and the CWE logo are trademarks of The MITRE Corporation."
- Licence, from the CWE Terms of Use (https://cwe.mitre.org/about/termsofuse.html, read 2026-10-19): "CWE™ is free to use by any organization or individual for any research, development, and/or commercial purposes, per these CWE Terms of Use. Accordingly, The MITRE Corporation hereby grants you a non-exclusive, royalty-free license to use CWE for research, development, and commercial purposes. Any copy you make for such purposes is authorized on the condition that you reproduce MITRE’s copyright designation and this license in any such copy. CWE is a trademark of The MITRE Corporation."
- The same Terms of Use say the information is provided "as is", without warranty of any kind.
