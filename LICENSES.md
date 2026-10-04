# Licences

This repository uses two licences. Which one applies depends on what a file
is, not where it happens to sit.

| Applies to | Licence | File |
|---|---|---|
| The specification text: everything under `spec/` | Creative Commons Attribution 4.0 International (`CC-BY-4.0`) | [LICENSE-CC-BY-4.0](LICENSE-CC-BY-4.0) |
| Everything else: source code, JSON Schemas, tests, test fixtures, build and CI configuration | Apache License 2.0 (`Apache-2.0`) | [LICENSE-Apache-2.0](LICENSE-Apache-2.0) |

The schemas are licensed as code, not as specification text, so that an
implementation may copy them into its own source tree under the same terms as
the rest of its code.

Element files used as test fixtures are copied from the QElectroTech element
collection and remain under that collection's licence; each fixture
directory says so.

New files should carry an SPDX header:

```text
SPDX-License-Identifier: Apache-2.0
```
