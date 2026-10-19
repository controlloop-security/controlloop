---
type: reference
title: License and third-party dependency audit
tags:
  - reference
  - licensing
  - legal
  - dependencies
created: 2026-08-20
---

# License and third-party dependency audit

This page records ControlLoop's license decision and the evidence behind
it. It is a decision record, not a proposal: the license is chosen and
applied.

## Decision

ControlLoop is licensed under the **Apache License, Version 2.0**. The full,
unmodified license text is in [`LICENSE`](../../LICENSE) at the repository
root.

### Why Apache-2.0 instead of MIT

The maintainers considered Apache-2.0 against MIT, the two dominant
permissive licenses for developer tooling, and chose Apache-2.0 for three
reasons:

1. **Matches the nearest competing scanner.** The nearest competing agent
   capability/security scanner ships under Apache-2.0. Matching it lowers
   friction for contributors and evaluators who already understand that
   license's terms, and avoids ControlLoop appearing to take a
   deliberately different legal stance from the product it is most
   directly compared against.
2. **Patent grant reduces enterprise legal-review friction.** Apache-2.0 §3
   grants an explicit, irrevocable patent license from every contributor,
   with a defensive termination clause if a user sues over patent
   infringement. MIT has no patent clause. ControlLoop's initial buyer
   is an engineering, AppSec, or
   platform-security lead evaluating a security product for enterprise use;
   those legal reviews routinely check for an explicit patent grant before
   approving adoption. Apache-2.0 answers that check directly; MIT leaves
   it to implication.
3. **Explicit trademark reservation.** Apache-2.0 §6 states that the license
   does not grant permission to use the licensor's trade names, trademarks,
   service marks, or product names. MIT is silent on trademarks. This
   protects the "ControlLoop" name from
   implied endorsement by redistributors or forks, independent of the
   copyright license granted over the code itself.

Both licenses are OSI-approved, permissive, and compatible with
ControlLoop's open-core business model. The three
reasons above are why Apache-2.0 specifically was chosen over MIT, not a
claim that MIT would have been unusable.

## Interaction with a future paid tier

Apache-2.0 is a permissive license, **not** a copyleft license. It imposes
no obligation to release derivative or combined works under the same
license, and no obligation to publish source code for software that merely
uses or is distributed alongside an Apache-2.0 component. That means
nothing about this license prevents a future paid tier from including
additional code or services that are not open source, whether built as a
separate proprietary service or a closed-source extension. The Community CLI in
this repository is entirely Apache-2.0; nothing
about the license itself constrains what business model a future tier
might use.

## `LICENSE` and package metadata

- [`LICENSE`](../../LICENSE) exists at the repository root with the
  canonical Apache License, Version 2.0 text from
  `https://www.apache.org/licenses/LICENSE-2.0.txt`, verified byte-for-byte
  identical for the terms-and-conditions body (sections 1-9), plus a filled
  copyright/boilerplate notice ("Copyright 2026 ControlLoop") in the
  Appendix form the license itself recommends.
- [`NOTICE`](../../NOTICE) at the repository root carries the copyright
  notice and the attributions for the third-party schemas the test suite
  vendors, as the Apache License's section 4(d) expects a `NOTICE` file
  to.
- `pyproject.toml` declares `license = "Apache-2.0"` (a PEP 639 SPDX
  license expression) and `license-files = ["LICENSE", "NOTICE"]`, so
  both ship in the built wheel and sdist. `LICENSE` is the same root file
  GitHub detects as the repository license.
- Verified in the actual built artifacts (not just the source TOML): the
  built wheel's `*.dist-info/METADATA` contains
  `License-Expression: Apache-2.0` and `License-File: LICENSE`, and the
  wheel embeds the license text at `*.dist-info/licenses/LICENSE`, confirmed
  byte-identical to the repository's `LICENSE`. The built sdist
  (`controlloop-0.1.0.tar.gz`) also contains a `LICENSE` file at its root.
- **Formula and image metadata (not yet built):** this repository has no
  Homebrew formula and no container image yet. There is no artifact to set metadata on today. When
  they are built, their formula/image metadata (e.g. a Homebrew formula's
  `license` field, an OCI image's `org.opencontainers.image.licenses`
  label) must be set to `Apache-2.0` to agree with this decision and with
  the package metadata above.

## Third-party dependency license audit

Every entry in `uv.lock` was checked for license compatibility with
distributing ControlLoop under Apache-2.0. `uv.lock` locks 44 packages
total: 43 third-party dependencies and the `controlloop` project itself.

**Method:** `uv` has no built-in license-listing command and no
`pip-licenses`-equivalent is installed. Licenses were determined by running
`uv sync --locked --all-groups` from the repository root and reading each installed
distribution's real package metadata (`License`, `License-Expression`, and
`Classifier: License ::` fields) via Python's `importlib.metadata` against
the synced `.venv` -- this reads the same metadata `pip show` would report,
directly from each package's own installed `METADATA` file, not a
hand-typed guess. One dependency, `colorama`, is locked only under a
`sys_platform == 'win32'` marker and does not install on this
(macOS/Linux-resolved) platform; its license was instead confirmed from the
PyPI JSON API (`https://pypi.org/pypi/colorama/0.4.6/json`), which reports
the `License :: OSI Approved :: BSD License` classifier.

"Distribution" below marks whether a dependency ships inside the built
`controlloop` package (runtime, resolved via `uv tree --all-groups` from
the `[project.dependencies]` closure) or is used only for local development
and CI (`dev` dependency group: linting, type checking, tests, pre-commit)
and is never redistributed to an end user.

| Package | Version | Distribution | License | Compatible with Apache-2.0 | How determined |
| --- | --- | --- | --- | --- | --- |
| annotated-doc | 0.0.5 | Runtime (typer) | MIT | Yes | Installed metadata |
| annotated-types | 0.8.0 | Runtime (pydantic) | MIT | Yes | Installed metadata |
| attrs | 26.1.0 | Dev only (jsonschema) | MIT | Yes | Installed metadata |
| cfgv | 3.5.0 | Dev only (pre-commit) | MIT | Yes | Installed metadata |
| colorama | 0.4.6 | Runtime, Windows only (typer); also dev (pytest) | BSD License (BSD-3-Clause) | Yes | PyPI JSON API (not installed on this platform; `sys_platform == 'win32'` marker) |
| coverage | 7.15.3 | Dev only (pytest-cov) | Apache-2.0 | Yes | Installed metadata |
| distlib | 0.4.3 | Dev only (virtualenv) | PSF-2.0 (Python Software Foundation License) | Yes | Installed metadata |
| filelock | 3.32.3 | Dev only (virtualenv) | MIT | Yes | Installed metadata |
| identify | 2.6.19 | Dev only (pre-commit) | MIT | Yes | Installed metadata |
| iniconfig | 2.3.0 | Dev only (pytest) | MIT | Yes | Installed metadata |
| jsonschema | 4.26.0 | Dev only | MIT | Yes | Installed metadata |
| jsonschema-specifications | 2025.9.1 | Dev only (jsonschema) | MIT | Yes | Installed metadata |
| lark | 1.3.1 | Runtime (python-hcl2) | MIT | Yes | Installed metadata |
| librt | 0.13.0 | Dev only (mypy) | MIT | Yes | Installed metadata |
| markdown-it-py | 4.2.0 | Runtime (rich) | MIT | Yes | Installed metadata |
| mdurl | 0.1.2 | Runtime (markdown-it-py) | MIT | Yes | Installed metadata |
| mypy | 1.20.2 | Dev only | MIT | Yes | Installed metadata |
| mypy-extensions | 1.1.0 | Dev only (mypy) | MIT | Yes | Installed metadata |
| nodeenv | 1.10.0 | Dev only (pre-commit) | BSD License | Yes | Installed metadata |
| packaging | 26.2 | Dev only (pytest) | Apache-2.0 OR BSD-2-Clause (dual) | Yes | Installed metadata |
| pathspec | 1.1.1 | Runtime (direct dependency; also mypy dev) | MPL-2.0 (Mozilla Public License 2.0) | Yes, with a note -- see below | Installed metadata |
| platformdirs | 4.11.3 | Dev only (virtualenv) | MIT | Yes | Installed metadata |
| pluggy | 1.6.0 | Dev only (pytest) | MIT | Yes | Installed metadata |
| pre-commit | 4.6.2 | Dev only | MIT | Yes | Installed metadata |
| pydantic | 2.13.4 | Runtime (direct dependency) | MIT | Yes | Installed metadata |
| pydantic-core | 2.46.4 | Runtime (pydantic) | MIT | Yes | Installed metadata |
| pygments | 2.20.0 | Runtime (rich); also dev (pytest) | BSD-2-Clause | Yes | Installed metadata |
| pytest | 9.1.1 | Dev only | MIT | Yes | Installed metadata |
| pytest-cov | 7.1.0 | Dev only | MIT | Yes | Installed metadata |
| python-discovery | 1.5.2 | Dev only (virtualenv) | MIT | Yes | Installed metadata |
| python-hcl2 | 8.1.2 | Runtime (direct dependency) | MIT | Yes | Installed metadata |
| pyyaml | 6.0.3 | Runtime (direct dependency); also dev (pre-commit) | MIT | Yes | Installed metadata |
| referencing | 0.37.0 | Dev only (jsonschema) | MIT | Yes | Installed metadata |
| regex | 2026.7.19 | Runtime (python-hcl2) | Apache-2.0 AND CNRI-Python | Yes | Installed metadata |
| rich | 15.0.0 | Runtime (typer) | MIT | Yes | Installed metadata |
| rpds-py | 2026.6.3 | Dev only (jsonschema) | MIT | Yes | Installed metadata |
| ruff | 0.16.1 | Dev only | MIT | Yes | Installed metadata |
| shellingham | 1.5.4 | Runtime (typer) | ISC License | Yes | Installed metadata |
| typer | 0.27.1 | Runtime (direct dependency) | MIT | Yes | Installed metadata |
| types-pyyaml | 6.0.12.20260815 | Dev only (type stubs) | Apache-2.0 | Yes | Installed metadata |
| typing-extensions | 4.16.0 | Runtime (pydantic, typer transitively) | PSF-2.0 | Yes | Installed metadata |
| typing-inspection | 0.4.2 | Runtime (pydantic) | MIT | Yes | Installed metadata |
| virtualenv | 21.7.4 | Dev only (pre-commit) | MIT | Yes | Installed metadata |
| controlloop | 0.1.0 | -- (this project) | Apache-2.0 | -- | This decision |

### Findings

- **No strong copyleft dependency exists.** No GPL, AGPL, or LGPL-licensed
  package appears anywhere in the resolved dependency graph, direct or
  transitive, runtime or dev-only.
- **One weak-copyleft runtime dependency: `pathspec` (MPL-2.0).** Mozilla
  Public License 2.0 is a file-level (not project-level) copyleft: it
  requires that modifications to MPL-covered *source files* remain
  available under MPL-2.0, but explicitly permits combining MPL-covered
  files with files under other licenses (including permissive licenses
  like Apache-2.0) in a larger work, and does not require the larger work
  itself to be MPL-licensed. ControlLoop uses `pathspec` as an unmodified
  upstream library dependency -- it is not vendored or modified in this
  repository -- so no MPL-2.0 obligation is triggered beyond what already
  applies to using the unmodified package. MPL-2.0 is on the FSF's and
  OSI's lists of licenses compatible with combination into a larger
  differently-licensed work; it is not a blocker for Apache-2.0
  distribution.
- **One dual-licensed dependency: `packaging` (`Apache-2.0 OR BSD-2-Clause`).**
  Dev-only; either branch of the dual license is independently permissive
  and compatible.
- **One dependency with a bundled historical license: `regex`
  (`Apache-2.0 AND CNRI-Python`).** `regex` incorporates code derived from
  CPython's original regular-expression engine under the CNRI Python
  License, an OSI-approved permissive license, alongside its own
  Apache-2.0 license for the rest of the package. Both components are
  permissive and compatible.
- Every other dependency uses a standard permissive license (MIT,
  BSD-2-Clause/BSD License, ISC, Apache-2.0, or PSF-2.0), all of which are
  straightforwardly compatible with Apache-2.0 distribution.
- **Conclusion: no dependency in `uv.lock` blocks distributing
  ControlLoop under Apache-2.0.**

## Related

- [`LICENSE`](../../LICENSE) -- the applied license text.
- [`CONTRIBUTING.md`](../../CONTRIBUTING.md) -- contribution terms.
