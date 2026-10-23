---
type: reference
title: Release notes
tags:
  - reference
  - releases
created: 2026-08-14
---

# Release notes

Each release is one `vX.Y.Z` tag, built and published by the
[release pipeline](release-pipeline.md). Its user-visible changes are the
matching section of the repository
[changelog](https://github.com/controlloop-security/controlloop/blob/main/CHANGELOG.md),
which the release notes on GitHub reproduce verbatim.

| Release | Date | Published |
| --- | --- | --- |
| [v0.1.1](https://github.com/controlloop-security/controlloop/releases/tag/v0.1.1) | 2026-10-20 | Wheel and sdist (also on [PyPI](https://pypi.org/project/controlloop/0.1.1/)); standalone binaries for macOS arm64, Linux x86_64 and Linux arm64 with checksums and build-provenance attestations. |

A container image and a Homebrew formula are published from the first
release after 2026-10-23; see [Container image](container-image.md) and
[Homebrew](homebrew.md).

Before upgrading a future release, check for:

- CLI, exit-code, configuration, and output compatibility changes;
- ACBOM schema or stable-identity changes;
- adapter version and coverage changes;
- policy rule or rule-pack changes;
- privacy, network, and telemetry changes; and
- known limitations and rollback instructions.
