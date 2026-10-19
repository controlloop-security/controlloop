---
type: reference
title: Release notes
tags:
  - reference
  - releases
created: 2026-08-14
---

# Release notes

ControlLoop has not published a scanner release. The repository is in a
development-preview stage: it contains the Python 3.12 package scaffold,
canonical ACBOM foundation, and governing internal guidance, but no supported
scan or gate workflow.

The repository
[changelog](https://github.com/controlloop-security/controlloop/blob/main/CHANGELOG.md)
tracks unreleased implementation and governance changes. Once versioned
artifacts are published, this page should summarize user-visible changes and
link each release to its detailed changelog entry.

A [release pipeline](release-pipeline.md) definition exists and is structurally and unit tested, but it has never actually run --
publishing requires a maintainer to push a real version tag, which has not
happened. See that page for exactly what would happen when it does, and
what it deliberately does not yet publish (PyPI, a container image, and a
Homebrew tap all remain separate and not yet implemented).

Before upgrading a future release, check for:

- CLI, exit-code, configuration, and output compatibility changes;
- ACBOM schema or stable-identity changes;
- adapter version and coverage changes;
- policy rule or rule-pack changes;
- privacy, network, and telemetry changes; and
- known limitations and rollback instructions.
