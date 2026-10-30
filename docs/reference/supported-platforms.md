---
type: reference
title: Supported platforms
tags:
  - reference
  - ci
  - platforms
created: 2026-08-21
---

# Supported platforms

The goal: "every supported platform and architecture is tested on every
change, not only at release." This page states, honestly, exactly
what is tested and what is not -- nothing here claims coverage this
repository's own CI does not actually run.

## Tested on every pull request and every release tag

The full verified command surface (`uv sync --locked --all-groups`,
formatting, lint, type checking, the whole `pytest` suite, and `uv build`)
runs on all three of these real GitHub-hosted runner legs, via
`.github/workflows/verify.yml`'s own build matrix:

| Platform | Architecture | Runner label |
| --- | --- | --- |
| Linux | x86_64 | `ubuntu-latest` |
| Linux | arm64 | `ubuntu-24.04-arm` |
| macOS | arm64 (Apple Silicon) | `macos-26` |

A failure on any one of these legs fails that leg's own check and blocks
merge -- `fail-fast` is disabled so every leg reports independently rather
than the first failure cancelling the rest.

`tests/test_gate_determinism_regression.py`'s
`TestGoldenDigestIsArchitectureIndependent` asserts one literal, hardcoded
digest for a fixed synthetic fixture with no platform-conditional skip.
Because every leg above runs the exact same test suite, all three legs
passing that one assertion is the proof that the same fixture produces
identical scan output across the matrix.

## Not tested, and why

### macOS x86_64 (Intel)

**Disclosed gap, not an oversight.** As of the current
[`actions/runner-images`](https://github.com/actions/runner-images)
catalog (checked directly on 2026-08-21), every GitHub-hosted macOS x86_64
image label is `-large` or `-intel` only -- standard, free-tier
GitHub-hosted macOS runners are Apple Silicon (arm64) only. Intel macOS
coverage now requires GitHub's paid "larger runners" tier. Enabling paid
usage is a maintainer decision; this project does not enable it without
that explicit authorization.

### Windows

**Explicitly unsupported**, per this repository's own scope:
Windows support has never been part of this milestone. It is not tested,
and no ControlLoop documentation or release artifact should ever imply it
is.

This exact same three-leg matrix (not a separately maintained one) also
determines which standalone-binary platform/architecture combinations
`.github/workflows/release.yml`'s `build-binaries` job produces -- see
[Standalone binaries](standalone-binaries.md) for
that job's own disclosure, including why macOS x86_64 (Intel) has no
binary for the identical reason it has no pull-request testing leg here.

## Next steps

- Review the [CLI reference](cli.md) for the commands this matrix verifies.
- Review [Golden baselines](golden-baselines.md) for the end-to-end
  determinism fixtures this matrix now proves across real, separate
  machines rather than one developer's own environment plus a single CI
  runner.
- Review [Standalone binaries](standalone-binaries.md) for the
  binary-build job that reuses this same platform/architecture matrix.
