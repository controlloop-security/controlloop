---
type: reference
title: Standalone binaries
tags:
  - reference
  - releases
  - ci
created: 2026-08-21
---

# Standalone binaries

**No standalone binary has ever been published.** This page describes what
`.github/workflows/release.yml`'s `build-binaries` job does when a
maintainer pushes a real tag matching `v*.*.*` -- that job has never
actually run as part of a real release, because no release has ever been
published (see [Release pipeline](release-pipeline.md)). Nothing on this
page is a claim that a downloadable ControlLoop executable is available
today.

The goal: a single downloadable executable for macOS and Linux, on
x86_64 and arm64, requiring no Python.

## What triggers it

The `build-binaries` job runs on every push of a tag matching `v*.*.*`,
as one job inside `.github/workflows/release.yml`, alongside the
distribution-package (`uv build`) and GitHub Release publishing jobs
the [release pipeline](release-pipeline.md) already defines. It never
runs on a pull request or an
ordinary branch push, and nothing in this repository ever pushes a tag on
its own.

## What it does, per platform/architecture leg

For each of three real, free-tier GitHub-hosted runner legs -- the exact
same three `.github/workflows/verify.yml` already tests every pull
request on, see [Supported platforms](supported-platforms.md) -- the job:

1. **Builds** one single-file executable with PyInstaller
   (`release-scripts/build_binary.py`), named `controlloop-<platform>-
   <arch>` (for example `controlloop-linux-x86_64`), bundling the real
   `.py` source of every `controlloop.policy.rules` module alongside the
   compiled bytecode. That bundling step is not cosmetic: without it,
   `controlloop.policy.engine`'s own runtime rule-safety check (which
   inspects each active rule module's source before evaluating it) fails
   with an internal error on every `scan`/`gate` invocation of an
   unmodified PyInstaller onefile build, since PyInstaller's default
   bundle ships compiled bytecode only. This was reproduced for real
   while building the binary locally.
2. **Smoke-tests it** by running the real built binary's
   `--version`, then a real `controlloop scan` against a small synthetic
   fixture repository, and checking the verdict is `passed`.
3. **Rebuilds it a second time and diffs scan output**: a fresh
   PyInstaller invocation of the same commit, then the identical scan
   again, asserting the two runs' JSON output is byte-identical. The two
   binaries' own bytes are *not* asserted identical -- PyInstaller embeds
   a fresh build UUID and absolute temp-directory metadata into its
   bootloader on every invocation, a well-known PyInstaller property, not
   a determinism defect in ControlLoop's own scan logic. "Reproducible
   enough" means identical scan output, not identical binary bytes.
4. **Uploads** the binary and a `sha256` checksum file as a build
   artifact.

Only if every one of those legs succeeds, and the tag's changelog gate and
full verification suite also pass, does `publish-github-release` attach all
three binaries and their checksums to the GitHub Release -- the same job the
release pipeline already gates behind `verify`, `changelog-gate`, and
`package`.

## Platform and architecture coverage

| Platform | Architecture | Runner label | Built? |
| --- | --- | --- | --- |
| Linux | x86_64 | `ubuntu-latest` | Yes |
| Linux | arm64 | `ubuntu-24.04-arm` | Yes |
| macOS | arm64 (Apple Silicon) | `macos-15` | Yes |
| macOS | x86_64 (Intel) | -- | **No -- disclosed gap** |

**macOS x86_64 (Intel) is a disclosed gap, not an oversight**, for the
identical reason [Supported platforms](supported-platforms.md) already
documents for pull-request testing: every current free-tier
GitHub-hosted macOS runner image is Apple Silicon (arm64) only. Building
a real Intel macOS binary would require GitHub's paid "larger runners"
tier, or a maintainer's own Intel Mac. Enabling paid CI usage is a
billing decision for the maintainers; this pipeline does not enable it
on its own. PyInstaller cannot cross-compile -- an arm64 runner
cannot produce a real x86_64 macOS binary -- so this gap cannot be
closed by reconfiguring the existing job.

Windows is out of scope for the first release (see [Supported
platforms](supported-platforms.md)).

## Smoke testing

Each leg's own smoke-test step is a real, not simulated, `controlloop
scan` against a small synthetic fixture directory (one fabricated
`agent-card.json` -- never a real repository, credential, or customer
content), asserting the returned verdict is `passed`. This runs on the
binary's own native platform/architecture -- PyInstaller cannot
cross-compile, so a Linux arm64 runner's own binary is smoke-tested on
that same Linux arm64 runner, never emulated or cross-tested elsewhere.

## Signing and notarization

**The macOS binary is neither signed nor notarized.** PyInstaller's own
build log records this explicitly for every macOS build
(`Code signing identity: None`). Consequence for a user: macOS
Gatekeeper will refuse to run an unsigned, unnotarized downloaded
executable by default, presenting an "unidentified developer" or
"cannot be opened" warning, until the user explicitly overrides it
(for example via **System Settings > Privacy & Security**, or `xattr -d
com.apple.quarantine` on the downloaded file). Signing and notarization
require an active Apple Developer Program membership and its associated
signing certificate and notarization credentials -- a paid, ongoing
commitment for the maintainers to make, not something this pipeline
provisions on its own. Linux binaries are
similarly unsigned; Linux has no OS-level equivalent to Gatekeeper
blocking an unsigned executable by default.

## Reproducibility

"Reproducible enough that two builds of one commit produce identical
scan output" is proven two ways:

- **In this pipeline itself**, per leg, by the "Reproducibility" step
  described above -- a real second build, a real second scan, and a
  real byte-for-byte diff of the two scans' JSON output.
- **In this repository's own test suite**,
  `tests/test_build_binary_script.py`'s
  `TestRealBuildEndToEnd`, which performs the identical two-build,
  two-scan, diff sequence locally against this repository's own source
  tree, plus a `--version` invocation with the binary's own real
  interpreter isolated from any Python on `PATH` (the closest this test
  suite can get to proving "requiring no Python" without provisioning a
  second, Python-free machine image).

Byte-identical *binaries* are explicitly not claimed or tested -- see
"What it does," step 3, above.

## What this does not do

- **No binary has ever been published anywhere.** No release tag has
  ever been pushed; see [Release
  pipeline](release-pipeline.md) for the same disclosure at the pipeline
  level.
- **No package-manager formula.** PyPI, a container image, and a
  Homebrew tap are separate, not-yet-implemented work, blocked on
  registering the `controlloop` name on each. A one-command shell
  installer that
  downloads, verifies, and installs the right binary does now exist --
  see [Shell installer](shell-installer.md).
- **No Windows binary**, unchanged from this repository's existing
  platform scope.
- **No macOS x86_64 (Intel) binary** -- see "Platform and architecture
  coverage" above.

## Next steps

- Review [Release pipeline](release-pipeline.md) for the surrounding
  tag-triggered workflow this job is one part of.
- Review [Shell installer](shell-installer.md) for the one-command
  installer that downloads, verifies, and installs one of these
  binaries.
- Review [Supported platforms](supported-platforms.md) for the identical
  runner-coverage reasoning applied to pull-request testing.
