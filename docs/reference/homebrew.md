---
type: reference
title: Homebrew
tags:
  - reference
  - distribution
created: 2026-10-23
---

# Homebrew

The tap `controlloop-security/controlloop` (repository
[`controlloop-security/homebrew-controlloop`](https://github.com/controlloop-security/homebrew-controlloop))
carries one formula, `controlloop`, written by the release pipeline for
every tagged release.

```bash
brew install controlloop-security/controlloop/controlloop
controlloop --version
```

## What the formula installs

The formula downloads the standalone binary the release already published
on its GitHub Release page and checks it against the checksum the release
pipeline recorded, so the binary Homebrew installs is byte-for-byte the one
`gh attestation verify` can verify (see
[Release verification](release-verification.md)).

| Platform | Binary installed |
| --- | --- |
| macOS, Apple Silicon | `controlloop-macos-arm64` |
| Linux, x86_64 | `controlloop-linux-x86_64` |
| Linux, arm64 | `controlloop-linux-arm64` |

macOS on Intel has no binary; the reasons are in
[Standalone binaries](standalone-binaries.md). On an Intel Mac the
formula stops with a message naming the alternative, `uv tool install
controlloop` or `pipx install controlloop`, rather than failing inside
Homebrew.

The formula declares the project's license (`Apache-2.0`) and homepage
(`https://controlloop.ai`), and its `test` block runs the installed binary
against a small synthetic repository and checks the verdict.

## How a release updates it

`release-scripts/homebrew_formula.py` renders the formula from the
release version and the release's own combined `SHA256SUMS` file; it
refuses to render if any binary's checksum is missing, so a formula can
never ship with a hole in it. The `publish-homebrew` job in
`.github/workflows/release.yml` then writes `Formula/controlloop.rb` to
the tap repository through the GitHub API, after the GitHub Release
exists. The tap's own CI installs the new formula on macOS (Apple
Silicon) and Linux, runs `brew test` and a real scan, and audits the
formula.

The job needs two things set once in this repository's settings, by a
maintainer:

- the variable `HOMEBREW_TAP_REPOSITORY`, `controlloop-security/homebrew-controlloop`;
- the secret `HOMEBREW_TAP_TOKEN`, a fine-grained token for that one
  repository with contents read and write.

Without the variable the job is skipped and the rest of the release is
unaffected. This is the one credential the release pipeline stores; every
other publication uses GitHub's own short-lived tokens.

## Verifying what Homebrew installed

```bash
gh attestation verify "$(brew --prefix controlloop)/bin/controlloop" \
  --repo controlloop-security/controlloop
```

## Next steps

- [Installation](../getting-started/installation.md) for every install
  path side by side.
- [Standalone binaries](standalone-binaries.md) for how the binaries are
  built and what "reproducible" means for them.
