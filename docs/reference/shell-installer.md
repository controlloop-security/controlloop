---
type: reference
title: Shell installer
tags:
  - reference
  - releases
  - ci
created: 2026-08-23
---

# Shell installer

The first release built and published by this pipeline is [v0.1.1](https://github.com/controlloop-security/controlloop/releases/tag/v0.1.1), 2026-10-20: wheel, sdist, release manifest, the three standalone binaries, their checksums, `SHA256SUMS`, and build-provenance attestations for all of them, with the same wheel and sdist on PyPI. `install.sh` downloads and verifies those assets; a real run
against that release is recorded in
[Installation](../getting-started/installation.md#the-shell-installer).

The goal: one command downloads, verifies, and installs the correct
binary for the user's platform.

## The one-liner

```
curl -fsSL https://raw.githubusercontent.com/controlloop-security/controlloop/main/install.sh | bash
```

Install a specific, pinned version instead of the latest:

```
curl -fsSL https://raw.githubusercontent.com/controlloop-security/controlloop/main/install.sh | bash -s -- --version v0.2.0
```

Both forms use only GitHub's own existing raw-content hosting and
Releases API -- no new domain, hosting provider, or account this
repository does not already use.

## What it does

1. **Detects platform and architecture** from `uname -s`/
   `uname -m`, matching the exact `controlloop-<platform>-<arch>` naming
   [Standalone binaries](standalone-binaries.md) already publishes.
   Windows and macOS x86_64 (Intel) are refused with a clear error before
   any download is attempted -- the same disclosed gaps
   [Standalone binaries](standalone-binaries.md#platform-and-architecture-coverage)
   already documents; no binary exists for either, so this script never
   pretends otherwise.
2. **Resolves a version**: a pinned `--version`/
   `CONTROLLOOP_INSTALL_VERSION` (with or without its leading `v`), or
   the latest published release, queried from the GitHub Releases API.
3. **Downloads the binary and the release's combined `SHA256SUMS` file**
   to a private, self-cleaning temporary directory.
4. **Verifies the checksum** -- always, unconditionally, using
   `sha256sum` or `shasum`, both effectively universal on Linux and
   macOS. Any mismatch, or a `SHA256SUMS` with no entry for the expected
   filename, aborts the install with a clear error. Nothing is installed
   on a checksum failure.
5. **Verifies the signature** -- when the GitHub CLI (`gh`) is on
   `PATH`, runs `gh attestation verify` against the downloaded binary and
   aborts on failure, identical in spirit to step 4. **When `gh` is not
   installed, this script does not silently treat the artifact as fully
   verified.** It prints a clear, disclosed warning that signature
   verification was skipped, points to [Release
   verification](release-verification.md) for how to check it manually,
   and proceeds on the already-passed checksum result alone. See "Why
   checksum verification is mandatory and signature verification is
   best-effort," below, for the reasoning.
6. **Installs with no elevated privileges**: to
   `$HOME/.local/bin` by default (`--install-dir`/
   `CONTROLLOOP_INSTALL_DIR` to override), creating the directory if
   needed. `install.sh` never invokes `sudo` or any other privilege
   escalation, anywhere.
7. **Prints `PATH` guidance** if the install directory is not already on
   `PATH` -- guidance only; this script never edits a shell profile or
   any other configuration file on its own.

Installing the same or a different version over an existing install is
always safe and produces the identical end state: the binary is
simply overwritten, never appended to or duplicated.

## Why checksum verification is mandatory and signature verification is best-effort

`sha256sum`/`shasum` ship with essentially every Linux and macOS system
already. `gh attestation verify` additionally requires the separate
GitHub CLI, which is common but not guaranteed on a machine running a
`curl | bash` one-liner. Requiring `gh` as a hard dependency would
materially hurt the entire point of a one-command installer; silently
skipping signature verification without saying so would violate this
repository's own "unknown, never omitted" invariant -- a downgraded
check must never be presented as equivalent to a full one. This script's
resolution: checksum verification always runs and always gates
installation; signature verification runs and also gates installation
when `gh` is available, and is otherwise disclosed as skipped, never
silently assumed.

This is treated as a normal implementation choice, not a provider
decision: this script selects no new provider at all. It verifies
against the checksum and signature the [release
pipeline](release-verification.md) already produces using GitHub's own
built-in tooling.

## Tested without a live release

`install.sh` is tested in CI without touching a real release, so a test
run can never depend on, or be broken by, what is published. Every
network endpoint it uses is overridable via environment variable
(`CONTROLLOOP_INSTALL_RELEASE_API_URL`, `CONTROLLOOP_INSTALL_BASE_URL`),
defaulting to the real GitHub endpoints.
`tests/test_install_script.py` points these at real synthetic
release files on disk, addressed with `file://` URLs -- `install.sh`
fetches both endpoints with plain `curl -fsSL`, which resolves a
`file://` URL exactly the same way it resolves `http://` (same exit
codes on success and on a missing file), so every real code path --
download, checksum computation, tamper and signature-failure negative
tests -- is exercised faithfully with no listening socket and no
platform-specific networking behavior involved. This runs as part of
the existing `pytest` suite already exercised on all three of this
repository's tested platform/architecture legs
([Supported platforms](supported-platforms.md)), the same "reuse the
existing matrix, do not invent a fourth" precedent the standalone
binaries and release verification already established.

## Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `CONTROLLOOP_INSTALL_VERSION` | (latest) | Pin a specific `vX.Y.Z` release. |
| `CONTROLLOOP_INSTALL_DIR` | `$HOME/.local/bin` | Install location; never requires elevated privileges. |
| `CONTROLLOOP_INSTALL_BASE_URL` | `https://github.com/controlloop-security/controlloop/releases/download` | Advanced/testing only. |
| `CONTROLLOOP_INSTALL_RELEASE_API_URL` | `https://api.github.com/repos/controlloop-security/controlloop/releases/latest` | Advanced/testing only. |
| `CONTROLLOOP_INSTALL_PLATFORM` / `CONTROLLOOP_INSTALL_ARCH` | (from `uname`) | Advanced/testing only -- overrides `uname`'s own output, still validated the same way. |

## What this does not do

- **No artifact has ever been published anywhere**, so this script has
  never actually installed a real release. See [Release
  pipeline](release-pipeline.md) for the same disclosure at the pipeline
  level.
- **No package-manager installation.** PyPI, a container image, and a
  Homebrew tap are separate, not-yet-implemented work, blocked on
  registering the `controlloop` name on each.
- **No shell-profile editing.** This script only prints `PATH` guidance;
  it never modifies `.bashrc`, `.zshrc`, or any other configuration file.
- **No Windows support**, unchanged from this repository's existing
  platform scope.

## Next steps

- Review [Release verification](release-verification.md) for the
  checksum and signature this script relies on.
- Review [Standalone binaries](standalone-binaries.md) for the binaries
  this script installs.
