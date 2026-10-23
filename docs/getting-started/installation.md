---
type: guide
title: Installation
tags:
  - getting-started
  - installation
created: 2026-08-14
updated: 2026-10-23
---

# Installation

Every way to install the ControlLoop CLI, each with the command that
installs it and the command that proves it worked. All of them give you
the same `controlloop` command; pick the one that fits the machine.

| You are on | Use |
| --- | --- |
| A developer machine with Python 3.12 | [uv or pipx](#from-pypi-with-uv-or-pipx) (recommended) |
| A machine without Python | [the shell installer](#the-shell-installer) or [a standalone binary](#a-standalone-binary-by-hand) |
| macOS with Homebrew | [Homebrew](#homebrew) |
| CI, or anywhere with a container runtime | [the container image](#the-container-image) |
| Contributing to ControlLoop | [from source](#from-source) |

Supported platforms are macOS on Apple Silicon and Linux on x86_64 and
arm64; the PyPI package also runs on macOS Intel under Python 3.12.
Windows is not supported. See [Supported platforms](../reference/supported-platforms.md)
for what CI tests on every change.

Installing needs network access to the package index, GitHub Releases or
the container registry. Running the CLI afterwards does not: scanning
makes no network request.

## From PyPI with uv or pipx

The package is [`controlloop` on PyPI](https://pypi.org/project/controlloop/).
It requires Python 3.12 (newer and older interpreters are refused by the
package metadata). With [uv](https://docs.astral.sh/uv/):

```bash
uv tool install controlloop
```

With [pipx](https://pipx.pypa.io/):

```bash
pipx install controlloop
```

Verify:

```bash
controlloop --version
```

```text
ControlLoop 0.1.1
Supported OASF versions: none yet
Agent host key sets (documentation read on): claude-code 2026-10-17, codex 2026-10-17, cursor 2026-10-17, gemini-cli 2026-10-17, kiro 2026-10-17
Rule pack: controlloop-community 0.6.0 (18 rules)
```

The version and rule-pack lines change with each release (the published
0.1.1 reports rule pack 0.5.0; the line above is the current source
tree's); a successful exit and a `ControlLoop <version>` first line is
what matters. If the
shell cannot find `controlloop`, the tool's bin directory is not on your
`PATH`: `uv tool update-shell` or `pipx ensurepath` adds it.

Upgrade with `uv tool upgrade controlloop` or `pipx upgrade controlloop`;
remove with `uv tool uninstall controlloop` or `pipx uninstall controlloop`.

## The shell installer

One command downloads the standalone binary for your platform from the
latest GitHub Release, verifies its checksum against the release's
`SHA256SUMS`, verifies its build-provenance attestation when the GitHub
CLI (`gh`) is installed, and puts it in `~/.local/bin`:

```bash
curl -fsSL https://raw.githubusercontent.com/controlloop-security/controlloop/main/install.sh | bash
```

Real output, recorded on 2026-10-23 on an Apple Silicon Mac:

```text
controlloop-install: installing controlloop-macos-arm64 v0.1.1
controlloop-install: checksum verified: controlloop-macos-arm64
controlloop-install: signature verified: controlloop-macos-arm64 (gh attestation verify)
controlloop-install: installed /Users/you/.local/bin/controlloop
```

Verify:

```bash
controlloop --version
```

A checksum mismatch always aborts the install. Without `gh` the
signature check is skipped with a printed warning and the install
proceeds on the checksum alone. To install a specific version, add
`-s -- --version v0.1.1`; to install somewhere else, set
`CONTROLLOOP_INSTALL_DIR`. Everything the script does, and every
override, is in [Shell installer](../reference/shell-installer.md).

There is no macOS Intel binary, so on an Intel Mac the installer stops and
names the PyPI route instead.

## A standalone binary, by hand

Each [GitHub Release](https://github.com/controlloop-security/controlloop/releases)
carries one single-file executable per platform
(`controlloop-macos-arm64`, `controlloop-linux-x86_64`,
`controlloop-linux-arm64`), a `.sha256` file for each, a combined
`SHA256SUMS`, and a build-provenance attestation. For Linux x86_64, for
example:

```bash
VERSION=v0.1.1
BASE=https://github.com/controlloop-security/controlloop/releases/download/$VERSION
curl -fsSLO "$BASE/controlloop-linux-x86_64"
curl -fsSLO "$BASE/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify controlloop-linux-x86_64 --repo controlloop-security/controlloop
chmod +x controlloop-linux-x86_64
mv controlloop-linux-x86_64 ~/.local/bin/controlloop
controlloop --version
```

`sha256sum --check` prints `controlloop-linux-x86_64: OK`; on macOS use
`shasum -a 256 --check --ignore-missing SHA256SUMS`. The attestation step
needs the GitHub CLI and prints the workflow that built the binary. What
the binaries are, how they are built, and why they are unsigned at the
OS level is in [Standalone binaries](../reference/standalone-binaries.md)
and [Release verification](../reference/release-verification.md).

## Homebrew

```bash
brew install controlloop-security/controlloop/controlloop
controlloop --version
```

The formula installs the same standalone binary as the release, verified
by checksum, on macOS (Apple Silicon) and Linux. It is written by the
release pipeline for each tagged release, starting with the first release
after 2026-10-23; before that release the tap has no formula and `brew`
reports that it does not exist. Details in [Homebrew](../reference/homebrew.md).

## The container image

```bash
docker run --rm --network none -v "$PWD:/work:ro" \
  ghcr.io/controlloop-security/controlloop:<version> scan /work
```

Verify by running it with `--version` in place of `scan /work`. The image
is published for each tagged release starting with the first release
after 2026-10-23, tagged by exact version only; the release notes record
its digest, and `gh attestation verify
oci://ghcr.io/controlloop-security/controlloop:<version> --repo
controlloop-security/controlloop` checks its provenance. What is in the
image, and how CI proves it makes no network request, is in
[Container image](../reference/container-image.md).

## From source

For contributing, or to run an unreleased change:

```bash
git clone https://github.com/controlloop-security/controlloop
cd controlloop
uv sync --locked --all-groups
uv run controlloop --version
```

`--locked` installs exactly the committed lockfile and refuses if it is
stale. Every command is then `uv run controlloop ...`. The version line
shows the version in `pyproject.toml`, which may be ahead of the latest
release. [Contributing](../../CONTRIBUTING.md) covers the checks to
run before a pull request.

## If installation fails

| Symptom | What it means | What to do |
| --- | --- | --- |
| `No solution found` or `requires a different Python` from uv or pipx | No Python 3.12 is available to the tool. | Install Python 3.12 (`uv python install 3.12` works), then retry. |
| `controlloop: command not found` after a successful install | The install directory is not on `PATH`. | `uv tool update-shell`, `pipx ensurepath`, or add `~/.local/bin` to `PATH`, then open a new shell. |
| The shell installer says `unsupported platform` or `unsupported architecture` | Windows, or macOS on Intel. | Use the PyPI route (macOS Intel) or a Linux machine or container (Windows). |
| `checksum mismatch` from the installer or `sha256sum` | The download does not match what the release published. | Do not run it. Retry the download; if it repeats, report it through the [security policy](https://github.com/controlloop-security/controlloop/blob/main/SECURITY.md). |
| `gh: command not found` during verification | The GitHub CLI is not installed. | Install it from <https://cli.github.com>, or accept checksum-only verification for the installer. |
| `manifest unknown` from `docker pull` | No image exists for that tag yet. | Use a version from the release notes that lists a digest. |

See [Troubleshooting](../troubleshooting.md) for problems after
installation.

## Next step

[Quickstart: your first scan](quickstart.md) scans a real agent and
explains the output line by line.
