---
type: guide
title: Install the development preview
tags:
  - getting-started
  - installation
created: 2026-08-14
---

# Install the development preview

Install the current repository package to verify your environment and follow
ControlLoop's implementation as it grows. This is a source installation for
contributors and evaluators, not a released scanner.

> **Current availability:** the installed command supports `--help`,
> `--version`, `init`, `bom`, `diff`, `scan`, and `gate`. `scan` and `gate`
> discover a repository, build its ACBOM, and evaluate policy; `gate` is the
> noninteractive CI-facing form. `auth` and `rules` are described in internal
> product contracts but are not implemented.

## Prerequisites

- macOS (arm64/Apple Silicon) or Linux (x86_64 or arm64). Windows support
  is outside the first-release requirements. See
  [Supported platforms](../reference/supported-platforms.md) for exactly
  what this repository's own CI tests on every change.
- Python 3.12.
- [`uv`](https://docs.astral.sh/uv/) for the locked environment.
- A local clone of the ControlLoop repository.

Installation does not require credentials, a cloud account, or a ControlLoop
service. Dependency download requires network access; running the current
commands after setup does not.

## Install from the repository

From the repository root:

```bash
cd cli
uv sync --locked --all-groups
```

The lockfile selects the exact development dependencies. A successful run
creates `cli/.venv` and installs the local `controlloop` package into it.

Verify the command:

```bash
uv run controlloop --version
```

Expected output:

```text
ControlLoop 0.1.0
```

The version will change as releases advance. The important result is a
successful exit and one version line on standard output.

## If installation fails

| Symptom | What it means | What to do |
| --- | --- | --- |
| Python 3.12 cannot be found | The required interpreter is unavailable to `uv`. | Install Python 3.12, confirm `python3.12 --version`, and rerun `uv sync --locked --all-groups`. |
| The lockfile is reported out of date | Project metadata and the committed lockfile differ. | Do not bypass `--locked`. Confirm you are on the intended branch and report the mismatch. |
| A dependency cannot be downloaded | Initial setup cannot reach the package index or a proxy is blocking it. | Restore approved package-index access and retry. Do not add an unpinned dependency as a workaround. |
| `controlloop` is not found | The command is being run outside the managed environment. | Run it as `uv run controlloop ...` from `cli/`. |

See [Troubleshooting](../troubleshooting.md) for command and environment checks.

## Next step

[Run the current quickstart](quickstart.md) to scan a repository, generate an
ACBOM, and see how an unavailable subcommand fails.
