---
type: guide
title: Troubleshooting
tags:
  - troubleshooting
  - getting-started
created: 2026-08-14
---

# Troubleshooting

Start with the smallest verified command, such as `--version` or `--help`,
before moving on to a `scan` or `gate` run.

## `uv` cannot find Python 3.12

Check the interpreter:

```bash
python3.12 --version
```

ControlLoop currently requires Python 3.12. Install that interpreter and rerun
the locked setup from `cli/`:

```bash
uv sync --locked --all-groups
```

Do not remove the Python constraint or regenerate the lockfile merely to work
around a missing local interpreter.

## Dependency setup cannot reach the package index

The first `uv sync` downloads locked dependencies from the configured package
index. Check approved network, DNS, proxy, and certificate settings, then retry
the same locked command.

This download is an installation requirement, not a ControlLoop telemetry or
repository-upload operation. After installation, the current `--help` and
`--version` options make no ControlLoop network request.

## `controlloop` is not found

Run the command through the managed environment from `cli/`:

```bash
uv run controlloop --version
```

If that still fails, rerun `uv sync --locked --all-groups` and inspect its first
error. Avoid installing an unpinned package with a separate `pip` command;
doing so would no longer match the repository lockfile.

## Running with no arguments exits with code 2

This is expected current behavior. The CLI shows help but has no default
operation. Use an explicit available option:

```bash
uv run controlloop --help
uv run controlloop --version
```

## `No such command 'auth'` or `'rules'`

`init`, `bom`, `diff`, `scan`, and `gate` are real, implemented commands.
`auth` and `rules` are described in internal product contracts but are not
current commands at all -- invoking either produces exactly this "No such
command" error.

Check the [CLI reference](reference/cli.md) for every command that exists
rather than inferring one from an example elsewhere.

## Help output looks different from an example

Terminal width, color support, and rendering can change spacing and border
characters. Verify the product-purpose line and option names instead of
comparing the decorative layout byte for byte.

Version output is stricter: it should be one line in the form
`ControlLoop <version>` with no standard-error text.

## Reporting a problem safely

Include:

- operating system and architecture;
- `python3.12 --version`;
- `uv --version`;
- `uv run controlloop --version`;
- the exact command and exit code; and
- a short, synthetic reproduction.

Do not attach source files, prompts, credentials, tokens, environment-variable
values, customer data, or proprietary configuration. Follow the repository
[security policy](../SECURITY.md) for vulnerabilities.

## Next step

Return to [Installation](getting-started/installation.md), or consult the
[current CLI reference](reference/cli.md) to confirm whether the attempted
operation is available.
