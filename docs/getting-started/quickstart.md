---
type: guide
title: Current CLI quickstart
tags:
  - getting-started
  - cli
created: 2026-08-14
---

# Current CLI quickstart

This quickstart confirms that the development-preview package is installed,
scans a repository, and generates an ACBOM. It also shows how a genuinely
unavailable subcommand fails.

## Before you begin

Complete [Installation](installation.md). Run the commands below from the
repository's `cli/` directory, against a local repository you want to
inspect (or this repository itself).

## 1. Confirm the installed version

```bash
uv run controlloop --version
```

Expected output for the current repository version:

```text
ControlLoop 0.1.0
Supported OASF versions: none yet
Agent host key sets (documentation read on): claude-code 2026-10-17, codex 2026-10-17, cursor 2026-10-17, gemini-cli 2026-10-17, kiro 2026-10-17
Rule pack: controlloop-community 0.6.0 (18 rules)
```

This proves that `uv` can invoke the package entry point.

## 2. Inspect the available surface

```bash
uv run controlloop --help
```

Spacing, color, and border characters can vary by terminal, but the output
includes these stable facts: a usage line
(`Usage: controlloop [OPTIONS] COMMAND [ARGS]...`), the product-purpose line
(`Inspect and gate AI agent capabilities.`), and five listed commands, each
with a one-line description:

| Command | One-line description |
| --- | --- |
| `init` | Discover candidate agents and draft a reviewable security manifest. |
| `bom` | Generate or validate an Agent Capability Bill of Materials. |
| `diff` | Compare two ACBOMs, or the repository against a baseline. |
| `scan` | Discover, build the ACBOM, evaluate policy, and report results. |
| `gate` | Evaluate policy noninteractively and return a deterministic verdict for CI. |

## 3. Generate an ACBOM

```bash
uv run controlloop bom
```

This discovers candidate agents in the current repository (or the nearest
enclosing git repository) and writes a canonical ACBOM document to standard
output. Add `--output acbom.json` to write it to a file instead, or
`--validate acbom.json` to validate an existing document.

## 4. Scan for policy findings

```bash
uv run controlloop scan
```

This runs the same discovery as `bom`, evaluates every registered policy
rule, and renders a human-readable report. Exit code `0` means a clean pass
or a pass with only warnings; `1` means a finding met or exceeded the
configured severity threshold; `3` means analysis was incomplete with
nothing blocking. Use `--format json` or `--format sarif` for machine
output. See the [CLI reference](../reference/cli.md#scan) for the full
report shape and every registered rule.

## 5. Gate a repository for CI

```bash
uv run controlloop gate
```

`gate` composes the identical discovery, baseline, and policy pipeline
`scan` uses, adds a four-state pass/warn/require-review/fail verdict, and
unconditionally writes a retainable evidence artifact (`evidence.json` by
default). It never prompts and never reads standard input, so it is safe to
run noninteractively in CI. See the [CLI reference](../reference/cli.md#gate)
for `--evidence-path`, `--sarif-path`, and completeness-enforcement details.

## 6. See what a change gives an agent

On a branch, `scan` and `gate` compare the repository with its merge base
and lead with the authority statement when the change hands a coding
agent new power. This is a real run, recorded on 2026-10-17, in a
repository whose `add-hook` branch adds a `SessionStart` hook to
`.claude/settings.json`:

```bash
git switch add-hook
uv run controlloop scan .
```

```text
! WORST REACHABLE  code-execution: Claude Code can invoke SessionStart command
  hook

✕ DEPLOYMENT BLOCKED

Authority:
  • This change gives Claude Code the power to run `node .github/setup.js` on
    every session start (`.claude/settings.json`, hook `SessionStart`). No
    approval is recorded.

• GAINED  code-execution: Claude Code invokes SessionStart command hook

✕ HIGH     policy.agent-hook-command-change: Added: Hook on event 'SessionStart'
  for host 'Claude Code' runs `node .github/setup.js`.
    at .claude/settings.json

Suppressions: none declared
```

It exits `1`. A change that grants no agent new power prints no
`Authority:` section at all. See [the authority statement](../reference/authority-statement.md)
for every grant it describes, and
[what a passing gate does not guarantee](../reference/agent-authority-limits.md)
before relying on a pass.

## 7. Recognize a genuinely unavailable command

Do not use this as a command:

```bash
uv run controlloop auth
```

It exits with code `2` and reports:

```text
No such command 'auth'.
```

`auth` is described in internal product contracts but is not
implemented; invoking it produces this exact "No such command" error,
identical to any other unrecognized subcommand.

That is expected in the development preview. Do not substitute the schema
model or a test fixture for user-facing scanner output, and do not treat a
successful `bom`/`scan`/`gate` run against a tiny or synthetic repository as
proof of behavior against a large or adversarial one.

## Expected results

| Check | Exit code | Meaning |
| --- | ---: | --- |
| `controlloop --version` | 0 | The package entry point and installed version are available. |
| `controlloop --help` | 0 | The current options and subcommands can be rendered. |
| `controlloop` with no arguments | 2 | Help is shown, but no operation was selected. |
| `controlloop bom` | 0 | An ACBOM was generated (or `2` if the repository path or configuration is invalid). |
| `controlloop scan` | 0, 1, or 3 | Depends on the scan's findings and completeness -- see step 4 above. |
| `controlloop gate` | 0, 1, or 3 | Depends on the gate verdict -- see [Exit codes](../reference/cli.md#exit-codes). |
| `controlloop auth` | 2 | The requested subcommand does not exist. |

## Privacy and network behavior

`bom`, `init`, `diff`, `scan`, and `gate` inspect only the repository you
point them at and make no ControlLoop network request; `diff`, `scan`, and
`gate` additionally read local git plumbing only (never `git fetch` or a
remote URL) to resolve a baseline. Initial dependency installation can
access the configured Python package index. The approved scanning design is
local first and offline, and every currently implemented command follows it.

## Next steps

- Read [The ACBOM and capability evidence](../concepts/acbom.md) to understand
  the product model.
- Use the [CLI reference](../reference/cli.md) for the complete current surface.
