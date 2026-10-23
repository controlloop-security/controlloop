---
type: guide
title: "Quickstart: your first scan"
tags:
  - getting-started
  - cli
created: 2026-08-14
updated: 2026-10-23
---

# Quickstart: your first scan

In a few minutes you will scan a real agent, read what ControlLoop says
about it, and run the same scan on a repository of your own. Nothing
leaves your machine: `scan` reads the repository you point it at and makes
no network request.

## Before you begin

Install the CLI ([Installation](installation.md)) and confirm it runs:

```bash
controlloop --version
```

```text
ControlLoop 0.1.1
Supported OASF versions: none yet
Agent host key sets (documentation read on): claude-code 2026-10-17, codex 2026-10-17, cursor 2026-10-17, gemini-cli 2026-10-17, kiro 2026-10-17
Rule pack: controlloop-community 0.6.0 (18 rules)
```

You also need `git`, which `scan` uses to compare a branch with its base.

## 1. Scan an agent

The public [reference agent](https://github.com/controlloop-security/controlloop-reference-agent)
is a realistic, deliberately imperfect customer-support agent built for
exactly this. Clone it and scan one scenario directory (always a scenario
directory, never the repository root):

```bash
git clone https://github.com/controlloop-security/controlloop-reference-agent
controlloop scan controlloop-reference-agent/scenarios/order-support-agent
```

Real output, recorded on 2026-10-23 with ControlLoop 0.1.1:

```text
! WORST REACHABLE  financial-action: widgetworks-order-support-agent can invoke
  Issue a refund

✓ PASSED

• material change: not evaluated

! MEDIUM   policy.undeclared-tools: Tool 'Look up an order' is reachable but not
  declared in controlloop.yaml.
    at agent-card.json

! MEDIUM   policy.undeclared-tools: Tool 'Reply to customer' is reachable but
  not declared in controlloop.yaml.
    at agent-card.json

! MEDIUM   policy.undeclared-tools: Tool 'Issue a refund' is reachable but not
  declared in controlloop.yaml.
    at agent-card.json

Suppressions: none declared
```

The command exits `0`.

## 2. Read the result, top to bottom

**The first line is the blast radius.** `WORST REACHABLE` names the most
consequential thing any agent in this repository can do, and the path to
it: the agent `widgetworks-order-support-agent` can invoke the tool `Issue
a refund`, which is a financial action. This is stated before any
finding, because it is what a reviewer needs to know first.

**The verdict.** `✓ PASSED` means nothing met the severity threshold
(`high` by default). The other verdicts are `PASSED WITH WARNINGS`,
`REVIEW REQUIRED` and `DEPLOYMENT BLOCKED`.

**Material change.** On a branch, `scan` compares the repository with the
branch's base and reports capabilities the change added or removed. Here
the scan ran on the default branch, so there is nothing to compare and it
says so rather than claiming "no change".

**Findings.** Each one names the rule (`policy.undeclared-tools`), its
severity, what it saw, and the file it saw it in. These three say that
the agent card declares tools that the repository's `controlloop.yaml` has
not acknowledged. They are `MEDIUM`, below the default threshold, so they
are reported but do not change the verdict.

**Suppressions.** A repository can suppress a finding for a stated reason
and a limited time in `controlloop.yaml`; the scan always says whether any
were applied. None were.

## 3. See what a change gives an agent

The same scan on a branch explains the change rather than the whole
repository. The reference agent keeps one scenario per branch; this one
adds a bulk-refund tool:

```bash
git -C controlloop-reference-agent switch -c capability-expansion origin/scenario/capability-expansion
controlloop scan controlloop-reference-agent/scenarios/order-support-agent
```

```text
! WORST REACHABLE  destructive-action: widgetworks-order-support-agent can
  invoke Bulk refund orders

✕ DEPLOYMENT BLOCKED

• material change: not evaluated

✕ HIGH     policy.destructive-or-financial-action: Agent gained new direct
  invokes access to 'Bulk refund orders', classified as destructive-action and
  financial-action.
    at agent-card.json
```

(The four `MEDIUM` undeclared-tool findings follow as before.) The command
exits `1`. The blast radius got worse, from a financial action to a
destructive one, and the `HIGH` finding objects to authority the branch
*adds*, not to refunds existing. Switch back with
`git -C controlloop-reference-agent switch main`.

## 4. Scan your own repository

```bash
controlloop scan /path/to/your/repository
```

`scan` looks for the agent definitions it understands: agent cards, MCP
server configurations, Claude Code, Codex, Cursor, Gemini CLI and Kiro
settings, agent-running GitHub workflows, and CrewAI, LangGraph and
OpenAI Agents SDK code. [Adapter status](../adapters/readme.md) lists
each format and how completely it is read. A repository with none of them
scans clean, which is a fact about discovery, not a security verdict; see
[what a passing gate does not guarantee](../reference/agent-authority-limits.md).

Useful variations:

| Command | What it does |
| --- | --- |
| `controlloop scan . --format json` | The same report as data, for scripts and dashboards ([format](../reference/report-format.md)). |
| `controlloop scan . --format sarif` | For code-scanning tools that read SARIF. |
| `controlloop bom .` | Only the capability graph (the ACBOM), no policy ([concepts](../concepts/acbom.md)). |
| `controlloop rules` | Every rule in the rule pack and what it looks for. |
| `controlloop init .` | Draft a `controlloop.yaml` from what is actually in the repository, so the undeclared-tool findings above become declarations. |

## 5. Exit codes

| Exit code | Meaning |
| ---: | --- |
| `0` | Passed, or passed with warnings only. |
| `1` | A finding met or exceeded the severity threshold. |
| `2` | Usage or configuration error (a path that does not exist, an invalid manifest). |
| `3` | Analysis was incomplete and nothing blocking was found. |

The full list, including the gate's review verdict, is in the
[CLI reference](../reference/cli.md#exit-codes).

## Privacy and network behavior

`scan`, `bom`, `init`, `diff` and `gate` read only the repository you point
them at, use local git plumbing to find a baseline (never `git fetch` or a
remote URL), and make no ControlLoop network request. Source code, prompt
bodies, secret values and environment values never appear in the output.
See [Privacy, security and limitations](../reference/privacy-security.md).

## Next steps

- [Quickstart: your first CI gate](first-ci-gate.md) makes the same
  analysis block a pull request.
- [The example walkthrough](../guides/example-walkthrough.md) goes through
  a scan line by line, or run `controlloop example` for the same tour in
  the terminal.
- [The ACBOM and capability evidence](../concepts/acbom.md) explains the
  model behind the output.
