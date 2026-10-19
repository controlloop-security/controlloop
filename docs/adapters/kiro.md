---
type: reference
title: Kiro
tags:
  - reference
  - adapters
  - agent-hosts
created: 2026-10-17
---

# Kiro

**Availability:** implemented. Files are read, never run.

## Files read

`.kiro/hooks/*.json` (and legacy `*.kiro.hook`), and `.kiro/agents/*.json`.
`.kiro/settings/mcp.json` is recorded by the MCP adapter: its
`autoApprove` lists become per-tool approvals, attached to the same Kiro
host.

## What is recorded

| Setting | Recorded as |
| --- | --- |
| A hook with `action.type: command` | A hook, code execution, with its command and trigger. |
| A hook with `action.type: agent` | A hook of type `agent`. Its prompt is never recorded. |
| `confirm.confirmCommand`, `confirm.options[].run` | Helper commands: code execution. |
| A legacy `.kiro.hook` file | A hook from `when.type` and `then`; `runCommand` is code execution. |
| `allowedTools`, `permissions.rules`, `toolsSettings.shell.allowedCommands` in an agent file | Rules. A rule on `all`, `builtin`, or `filesystem`, or without a `match`, is a wildcard. |

## What becomes unknown

An undocumented trigger, or a legacy `then.type` other than `runCommand`
or `askAgent`, against the documentation as read on **2026-10-17**, is
reported as `INCOMPLETE-UNRECOGNIZED-KEY`.

## What is not read

Steering files; `~/.kiro/`, including the user and workspace
`permissions.yaml`, which Kiro keeps outside the repository.
