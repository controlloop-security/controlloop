---
type: reference
title: Codex
tags:
  - reference
  - adapters
  - agent-hosts
created: 2026-10-17
---

# Codex

**Availability:** implemented. Files are read, never run.

## Files read

`.codex/config.toml` and `.codex/hooks.json`. MCP servers declared under
`[mcp_servers]` are recorded by the MCP adapter, attached to the same
Codex host.

## What is recorded

| Setting | Recorded as |
| --- | --- |
| `approval_policy` | Host attribute. `never` sets the bypass flag; a `granular` table is recorded as `granular`. Order, strictest first: `untrusted`, `on-request`, `on-failure`, `never` (the first and third are retired or deprecated in current Codex, and kept for older files). |
| `sandbox_mode` | Host attribute: `read-only`, `workspace-write`, `danger-full-access`. The last sets the bypass flag. |
| `default_permissions` | Host attribute: `:read-only`, `:workspace`, `:danger-full-access`. The last sets the bypass flag. |
| `sandbox_workspace_write.network_access` | Host attribute. |
| `projects.*.trust_level` | The set of trust levels, as one host attribute. |
| `hooks` (inline or in `hooks.json`) | One hook per handler, as for Claude Code. Events: `PreToolUse`, `PermissionRequest`, `PostToolUse`, `PreCompact`, `PostCompact`, `SessionStart`, `SessionEnd`, `SubagentStart`, `SubagentStop`, `UserPromptSubmit`, `Stop`, `Interrupt`. |
| `mcp_servers.*.http_headers_helper`, `model_providers.*.auth.command` | Helper commands: code execution. |
| `notify`, `profile`, `profiles`, `model_provider`, `model_providers` | Recorded as present. Codex ignores them in project configuration. |

## What becomes unknown

The recognized keys are Codex's configuration reference as read on
**2026-10-17**. Any other top-level key, an undocumented hook event, or
an `approval_policy`, `sandbox_mode`, or `default_permissions` value off
the scale is reported as `INCOMPLETE-UNRECOGNIZED-KEY`. A file that is
not valid TOML or JSON is `INCOMPLETE-UNPARSED-REGION`.

## What is not read

`AGENTS.md` and other instruction files; `~/.codex/`; profile files
outside the repository.
