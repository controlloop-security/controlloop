---
type: reference
title: Cursor
tags:
  - reference
  - adapters
  - agent-hosts
created: 2026-10-17
---

# Cursor

**Availability:** implemented. Files are read, never run.

## Files read

`.cursor/hooks.json`, `.cursor/environment.json`, and `.cursor/cli.json`.
MCP servers in `.cursor/mcp.json` are recorded by the MCP adapter,
attached to the same Cursor host.

## What is recorded

| Setting | Recorded as |
| --- | --- |
| `hooks.<event>[]` in `hooks.json` | One hook per entry, as code execution with its command. |
| `install`, `start`, `terminals[].command` in `environment.json` | Helper commands: code execution, run when a cloud agent's environment is built and started. |
| `build.dockerfile`, `build.dockerfileContents` | A build helper; an inline Dockerfile is recorded only as present. |
| `egressMode` | Host attribute. Order, strictest first: `network_settings_only`, `default_with_network_settings`, `parent_plus_network_settings`, `allow_all` (read from the schema's descriptions; the documentation does not state an order). |
| `agentCanUpdateSnapshot: true` | Host attribute. |
| `permissions.allow`, `permissions.deny` in `cli.json` | Rules. `Shell(curl:*)` is a wildcard; `Read(src/**)` is not. |

## What becomes unknown

An undocumented hook event or `environment.json` key, against the
documentation as read on **2026-10-17**, is reported as
`INCOMPLETE-UNRECOGNIZED-KEY`.

## What is not read

`.cursor/rules` and `.cursorrules` (instructions, not authority);
Cursor's Run Mode and auto-run settings, which live in the editor, not
in a repository file.
