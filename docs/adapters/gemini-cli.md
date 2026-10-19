---
type: reference
title: Gemini CLI
tags:
  - reference
  - adapters
  - agent-hosts
created: 2026-10-17
---

# Gemini CLI

**Availability:** implemented. Files are read, never run.

## Files read

`.gemini/settings.json`, and `.gemini/.env` for variable names only.
MCP servers under `mcpServers` are recorded by the MCP adapter; a server
with `trust: true` gets a wildcard approval of all its tools.

## What is recorded

| Setting | Recorded as |
| --- | --- |
| `general.defaultApprovalMode` | Host attribute. Order, strictest first: `plan`, `default`, `auto_edit`. `yolo` is a command-line option only; a file that sets it is recorded and sets the bypass flag. |
| `security.disableYoloMode`, `disableAlwaysAllow`, `enablePermanentToolApproval`, `autoAddToPolicyByDefault`, `folderTrust.enabled` | Host attributes. |
| `tools.allowed`, `tools.exclude` | Allow and deny rules. `run_shell_command(git)` allows every `git` command, so it is marked as a wildcard. |
| `tools.sandbox`, `tools.sandboxNetworkAccess` | Host attributes. |
| `tools.discoveryCommand`, `tools.callCommand`, `mcp.serverCommand` | Helper commands: code execution. |
| `hooks` | One hook per handler. Events: `SessionStart`, `SessionEnd`, `BeforeAgent`, `AfterAgent`, `BeforeModel`, `AfterModel`, `BeforeToolSelection`, `BeforeTool`, `AfterTool`, `PreCompress`, `Notification`. |
| `.gemini/.env` | Variable names, as one host attribute. Values are never read into anything. |

## What becomes unknown

Keys outside Gemini CLI's configuration reference as read on
**2026-10-17**, an undocumented hook event, or a mode off the scale are
reported as `INCOMPLETE-UNRECOGNIZED-KEY`.

## What is not read

`GEMINI.md` and other context files; `~/.gemini/`; the trusted-folders
list.
