---
type: reference
title: Cline
tags:
  - reference
  - adapters
  - agent-hosts
created: 2026-10-17
---

# Cline

**Availability:** implemented, through the MCP
adapter. Files are read, never run.

Cline keeps its approval settings in the editor, not in a repository
file. What a repository can commit is an MCP settings file, which Cline
normally keeps outside the repository.

## Files read

`cline_mcp_settings.json`, anywhere in the repository.

## What is recorded

| Key | Recorded as |
| --- | --- |
| `mcpServers.<name>` | One MCP server, with its command or URL host, package and version when it names one, environment variable *names*, header *names*, and a digest of its declaration. Values of environment variables and headers are never recorded. |
| `mcpServers.<name>.autoApprove` | One per-tool approval for each tool listed: the tool runs without asking. `policy.permission-bypass-from-project` reports one added by a change. |
| `mcpServers.<name>.disabled` | The server is recorded as disabled. |

Each file becomes a Cline agent host holding its servers.

## What becomes unknown

The keys above are Cline's MCP documentation as read on **2026-10-17**.
A file that is not valid JSON, or whose `mcpServers` is not an object, is
`INCOMPLETE-UNPARSED-REGION`; a server with neither a command nor a URL
is `INCOMPLETE-UNPARSED-REGION` too.

Other keys on a server entry are not reported as unknown: the MCP adapter
reads the server keys it knows and ignores the rest. See
[the limits of static analysis](../reference/agent-authority-limits.md).

## What is not read

- `.clinerules` and `.cline/rules`. They are treated as instructions,
  not authority.
- `.cline/hooks/` and `.cline/plugins/`. They can run code, but their
  file format is not documented, so they are not read; a repository that
  has them is not fully described by ControlLoop's output.
- Cline's editor settings, including auto-approval, which live outside
  the repository.
