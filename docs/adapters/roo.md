---
type: reference
title: Roo Code
tags:
  - reference
  - adapters
  - agent-hosts
created: 2026-10-17
---

# Roo Code

**Availability:** implemented, through the MCP
adapter. Files are read, never run.

Roo Code keeps its approval settings in the editor, not in a repository
file. What a repository can commit is an MCP configuration.

## Files read

`.roo/mcp.json`.

## What is recorded

| Key | Recorded as |
| --- | --- |
| `mcpServers.<name>` | One MCP server, with its command or URL host, package and version when it names one, environment variable *names*, header *names*, and a digest of its declaration. Values of environment variables and headers are never recorded. |
| `mcpServers.<name>.alwaysAllow` | One per-tool approval for each tool listed: the tool runs without asking. `policy.permission-bypass-from-project` reports one added by a change. |
| `mcpServers.<name>.disabled` | The server is recorded as disabled. |

Each file becomes a Roo Code agent host holding its servers.

## What becomes unknown

The keys above are Roo Code's MCP documentation as read on
**2026-10-17**. A file that is not valid JSON, or whose `mcpServers` is
not an object, is `INCOMPLETE-UNPARSED-REGION`; a server with neither a
command nor a URL is `INCOMPLETE-UNPARSED-REGION` too.

Other keys on a server entry (for example `timeout` or `watchPaths`) are
not reported as unknown: the MCP adapter reads the server keys it knows
and ignores the rest. See [the limits of static analysis](../reference/agent-authority-limits.md).

## What is not read

- `.roomodes` and `.roo/rules*`. They are treated as instructions,
  not authority. Roo Code's
  documentation says a mode's `groups` can grant tool groups (`command`,
  `mcp`, unrestricted `edit`), so `.roomodes` is not purely instructions;
  reading it as authority is not yet decided.
- Roo Code's editor settings, including auto-approval, which live outside
  the repository.
