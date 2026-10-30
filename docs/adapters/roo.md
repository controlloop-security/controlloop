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

**Availability:** implemented, through the MCP adapter and
`RooModesAdapter`. Files are read, never run.

Roo Code keeps its approval settings in the editor, not in a repository
file. What a repository can commit is an MCP configuration and a set of
custom modes, each of which is given tool groups.

## Files read

`.roo/mcp.json` and `.roomodes`.

## What is recorded

| Key | Recorded as |
| --- | --- |
| `mcpServers.<name>` | One MCP server, with its command or URL host, package and version when it names one, environment variable *names*, header *names*, and a digest of its declaration. Values of environment variables and headers are never recorded. |
| `mcpServers.<name>.alwaysAllow` | One per-tool approval for each tool listed: the tool runs without asking. `policy.permission-bypass-from-project` reports one added by a change. |
| `mcpServers.<name>.disabled` | The server is recorded as disabled. |

Each file becomes a Roo Code agent host holding its servers.

## Custom modes

`.roomodes` sits at the repository root and may be YAML or JSON; Roo
Code tries YAML first, and so does ControlLoop.

| Key | Recorded as |
| --- | --- |
| `customModes[].slug` | The mode's identity. Renaming its `name` does not change it. |
| `customModes[].name` | The mode's display name: a `subagent` node called `mode <name>` under the Roo Code host. |
| `customModes[].groups` | One permission rule per tool group, held by the Roo Code host and linked from the mode. |
| `"read"` | Rule `read`. |
| `"edit"` | Rule `edit`, a wildcard: the mode may edit any file. |
| `["edit", {"fileRegex": "..."}]` | Rule `edit(<fileRegex>)`. The regular expression is recorded as text and never evaluated. |
| `"browser"`, `"command"`, `"mcp"` | Rules marked as wildcards, since Roo Code does not scope them to a site, a command, or a server. `command` is code execution; `browser` is external communication. |
| `roleDefinition`, `customInstructions`, `whenToUse`, `description` | Never read: prompt text. |

A mode that gains a group, or an `edit` group that loses its
`fileRegex`, is reported by
[`policy.widened-permission-rule`](../reference/policy-rules.md#widened-permission-rule)
exactly as a widened Claude Code `permissions.allow` entry is. Because
the host holds each rule, the group is part of the host's allow set, and
[`policy.component-self-grant`](../reference/policy-rules.md#component-self-grant)
does not report it a second time. A changed `fileRegex` shows in `diff`;
it is reported as widened only when the group becomes unrestricted,
since a regular expression is never evaluated.

**Whether the host honours a setting.** Roo Code's documentation says a
project mode in `.roomodes` "completely overrides" a global mode with
the same slug, with no merging of properties, and that project modes
come before global modes and the built-in modes. A project mode
therefore grants exactly the groups it lists, whatever the user's global
modes say. Global modes (`custom_modes.yaml`) live outside the
repository and are not read.

## What becomes unknown

The MCP keys above are Roo Code's MCP documentation as read on
**2026-10-17**. A file that is not valid JSON, or whose `mcpServers` is
not an object, is `INCOMPLETE-UNPARSED-REGION`; a server with neither a
command nor a URL is `INCOMPLETE-UNPARSED-REGION` too.

The custom mode keys are Roo Code's custom modes documentation as read
on **2026-10-29**, reported by `controlloop --version` as `roo-code`.
That page lists the `read`, `edit`, `command`, and `mcp` groups;
`browser` is also accepted, since Roo Code still honours it in existing
files. A `.roomodes` that is neither valid YAML nor valid JSON, or whose
top level is not a mapping, is `INCOMPLETE-UNPARSED-REGION`, as are a
`customModes` that is not a list, a mode without a valid slug, two modes
sharing a slug, and a group listed twice. A top-level key other than
`customModes`, a mode key outside the list above, and an unknown group
are `INCOMPLETE-UNRECOGNIZED-KEY`.

Other keys on a server entry (for example `timeout` or `watchPaths`) are
not reported as unknown: the MCP adapter reads the server keys it knows
and ignores the rest. See [the limits of static analysis](../reference/agent-authority-limits.md).

## What is not read

- `.roo/rules*`, `.roorules-<slug>`, and a mode's prompt text. They are
  instructions, not authority.
- A `.roomodes` anywhere but the repository root, which Roo Code's
  documentation does not name.
- Roo Code's editor settings, including auto-approval, which live outside
  the repository.
