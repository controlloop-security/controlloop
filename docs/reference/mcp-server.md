# The local MCP server: `controlloop mcp`

`controlloop mcp` runs ControlLoop as a local Model Context Protocol (MCP)
server over stdio. An agent host that speaks MCP can then call `gate`,
`diff`, `bom` and `rules` as tools and get the CLI's own JSON back, instead
of being told how to run shell commands.

It works with any host that runs stdio MCP servers: Claude Code, Codex,
Gemini CLI, Cursor, VS Code with GitHub Copilot, Kiro, Windsurf, Roo Code,
Cline, Continue and opencode.

> **Availability:** in the CLI's `main` branch; ships in the release after
> 0.6.1. `controlloop --help` lists `mcp` when your installed version has
> it.

## What it will not do

- **No network.** Every tool call runs with Team switched off, even in a
  repository whose `controlloop.toml` sets `team_enabled = true`: the
  server sets `CONTROLLOOP_TEAM_ENABLED=false` and removes
  `CONTROLLOOP_TEAM_TOKEN` for the call. The Community path opens no
  connection, so neither does the server.
- **No writes.** No tool takes an output path. `gate` writes its evidence
  artifact to a private temporary directory outside your repository and
  deletes it before returning; the tool's result is that same artifact.
- **Nothing outside the workspace.** The workspace is the directory the
  server was started with (the current directory unless you pass one).
  Every `path` argument, and a `baseline` that names a file, must resolve
  inside it after symlinks are followed. A git revision must look like one
  (`main`, `origin/main`, `HEAD~1`, a commit) and may not start with `-`.
- **Nothing the CLI would not print.** Output is captured inside the same
  redaction boundary as every other command (see
  [Privacy, security, and limitations](privacy-security.md)): no secret
  values, prompts or file contents.
- It never starts the MCP servers it finds, runs repository code, or edits
  agent configuration. It only reads.

## Tools

| Tool | Runs | Arguments |
| --- | --- | --- |
| `gate` | `controlloop gate <path> --format json` | `path`, `default_branch` |
| `diff` | `controlloop diff <path> --format json` | `path`, `baseline` (a revision or an ACBOM file) |
| `bom` | `controlloop bom <path>` | `path` |
| `rules` | `controlloop rules <path> --format json` | `path`, `all` |

Every argument is optional. Each result has the same shape, as structured
content and as its JSON text:

```json
{
  "command": "controlloop gate scenarios/storefront-agent-config --format json",
  "exit_code": 1,
  "exit_meaning": "blocked or review required",
  "result": { "verdict": "deployment_blocked", "authority_delta": { "...": "..." }, "findings": [] },
  "stderr": []
}
```

`result` is exactly what the command prints on standard output: the
[evidence artifact](evidence-artifact-format.md) for `gate`, the
[diff report](diff-output-format.md) for `diff`, the ACBOM for `bom`, and
the rule catalog (with each rule's `documentation_url`) for `rules`.
`exit_code` follows the CLI's [exit codes](cli.md#exit-codes). A blocked
gate (exit 1) is an answer, not an error; the result is marked `isError`
only for invalid input (2), an internal error (5), or output that is not
JSON.

`gate` needs real git history to find the merge base with the default
branch, exactly like the command. Pass `default_branch` when `origin/HEAD`
is not set.

## Install it in your host

Each snippet runs the `controlloop` on your `PATH`. Install it first with
Homebrew (`brew install controlloop-security/controlloop/controlloop`),
`uv tool install controlloop`, `pipx install controlloop`, or the
[shell installer](shell-installer.md). Hosts start the server from your
project directory; where a host may not, the snippet passes the workspace
explicitly.

To run it without installing, replace `"command": "controlloop"` and
`"args": ["mcp"]` with `"command": "uvx"` and
`"args": ["controlloop@<version>", "mcp"]`. Pin the version, in that
`@` form, which `controlloop gate` reads as a pin: an unpinned launcher is the
[MCP server identity change](policy-rules.md#mcp-server-identity-change) ControlLoop reports in other
repositories, and the same advice applies to ControlLoop itself.

**Claude Code** (project `.mcp.json`, or `claude mcp add controlloop -- controlloop mcp`):

```json
{ "mcpServers": { "controlloop": { "command": "controlloop", "args": ["mcp"] } } }
```

**Codex** (`~/.codex/config.toml`, or `codex mcp add controlloop -- controlloop mcp`):

```toml
[mcp_servers.controlloop]
command = "controlloop"
args = ["mcp"]
```

**Gemini CLI** (`.gemini/settings.json`):

```json
{ "mcpServers": { "controlloop": { "command": "controlloop", "args": ["mcp"] } } }
```

**Cursor** (`.cursor/mcp.json`):

```json
{ "mcpServers": { "controlloop": { "command": "controlloop", "args": ["mcp", "${workspaceFolder}"] } } }
```

**VS Code and GitHub Copilot** (`.vscode/mcp.json`):

```json
{ "servers": { "controlloop": { "type": "stdio", "command": "controlloop", "args": ["mcp", "${workspaceFolder}"] } } }
```

**Kiro** (`.kiro/settings/mcp.json`), **Roo Code** (`.roo/mcp.json`),
**Cline** (`cline_mcp_settings.json`) and **Windsurf**
(`~/.codeium/windsurf/mcp_config.json`) use the same `mcpServers` shape as
Claude Code. A user-level file such as Windsurf's is not tied to one
project, so pass the project path: `"args": ["mcp", "/path/to/project"]`.

**Continue** (`.continue/mcpServers/controlloop.yaml`):

```yaml
name: ControlLoop
version: 0.0.1
schema: v1
mcpServers:
  - name: controlloop
    command: controlloop
    args: ["mcp"]
```

**opencode** (`opencode.json`):

```json
{ "mcp": { "controlloop": { "type": "local", "command": ["controlloop", "mcp"], "enabled": true } } }
```

Do not set `autoApprove`, `alwaysAllow` or `trust` for it unless you mean
to: every tool is read-only, but approving tools per call is still your
host's decision.

## Not the Team MCP server

ControlLoop Team has a separate, hosted MCP server for organization data:
fleet queries, approved-component (sanction) checks, gate history and
evidence reports. It is reached over HTTPS with your Team sign-in and is
documented in the Team dashboard under **Settings → AI assistants**. The
local server never contacts it and cannot answer those questions; see
[controlloop.ai](https://controlloop.ai).

## Protocol

Newline-delimited JSON-RPC 2.0 on standard input and output, MCP protocol
versions `2025-06-18`, `2025-03-26` and `2024-11-05`. Implemented methods:
`initialize`, `notifications/initialized`, `ping`, `tools/list` and
`tools/call`. Any other request gets JSON-RPC error `-32601`; an invalid
argument, an unknown tool, or a path outside the workspace gets `-32602`.
A message over 1 MiB is refused with `-32700`. The server exits `0` when
the host closes standard input, and `2` if the workspace is not an
existing directory.

## Limitations

- One request at a time; a long `gate` on a very large repository delays
  the next call. The traversal bounds in
  [Configuration](configuration.md) apply.
- `scan` and `init` are not tools: `gate` gives the same verdict and
  findings, and `init` writes a file.
- No MCP resources, prompts or HTTP transport.
