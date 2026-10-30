---
type: reference
title: Claude Code
tags:
  - reference
  - adapters
  - agent-hosts
created: 2026-10-17
---

# Claude Code

ControlLoop reads the Claude Code settings committed to your repository
and records what they let Claude Code do. It never runs a hook, a helper
command, or anything else the files name.

**Availability:** implemented. The
[agent-authority rules](../reference/policy-rules.md#agent-hook-command-change)
act on these records, and the
[authority statement](../reference/authority-statement.md) describes
each change in plain language.

## Files read

| File | When |
| --- | --- |
| `.claude/settings.json` | Always, when present. |
| `.claude/settings.local.json` | When present and not excluded by `.gitignore`. Claude Code adds it to `.gitignore` itself, so it is usually skipped. |
| `.mcp.json` | Claude Code's project MCP file. Its servers are reachable by Claude Code, so a repository with only `.mcp.json` still has a Claude Code host. |

Comments and trailing commas in a settings file are accepted. When both
settings files set the same single-valued setting, such as
`permissions.defaultMode`, the local file wins, as it does in Claude
Code.

## What ControlLoop records

There is one **Claude Code** agent host per repository, with each
settings file as evidence. Everything below hangs off it.

| Setting | Recorded as |
| --- | --- |
| `hooks` | One hook per handler, with its event, matcher, and type. A `command` hook is code execution and records its command line; when the command names a script committed in the repository, it also records `script_path` and `script_digest` (the file's SHA-256, never its content), and [hook script changed](../reference/policy-rules.md#hook-script-changed) reports the script changing under an unchanged hook. Helper commands, skill shell lines, and a plugin's `bin/` directory (one digest over its files) record the same, and so do the Codex, Gemini CLI, Cursor, and Kiro hooks. An `http` hook is external communication and records the URL's host and the header names. An `mcp_tool` hook records the server and tool names. A `prompt` or `agent` hook records its type only; the prompt text is never recorded. |
| `apiKeyHelper`, `awsAuthRefresh`, `awsCredentialExport`, `gcpAuthRefresh`, `otelHeadersHelper`, `processWrapper`, `statusLine`, `subagentStatusLine`, `fileSuggestion`, `policyHelper`, a marketplace's `headersHelper` | A helper command: code execution, with its command line. |
| `permissions.allow`, `ask`, `deny` | One permission rule each, with its effect and pattern. A bare tool name, `Bash(*)`, any `*` in a `Bash` or `PowerShell` rule, `mcp__server`, `mcp__server__*`, and tool-name globs are marked as wildcards. A rule is never expanded into the commands it might match. |
| `permissions.defaultMode` | An attribute on the host. `bypassPermissions` also sets the host's bypass flag. |
| `permissions.disableBypassPermissionsMode`, `disableAllHooks`, `disableSkillShellExecution`, `allowManagedHooksOnly`, `enableAllProjectMcpServers`, `sandbox.enabled`, `sandbox.allowUnsandboxedCommands`, `sandbox.autoAllowBashIfSandboxed` | Attributes on the host. A change that loosens a `sandbox` setting is reported by [agent sandbox weakened](../reference/policy-rules.md#agent-sandbox-weakened). |
| `permissions.additionalDirectories` | A resource the host can read and write. A path outside the repository is recorded as `<outside-repository>`. Adding one is reported by [workspace scope expansion](../reference/policy-rules.md#workspace-scope-expansion). |
| `env` | The variable **names**, as one host attribute. Values are never read into anything. |
| `enabledPlugins` | One plugin each, enabled or disabled. Its pin status is unknown here, because the pin lives in the marketplace that serves it. |
| `extraKnownMarketplaces` | One marketplace each, with its source type and whether it is pinned: a full commit SHA or a SHA-256 digest is pinned, a branch or tag is not, and a path inside the repository is pinned by the commit itself. Plugins declared inline in a `settings` marketplace are recorded too. |
| `.mcp.json` servers | One edge from the host to each server. A server no settings file mentions still connects once the user approves it at the prompt, so it is reachable and marked as requiring approval. |
| `enabledMcpjsonServers`, `allowedMcpServers` | Marks the named server's edge as approved. |
| `disabledMcpjsonServers`, `deniedMcpServers` | Replaces the named server's edge with a constraint. A rejection wins over an approval. |
| `enableAllProjectMcpServers: true` | Marks every server as approved, flagged as a wildcard approval. |
| `permissions.allow` with `mcp__<server>__<tool>` | Also an approval of that tool on the server it names. |

Every command line and rule pattern is limited to 512 characters and
passes through ControlLoop's redaction first. Known credential formats,
and values after `--token=`, `--key`, `--password`, `Bearer`, and
`NAME_TOKEN=`-style assignments, are replaced before anything is
recorded.

## Skills, subagents, and plugins

| File | Recorded as |
| --- | --- |
| `SKILL.md` under `.claude/skills/`, `.agents/skills/`, `.github/skills/`; `.claude/commands/*.md` | A skill the host can invoke, named by its `name` field or its directory. `allowed-tools` become rules the skill is permitted by; `disallowed-tools` become rules it is constrained by. Frontmatter `hooks` are recorded like settings hooks. Every `` !`cmd` `` at the start of a line or after a space, and every line of a ` ```! ` block, is a command that runs before the skill reaches the model, recorded as code execution and reported by [component shell execution](../reference/policy-rules.md#component-shell-execution) when added or changed. |
| `.claude/agents/*.md` | A subagent the host delegates to: its `tools` (or `inherit`), `disallowedTools`, `permissionMode` (`bypassPermissions` sets the bypass flag), `mcpServers` (named ones link to `.mcp.json`, inline ones are recorded as servers), `hooks`, and preloaded `skills`. |
| A directory with `.claude-plugin/plugin.json` | A plugin the host invokes, pinned by the repository commit, with its `hooks/hooks.json`, `.mcp.json`, manifest `hooks` and `mcpServers`, `skills/`, `commands/`, `agents/`, manifest `lspServers` and `monitors` commands, and its `bin/` directory, which joins the agent's `PATH` and is recorded as code execution ([component shell execution](../reference/policy-rules.md#component-shell-execution) reports it when added). Plugin subagents' `hooks`, `mcpServers`, and `permissionMode` are ignored, as Claude Code ignores them, and the subagent records that they were present. |
| `.claude-plugin/marketplace.json` | A marketplace, and one plugin per entry with its source type and pin status. A `command` source is code execution. |

A skill whose frontmatter does not parse is still recorded, with no
fields, because Claude Code still loads it, and the parse failure is
reported.

## What becomes unknown

The recognized keys are the ones the Claude Code settings reference
documented on **2026-10-17**, the date `controlloop --version` reports.
A key outside that set, a hook event or handler type that was not
documented on that date, or an undocumented `defaultMode` value is
reported once per file as `INCOMPLETE-UNRECOGNIZED-KEY`, naming each key
path. A server name that `.mcp.json` does not declare is reported as
`INCOMPLETE-UNRESOLVED-REFERENCE`. A file that cannot be parsed is
reported as `INCOMPLETE-UNPARSED-REGION`, and the other settings file is
still read.

Under the default `completeness_enforcement: warn`, any of these makes
`gate` report **Passed with warnings** rather than **Passed**.

## What is not read

- `CLAUDE.md`, `AGENTS.md`, and other instruction files. They shape what
  an agent tries to do, not what Claude Code allows it to do.
- Settings outside the repository: `~/.claude/settings.json` and
  managed settings. A passing scan says nothing about them.
- The description and instructions in a skill or subagent file. Only
  the frontmatter and shell-injection lines are read (see below).

## Whether Claude Code honors a setting

ControlLoop records what a file grants, whichever Claude Code version
reads it. Some settings take effect from a project file only after the
folder is trusted, and some not at all. For example, `defaultMode:
bypassPermissions` has been ignored in project files since Claude Code
v2.1.257. The Claude Code settings reference is the authority on which
version honors what.
