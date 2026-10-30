---
type: reference
title: What a passing gate does not guarantee
tags:
  - reference
  - agent-authority
  - limitations
created: 2026-10-17
---

# What a passing gate does not guarantee

ControlLoop reads the files a repository commits and reports what they
grant coding agents. It never runs them, and it never watches an agent
run. A passing gate means that nothing in the committed configuration it
can read crossed a rule's threshold. **It is not a safety guarantee.**

This page lists what static analysis of a repository cannot see. Each
point is a limit of the approach, not a bug waiting for a fix.

## Configuration outside the repository

- **User-scope and home-directory settings.** `~/.claude/settings.json`,
  `~/.codex/config.toml`, `~/.gemini/settings.json`, Cursor's and Kiro's
  user settings, and the editor settings of Roo Code and Cline can add
  hooks, allow rules, MCP servers, and looser modes. They are not in the
  repository, so ControlLoop does not read them, and they can override or
  add to everything it reports.
- **Managed or enterprise policy files** that an organization installs on
  a machine.
- **Command-line flags** a developer passes when starting an agent, for
  example `--dangerously-skip-permissions`. ControlLoop sees these only
  when they are committed in a workflow file.

## Things added at runtime

- **Servers and components a plugin brings with it.** A plugin enabled by
  name is recorded, but the hooks, servers, and skills inside it come from
  its own repository, which ControlLoop does not fetch. A pinned plugin's
  contents are fixed; an unpinned one's can change at any time.
- **Servers added through user scope or by an agent's own command**, such
  as `claude mcp add`, after the repository was scanned.
- **Tool descriptions served live by a remote MCP server.** ControlLoop
  records a remote server's URL host and, when a tool list is committed
  beside it, a digest of that list. What an unpinned remote server serves
  on the day it is used can differ from both.

## Content the agent reads

- **Prompt injection.** A README, an issue, a web page, a dependency's
  source, or a tool's output can contain instructions an agent follows.
  ControlLoop treats every file as data and does not judge text as an
  attack. A repository can pass and still contain text that steers an
  agent to misuse the authority it already has.
- **Instruction files** (`CLAUDE.md`, `AGENTS.md`, `.cursor/rules`,
  `.roo/rules*`, Cline rules, skill and subagent bodies) are not read as
  authority. They shape what an agent does with its permissions; they do
  not grant permissions themselves. Roo Code's `.roomodes` grants tool
  groups to each mode, so its `groups` are read as permission rules (see
  [Roo Code](../adapters/roo.md)); a mode's role definition and
  instructions are prompt text and are not.

## What the files themselves leave open

- **What a hook or command actually does.** ControlLoop records the
  command a hook runs and reports when it is added or changed. A script
  committed in the repository that the command names is tracked by
  digest, so a change to it is reported by
  [hook script changed](policy-rules.md#hook-script-changed) even when
  the configuration is untouched. Its behaviour stays unread: a formatter
  script and a credential harvester look the same, and a script outside
  the repository, or one another script calls, is not tracked.
- **What a permission rule matches at runtime.** Rules are classified (a
  wildcard, a shell rule, a read-only tool), never expanded into the
  commands they would allow.
- **Whether a host honors a setting from a project file.** Some hosts
  ignore some settings in project scope. ControlLoop reports what the file
  asks for either way.
- **Keys a host added after the documentation snapshot.** Each host's key
  set is pinned to its documentation as read on the date shown on its
  [adapter page](../adapters/readme.md) and in `controlloop --version`.
  A newer key is reported as unknown, never ignored, on the pages that
  say so; the MCP adapter reads the server keys it knows and ignores
  others.
- **Files whose format is undocumented**, such as Cline's `.cline/hooks/`
  and `.cline/plugins/`, which can run code and are not read.

## Change-only by design

The agent-authority rules report what a change grants, not what a
repository already holds. A first scan, with no baseline, reports
existing hooks, wildcards, and bypass modes once, at low severity, and
never blocks on them alone. After that, a component that does not change
produces no finding. A gate that passes on a pull request says that pull
request granted nothing over the threshold; it says nothing new about
authority granted earlier.

## What this means for a passing gate

Treat a pass as "this change, in the files ControlLoop can read, did not
hand an agent new power above your threshold." Pair it with the controls
that cover what static analysis cannot: managed settings on developer
machines, sandboxed or network-restricted agent runs, short-lived and
narrowly scoped CI tokens, and review of what an agent reads.

See also: [the authority statement](authority-statement.md),
[policy rules](policy-rules.md), and each host's
[adapter page](../adapters/readme.md).
