---
type: reference
title: The authority statement
tags:
  - reference
  - reporting
  - agent-authority
created: 2026-10-17
---

# The authority statement

**Status: Available now** on the `main` branch of this repository.
`controlloop diff`, `scan`, and `gate` print it in every
output format, and the [GitHub Action](github-action.md) carries it in
the check summary. It is not in a published release yet.

## What it says

When a change hands a coding agent new power, the output leads with one
sentence per grant: what the power is, which agent gets it, and where it
was granted.

```text
This change gives Claude Code the power to run `node .github/setup.js` on
every session start (`.claude/settings.json`, hook `SessionStart`). No
approval is recorded.
```

The statement is change-only. It is computed from the baseline
comparison, so:

- A change that grants nothing adds nothing to any output, in any format.
- A scan with no baseline (a first scan) has no statement. The
  agent-authority rules still report what they find, at the first-scan
  severities in [Policy rules](policy-rules.md).
- A removed hook, a narrowed rule, a new `deny` rule, and a tightened
  mode grant nothing.

## What counts as a grant

| Kind | Example statement fragment |
| --- | --- |
| A hook added, or its command changed | the power to run `./audit.sh` before every `Bash` tool call |
| A helper command | the power to run `./key.sh` through the `apiKeyHelper` setting |
| An allow rule held by a host, workflow, skill, or subagent | the power to use `Bash(*)` without asking (a wildcard) |
| A per-tool auto-approval (Kiro, Roo, Cline, Gemini CLI `trust`) | the power to run tool `write_file` of MCP server `fs` without approval |
| A permission or approval mode loosened | the power to act with fewer confirmations: 'permissions.defaultMode' moved from 'plan' to 'bypassPermissions' |
| A subagent moved into a looser mode | the power to run subagent `fixer` with fewer confirmations |
| A workflow that runs an agent | the power to run in GitHub Actions workflow `agent` with write access to contents |
| An MCP server added, or its declaration or tool list changed | the power to start MCP server `fs` by running `npx fs` |
| A plugin or marketplace added, or its source changed | the power to install plugin `lint` from `./plugins/lint`, unpinned |
| A skill that pre-approves tools | the power to load skill `deploy`, which may use `Bash(git push:*)` without asking |

Each entry names the file and the key path, event, rule, setting, or
server. Entries are ordered by agent, then file, then key path.

## Approvals

An approval in [`controlloop.yaml`](manifest-schema.md) is reflected in
the statement when it is active at evaluation time and its `capability`
is one of:

- `<file>#<key path>`, for example
  `.claude/settings.json#hooks.SessionStart[0].hooks[0]` (the `key_path`
  field of the JSON entry);
- the component's name, for example an MCP server's name `fs` or a
  subagent's name `fixer`.

The statement then ends `Approval recorded.` instead of `No approval is
recorded.` The same approval keeps the agent-authority rule's finding for
that component in the report but lowers it to `info`, with the
approver's name, so the change no longer blocks. An expired approval does neither.

`diff` comparing two ACBOM files has no repository and no manifest to
read, so its statements end `Approvals were not evaluated.`, and the JSON
field `approval_recorded` is `null`.

## Where it appears

| Output | Shape |
| --- | --- |
| Terminal (`scan`, `gate`) | An `Authority:` section right after the verdict and before the material changes and findings. |
| Terminal (`diff`) | An `Authority:` section after the baseline and scope lines. |
| `scan --format json` | Top-level `authority_delta` in the [report](report-format.md), schema `1.2.0`. |
| `gate --format json` and the evidence file | Top-level `authority_delta` in the [evidence artifact](evidence-artifact-format.md), schema `1.4.0`. |
| `diff --format json` | Top-level `authority_delta` in the [diff report](diff-output-format.md), schema `1.1.0`. |
| SARIF | `runs[0].properties.controlloop.authorityDelta`; on each result about one of the grants, `properties.controlloop.authorityStatement` and `approvalRecorded`; and `help.text` on each agent-authority rule. See [SARIF export format](sarif-export-format.md). |
| GitHub Action check summary | An **Authority** list under the blast-radius statement, with the agent's name in bold. |
| GitHub Action pull-request comment | One comment, edited in place, only when the pull request grants something; see [the Action](github-action.md#pull-request-comment). |

The JSON field is left out entirely when there is no grant, so a report
with no agent authority change is the same as before apart from its
schema version string.

### The JSON entry

```json
{
  "schema_version": "1.0.0",
  "entries": [
    {
      "node_id": "clp:tool:sha256:...",
      "host_id": "clp:agent:sha256:...",
      "host_name": "Claude Code",
      "kind": "hook",
      "change": "added",
      "grant": "run `node .github/setup.js` on every session start",
      "material_class": "code-execution",
      "statement": "This change gives Claude Code the power to run ...",
      "path": ".claude/settings.json",
      "key_path": "hooks.SessionStart[0].hooks[0]",
      "detail": "hook `SessionStart`",
      "approval_recorded": false,
      "confidence": "high"
    }
  ]
}
```

`kind` is one of `hook`, `helper-command`, `permission-rule`, `mode`,
`workflow-runtime`, `mcp-server`, `plugin`, `marketplace`, `skill`, or
`subagent`. `change` is `added` or `changed`. `material_class` is the
kind of power the grant hands over, in the
[material capability taxonomy](material-capability-taxonomy.md)'s
vocabulary: a command hook, a shell allow rule, a stdio MCP server, or a
looser mode is `code-execution`; an edit rule or a workflow with a write
token is `write-access`; an HTTP hook or server is
`external-communication`; a subagent is `delegation`; anything the
scanner cannot classify is `unclassified`. Backtick spans in `statement`
are single-level code spans; a backtick inside a value is written as
`'`.

## The blast-radius statement

The worst reachable action also accounts for agent authority. A hook
that runs a command is already a reachable code-execution action. The
statement also names any agent host or subagent in a bypass mode, which
acts on that capability without asking, and any over-privileged agent
workflow (the same test `policy.overprivileged-agent-workflow` applies):

```text
! WORST REACHABLE  code-execution: Claude Code can invoke SessionStart
  command hook; without asking, since Claude Code is in a bypass mode
```

In JSON these are `blast_radius.bypass_agents` and
`blast_radius.overprivileged_workflows`, left out when empty.

## Privacy

Every command, rule pattern, and name was bounded and redacted by the
adapter that recorded it, and each statement passes through the
redaction primitive again before it is written. Environment values,
header values, and prompt bodies are never recorded. The redaction
canary (`tests/test_redaction.py`,
`TestAuthorityStatementCanary`) plants credential-shaped values in a
hook command, an allow rule, and an MCP server's arguments and checks
every `scan`, `gate`, and `diff` format, the evidence file, and the
SARIF file. See [Privacy and security](privacy-security.md).

## Limitations

See also [what a passing gate does not guarantee](agent-authority-limits.md).

- The statement says what a file grants, whether or not a given host
  version honors that setting from a project file.
- A grant that only appears in the effective-authority comparison (a
  committed baseline file with no captured graph) has no statement.
  Use a merge-base or revision baseline for the full comparison.
- A host's settings can come from several files. A loosened mode cites
  the host's own settings file, not the exact file that changed the key.
- The [pull-request comment](github-action.md#pull-request-comment) that
  carries this statement is skipped on forks and without
  `pull-requests: write`.
