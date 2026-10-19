---
type: reference
title: Agent-running workflows
tags:
  - reference
  - adapters
  - agent-hosts
  - ci
created: 2026-10-17
---

# Agent-running workflows

A GitHub workflow that runs a coding agent decides, in a committed file,
what that agent can do with no one watching. ControlLoop records each
such job and what it hands the agent. Workflow files are read, never
run.

**Availability:** implemented.
[`policy.overprivileged-agent-workflow`](../reference/policy-rules.md#overprivileged-agent-workflow)
reports an agent workflow given a write token with no brakes.

## Files read

`.github/workflows/*.yml` and `.github/workflows/*.yaml`, directly in
that directory. YAML anchors and merge keys are resolved as YAML defines
them.

## Which jobs count

| In the job | Agent host |
| --- | --- |
| A step using `anthropics/claude-code-action` or `anthropics/claude-code-base-action` | Claude Code |
| A step using `openai/codex-action` | Codex |
| A step using `google-github-actions/run-gemini-cli` | Gemini CLI |
| In a gh-aw `*.lock.yml`, a `run` step starting `claude`, `codex`, `copilot`, or `gemini` | that CLI's host |

Each counts as one **workflow runtime**, named `<workflow> / <job>`,
which invokes its agent host. When the repository also configures that
host, for example with `.claude/settings.json`, the workflow joins that
same host rather than creating a second one.

## What is recorded

| Recorded | How |
| --- | --- |
| Token permissions | The job's `permissions` block, or the workflow's when the job has none. With neither, they are `unknown`, never assumed to be GitHub's default. Each scope is recorded, and `contents`, `pull-requests`, and `id-token` write access are flagged on the runtime. `write-all` is a wildcard. |
| Skipped permission prompts | Any of `--dangerously-skip-permissions`, `--dangerously-bypass-approvals-and-sandbox`, `--yolo`, `--allow-all-tools`, `--approval-mode yolo`, `--permission-mode bypassPermissions` in the step's inputs, or Codex `safety-strategy: unsafe` or `sandbox: danger-full-access`. |
| Allowed tools | `allowed_tools` / `allowedTools` inputs and `--allowedTools` in the agent's arguments, one permission rule each, wildcards marked. |
| Secrets | The **names** in `${{ secrets.NAME }}` used by the agent step or the job's `env`. Never a value. |
| `settings`, `mcp_config` inputs | A path, or `inline` with a short digest of the inline text. The inline text itself is not recorded. |
| Untrusted input | A `pull_request_target`, `issue_comment`, `workflow_run`, `issues`, `pull_request_review_comment`, or `discussion_comment` trigger, or a checkout of the pull request's head, is an untrusted-input event that both the runtime and the agent host receive from. |

## What becomes unknown

These are reported as `INCOMPLETE-UNRESOLVED-REFERENCE`, naming the
workflow and the job:

- a job that calls a reusable workflow (`jobs.<id>.uses`);
- a matrix on an agent job;
- an expression other than `${{ secrets.NAME }}` in an agent input;
- `permissions` given as an expression.

A workflow that is not valid YAML is reported as
`INCOMPLETE-UNPARSED-REGION`.

## What is not read

Workflows in other CI systems, composite actions defined in other
repositories, and anything a step downloads or runs at execution time.
