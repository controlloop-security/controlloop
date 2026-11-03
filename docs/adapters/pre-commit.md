---
type: reference
title: pre-commit
tags:
  - reference
  - adapters
  - environment
created: 2026-11-03
---

# pre-commit

**Availability:** implemented. The file is read, never run; no hook
repository is cloned and no dependency is installed.

Once a developer runs `pre-commit install`, every commit clones each
hook repository at its `rev`, installs it with its
`additional_dependencies`, and runs it, including every commit a coding
agent makes. A pull request that adds a repository, moves a `rev`,
points it at a tag instead of a commit, or changes a local hook's
command changes what runs on every machine that commits. The gate
reports that change for a person to review; it does not judge whether a
hook is safe.

## Files read

`.pre-commit-config.yaml` (or `.pre-commit-config.yml`) at the
repository root, parsed with `yaml.safe_load`. `.pre-commit-hooks.yaml`,
the file a hook repository publishes its own hooks in, is not read.

## What is recorded

| Entry | Recorded as | Pinned when | Reported by |
| --- | --- | --- | --- |
| `repos[]` with a `repo` URL | A `plugin` component, `source_type: pre-commit-hook`, named `pre-commit hook repository <url>` with the scheme, credentials, and `.git` removed, its `rev` as `ref`, and its hook ids. The host `pre-commit` invokes it. | `rev` is a full 40-character commit SHA. A tag, a branch, or a short SHA can be moved upstream. | [unpinned agent component](../reference/policy-rules.md#unpinned-agent-component), and on a Team gate [unsanctioned agent component](../reference/policy-rules.md#unsanctioned-agent-component). A `rev` moved from one SHA to another is a changed `ref`. |
| `additional_dependencies[]` on any hook | A `plugin` component per dependency, `source_type: pre-commit-dependency`, named `pre-commit dependency <name> for hook <id>`. | An exact version: `name==1.2.3` or `name===1.2.3` (Python), `name@1.2.3` (npm, Go). A range, a wildcard, or no version is unpinned. | The same rules; the finding names the dependency. |
| `repo: local` hooks | A `helper-command` per hook, named by its `id`, as code execution, with `entry` and `args` as the command, `event` naming its `stages` (or `default_stages`, or `pre-commit`), and its `language`. | -- | [agent hook command change](../reference/policy-rules.md#agent-hook-command-change); a committed script `entry` names is tracked by digest for [hook script changed](../reference/policy-rules.md#hook-script-changed). |
| A remote hook that sets `entry` | A `helper-command` the same way, since that command replaces the one the repository publishes. | -- | The same rules. |

A `repo: meta` hook runs pre-commit's own checks and is ignored, as are
`default_language_version`, `exclude`, `files`, `fail_fast`, and the
`ci:` block. The pre-1.0 form, a bare list of repositories, is read as
`repos`. A command passes through the same redaction as hook commands,
so a credential-shaped value in an `entry`, an `args` list, or a
repository URL never reaches the output.

Dependencies are their own components rather than a flag on the
repository's component, so a finding says which dependency can float
and an unpinned dependency does not hide behind a pinned `rev`.

An example of what a pull request that adds a tag-pinned hook reports:

```text
! MEDIUM   policy.unpinned-agent-component: Added: Pre-commit hook
  repository github.com/psf/black (pre-commit-hook) has no commit or digest
  pin.
    at .pre-commit-config.yaml
```

## What becomes unknown

Malformed YAML, a top level that is not a mapping or list, `repos` that
is not a list, an entry with no `repo`, a hook with no `id`, and a local
hook with no `entry` each produce `INCOMPLETE-UNPARSED-REGION`; nothing
is guessed. A repository with no `rev` is recorded as unpinned with the
same diagnostic. One file yields at most 2,048 nodes, so YAML aliases
cannot multiply a small file into an unbounded graph; past that, an
`INCOMPLETE-BOUND-EXCEEDED` diagnostic says the rest were not read.

## Sources

The file format is pre-commit's "Adding pre-commit plugins to your
project" reference on pre-commit.com, read on **2026-11-03**.

## What is not read

The hooks a repository publishes (`.pre-commit-hooks.yaml` in that
repository) and what a hook does once installed; a user's global
`init.templateDir` hooks; plain Git hooks under `.git/hooks`, which are
never committed; and Husky, Lefthook, or other hook managers.
