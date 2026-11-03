---
type: reference
title: Dev containers and VS Code extensions
tags:
  - reference
  - adapters
  - environment
created: 2026-11-03
---

# Dev containers and VS Code extensions

**Availability:** implemented. Files are read, never run, pulled, or
resolved.

Opening a repository in a dev container installs the editor extensions
and features its `devcontainer.json` names and runs its lifecycle
commands, one of them on the developer's own machine before the
container exists. A pull request that adds one, swaps one, or drops a
version pin changes what runs on every clone and every Codespace. The
gate reports that change for a person to review; it does not judge
whether an extension or feature is safe.

## Files read

- `.devcontainer/devcontainer.json`, `.devcontainer/<folder>/devcontainer.json`
  (one folder deep, as the specification looks), and `.devcontainer.json`.
- `.vscode/extensions.json`.
- Any `*.code-workspace` file.

All are JSON with comments and trailing commas allowed. They carry no
version field.

## What is recorded

| Entry | Recorded as | Pinned when | Reported by |
| --- | --- | --- | --- |
| `customizations.vscode.extensions[]` (and the older top-level `extensions[]`) | A `plugin` component, `source_type: editor-extension`, named `editor extension <publisher.name>`, the host `Dev Containers` invokes. | The id carries `@<major.minor.patch>` (VS Code's form, with an optional pre-release or build suffix). `@prerelease` and a bare id are unpinned. | [unpinned agent component](../reference/policy-rules.md#unpinned-agent-component), and on a Team gate [unsanctioned agent component](../reference/policy-rules.md#unsanctioned-agent-component). |
| `features.<id>` | A `plugin` component, `source_type: devcontainer-feature`, named `devcontainer feature <registry/path>`, with `origin` (`registry`, `local`, or `tarball`) and the registry host. | An `@sha256:<64 hex>` digest, or an exact `major.minor.patch` tag. `:1`, `:1.2`, `:latest`, and no tag are unpinned; a local `./feature` is pinned by the commit; an `https://` tarball is unpinned. | The same rules. |
| `initializeCommand`, `onCreateCommand`, `updateContentCommand`, `postCreateCommand`, `postStartCommand`, `postAttachCommand` | One `helper-command` per command, as code execution, with `event` naming the key and `runs_on_host: true` for `initializeCommand`. The object form's named commands are `postStartCommand.<name>`. | -- | [agent hook command change](../reference/policy-rules.md#agent-hook-command-change); a committed script the command runs is tracked by digest for [hook script changed](../reference/policy-rules.md#hook-script-changed). |
| `recommendations[]` in `.vscode/extensions.json`, `extensions.recommendations[]` in a workspace file | A `plugin` component, `source_type: editor-extension`, `recommended_only: true`, `pinned: unknown`, held by the host `VS Code` with a `receives-from` edge (VS Code suggests it; nothing installs it unasked). | Never: the format has no place for a pin. | Unpinned agent component, as a component with no pin this repository can verify. |
| `dockerComposeFile` | A path on the `Dev Containers` host (`docker_compose_files`). The Compose file is not opened. | -- | -- |

A version or digest change keeps the component's identity and changes
its `ref`, so the unpinned rule reports it as a changed pin. A command
is recorded through the same redaction as hook commands, so a
credential-shaped value in it never reaches the output.

An example of what a pull request that adds a dev container reports:

```text
! MEDIUM   policy.unpinned-agent-component: Added: Editor extension
  ms-python.python (editor-extension) has no commit or digest pin.
    at .devcontainer/devcontainer.json

! MEDIUM   policy.unpinned-agent-component: Added: Devcontainer feature
  ghcr.io/devcontainers/features/node (devcontainer-feature) has no commit or
  digest pin.
    at .devcontainer/devcontainer.json

✕ HIGH     policy.agent-hook-command-change: Added: Setting 'initializeCommand'
  for host 'Dev Containers' runs `bash .devcontainer/init.sh`.
    at .devcontainer/devcontainer.json
```

## What becomes unknown

Malformed JSON, a top level that is not an object, a `features` value
that is not an object, an extension entry that is not a `publisher.name`
id, and a lifecycle command that is not a string, list, or object each
produce `INCOMPLETE-UNPARSED-REGION`; nothing is guessed. A file with
only an image or a Dockerfile is silent.

## Sources

The `@version` form for extensions is the item pattern of
`devContainer.vscode.schema.json` in the VS Code repository; the
specification itself only says "an array of extension IDs". Feature
references and their semver tags follow the dev container
specification's feature distribution page; the lifecycle commands, their
forms, and that `initializeCommand` runs on the host follow its
`devcontainer.json` reference. All were read on **2026-11-03**.

## What is not read

The image, the Dockerfile, the Compose file, `containerEnv`,
`remoteEnv`, mounts, ports, and `customizations.vscode.settings`.
`.vscode/tasks.json` tasks that run on folder open, and
`.vscode/settings.json`, are not read either. Extensions a user installs
by hand, and device-level controls such as VS Code's
`extensions.allowed` policy, are outside the repository; the gate is the
repository-side complement to them.
