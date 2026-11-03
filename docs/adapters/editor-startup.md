---
type: reference
title: Editor startup files and JetBrains required plugins
tags:
  - reference
  - adapters
  - environment
created: 2026-11-03
---

# Editor startup files and JetBrains required plugins

**Availability:** implemented. Files are read, never run or evaluated.

Some editors source a file committed at the project root as code when
the project opens, and JetBrains IDEs ask to install the plugins a
project lists as required. A pull request that adds or changes one of
these files changes what can run on every developer's machine that
opens the repository. The gate reports the change for a person to
review; it does not judge whether a file or plugin is safe.

## Files read

| File | Editor | When it runs |
| --- | --- | --- |
| `.nvim.lua`, `.nvimrc` | Neovim | On open, with `'exrc'` set; Neovim 0.9 and later asks before running a file it has not trusted. |
| `.exrc` | Vim (and Neovim) | On open, with `'exrc'` set. |
| `.lvimrc` | Vim, with the localvimrc plugin | On open, after the plugin's own prompt unless disabled. |
| `.dir-locals.el`, `.dir-locals-2.el` | Emacs | On visiting a file; an `eval` form runs code once allowed. |
| `.idea/externalDependencies.xml` | JetBrains IDEs | On open, the IDE asks to install or enable each missing required plugin. |

Only files at the repository root are read: a startup file in a
subdirectory is not sourced when the project opens, and `.vimrc`,
`init.lua`, and other user configuration files are not read.

## What is recorded

| Entry | Recorded as | Reported by |
| --- | --- | --- |
| A startup file | A `helper-command` held by the editor's host (`Neovim`, `Vim`, `Emacs`), named by the file, with `event: project-open`, the path as the command, and the file's SHA-256 as `script_digest`. The file is never parsed; its content never reaches the output. | [agent hook command change](../reference/policy-rules.md#agent-hook-command-change) for a new or removed file (a first scan reports it once at `low`), and [hook script changed](../reference/policy-rules.md#hook-script-changed) when its content changes. |
| `<plugin id min-version max-version>` in `externalDependencies.xml` | A `plugin` component, `source_type: editor-extension`, named `editor plugin <id>`, with its bounds. The host `JetBrains IDEs` `receives-from` it: the IDE asks, it does not install unasked. Pinned only when `min-version` equals `max-version`; a range or one bound is unpinned; no bound is `unknown`. | [unpinned agent component](../reference/policy-rules.md#unpinned-agent-component), and on a Team gate [unsanctioned agent component](../reference/policy-rules.md#unsanctioned-agent-component). A changed bound is a changed `ref`. |

An example of what a pull request that changes `.nvim.lua` reports:

```text
✕ HIGH     policy.hook-script-changed: Setting '.nvim.lua' for host 'Neovim'
  runs `.nvim.lua`, whose contents changed while the command did not.
    at .nvim.lua
```

## What becomes unknown

Malformed XML, a top-level element other than `project`, a project
format version other than 4, a `<plugin>` with no `id`, a document type
declaration (refused before parsing, so no entity is expanded or
fetched), and a file that is not UTF-8 each produce
`INCOMPLETE-UNPARSED-REGION`. A startup file past the walker's per-file
size bound is skipped by the walker, which reports it.

## Sources

The `externalDependencies.xml` element and attribute names are
IntelliJ's own serialization (`DependencyOnPluginState` and
`ExternalDependenciesManagerImpl` in the IntelliJ Community source),
read on **2026-11-03**. Zed's `.zed/settings.json` was checked the same
day and is not read: `auto_install_extensions` is a user setting, and a
project settings file has no such field, so a repository cannot make
Zed install an extension.

## What is not read

User-level editor configuration, plugins a user installs by hand,
`.idea/` files other than `externalDependencies.xml`, and editor
settings that only change behavior without running code.
