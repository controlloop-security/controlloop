---
type: reference
title: CrewAI support
tags:
  - reference
  - adapters
  - frameworks
created: 2026-08-31
---

# CrewAI support

**Status: available.** `controlloop scan` discovers CrewAI agents,
delegation, and tool wiring. Every output below is real recorded output
from a real project, not an illustration.

Supported versions: **`crewai>=0.80,<1.0`**. A project declaring a
version outside that range, or declaring none at all, is refused rather
than parsed hopefully — see [Version handling](#version-handling).

## What is discovered

| Construct | Read from | Becomes |
| --- | --- | --- |
| each entry in `config/agents.yaml` | YAML | an `agent` node named by its `role` |
| `allow_delegation: true` | YAML | a `delegates-to` edge to every other agent in the crew |
| `tools=[SomeTool(), other.Tool()]` | `crew.py`, parsed | a `tool` node each, plus an `invokes` edge |

CrewAI does not let an agent name specific delegation targets, so
`allow_delegation: true` becomes an edge to **every** other agent.
Understating reach is the more dangerous error.

## What is reported as unknown

This is the important half.

Only a **literal list of constructor calls** resolves. Every other shape
produces two things: an `INCOMPLETE-UNRESOLVED-REFERENCE` diagnostic, and
a tool node whose security attributes are literally `"unknown"`.

```python
tools = [SerperDevTool(), FileWriterTool()]  # resolves
tools = self._pick_tools()  # unknown
tools = [t for t in self.all_tools]  # unknown
tools = TOOLS  # unknown
tools = [SerperDevTool()] if flag else []  # unknown
tools = [*base_tools]  # unknown
```

The second half matters more than the diagnostic. An `"unknown"`
attribute classifies as `UNCLASSIFIED`, which the [material capability
taxonomy](material-capability-taxonomy.md) ranks **worst of all**. So an
unreadable tool is not merely noted — it becomes the worst reachable
capability in the graph:

```
! WORST REACHABLE  unclassified: Content Writer can invoke
  unresolved-tools:writer
```

A tool nobody can read is treated as the most dangerous thing present,
because nobody knows what it is. The alternative — omitting it — would
produce `no material capability is reachable` over an agent that may
hold a file-writing tool, and that confident pass is the worst failure
this product can have.

Also reported, never silently handled:

- a crew that overrides `agents_config` to a non-default path, since the
  agents discovered may not be the ones the crew actually uses;
- a crew using the hierarchical process, whose manager may delegate to
  every agent;
- an `Agent(...)` construction that cannot be matched to a declared
  agent, so its tools would otherwise be attributed to nothing.

## What is not read at all

- **`config/tasks.yaml`.** Tasks describe work, not capability. A task
  grants nothing an agent does not already hold.
- **Tool implementations under `tools/`.** What a tool *does* is not
  stated anywhere a scanner can read it. Declare it in
  `controlloop.yaml` under `tool_capabilities`, exactly as for an A2A
  skill — see [the manifest schema](manifest-schema.md).
- **Anything at runtime.** No CrewAI code is imported, executed, or
  evaluated. Ever.

## Verdicts you should expect

A crew whose tools all resolve scans like any other project.

A crew with **any** unresolved tool cannot pass silently. Under
`completeness_enforcement = "enforce"`:

```
$ CONTROLLOOP_COMPLETENESS_ENFORCEMENT=enforce controlloop gate .
• COMPLETENESS  merge-base baseline ACBOM: 1 diagnostic(s) indicate
  incomplete analysis: INCOMPLETE-UNRESOLVED-REFERENCE
! WORST REACHABLE  unclassified: Content Writer can invoke
  unresolved-tools:writer

! REVIEW REQUIRED

$ echo $?
3
```

`REVIEW REQUIRED`, exit 3 — a human has to look. In the default `warn`
mode the unclassified tool usually still blocks, because a privileged
tool with no declared audit path trips `policy.missing-action-logging`.

## Version handling

The framework version comes from your `pyproject.toml` `dependencies`,
read as the **lower bound** of whatever specifier is declared — the
oldest version you claim to work with, and therefore the one the adapter
must be able to parse.

```
crewai>=0.86.0        supported
crewai==0.86.0        supported
crewai>=0.1.0         refused: outside the verified range
crewai                refused: unpinned, so undeterminable
(no crewai dependency) refused: undeclared
```

An undeterminable version is treated as **unsupported**, never as
"presumably current." Resolving an unknown to the newest supported
version is how a silent misparse happens.

Widening the supported range requires a conformance fixture proving the
new end still parses; a test fails CI otherwise. The mechanism is shared
with the LangGraph and OpenAI Agents SDK adapters rather than copied.

## Limitations, stated plainly

- **Static resolution is not guaranteed.** How much of a real crew
  resolves depends entirely on how it is written. A project that builds
  its tool lists dynamically will produce mostly unknowns and mostly
  `REVIEW REQUIRED`. A tool list built at runtime (a comprehension, a
  call, a splat, a conditional, a loop that appends, or
  `agent.tools.append` after construction) is reported by
  [`policy.unresolved-dynamic-registration`](policy-rules.md#unresolved-dynamic-registration)
  with the file, line, and agent; a bare name the crew imports stays an
  unresolved reference.
- **A passing scan is not a safety claim.** It tells you what powers the
  crew has, and what changed since you last approved them.
- **Tool capability still comes from your manifest.** Discovery learns
  that `FileWriterTool` exists, not that it writes files.
