---
type: reference
title: LangGraph support
tags:
  - reference
  - adapters
  - frameworks
created: 2026-09-01
---

# LangGraph support

**Status: available.** `controlloop scan` discovers LangGraph
applications, their graph topology, and their tool bindings. Every
output below is real recorded output.

Supported versions: **`langgraph>=0.2,<1.0`**, governed by the same
registry as [CrewAI](crewai-support.md). A project declaring a version
outside that range, or declaring none, is refused rather than parsed
hopefully.

## What is discovered

| Construct | Read from | Becomes |
| --- | --- | --- |
| each entry in `graphs` | `langgraph.json` | an `agent` node named by its graph key |
| `add_node("name", fn)` | the graph module | a `tool` node, plus an `invokes` edge from the graph |
| `add_edge("a", "b")` | the graph module | a `delegates-to` edge |
| `add_conditional_edges(...)` | the graph module | a `delegates-to` edge to **every** target |
| `ToolNode([...])`, `bind_tools([...])` | the graph module | a `tool` node each, plus an `invokes` edge |

`langgraph.json` is read first and needs no source parsing at all: it
names every graph and the `module.py:attribute` it lives at.

## Every branch of a router is reachable

This is the part worth understanding.

```python
builder.add_conditional_edges("plan", route, {"research": "research", "write": "write"})
```

`route` decides at runtime. ControlLoop emits **both**:

```
plan --delegates-to--> research
plan --delegates-to--> write
```

Picking the likeliest branch would report a graph narrower than the one
that actually runs — a confident answer quietly smaller than reality,
which is more dangerous than an obviously incomplete one.

`START` and `END` are recognized as LangGraph's own sentinels, not
mistaken for computed values. Flagging every idiomatic graph as
partially unknown would be a false alarm that teaches readers to ignore
the real ones.

## What is reported as unknown

Only a **literal list** resolves. Everything else produces an
`INCOMPLETE-UNRESOLVED-REFERENCE` diagnostic **and** a node whose
security attributes are literally `"unknown"`:

```python
ToolNode([TavilySearchResults()])  # resolves
ToolNode(build_publish_tools())  # unknown
builder.add_node(name, make(name))  # unknown -- graph shape not fully known
add_conditional_edges("plan", route, computed_map)  # unknown targets
```

An `"unknown"` attribute classifies as `UNCLASSIFIED`, which the
[material capability taxonomy](material-capability-taxonomy.md) ranks
**worst of all**, so an unreadable binding becomes the worst reachable
capability:

```
! WORST REACHABLE  unclassified: research-graph can invoke
  unresolved-tools:research-graph
```

Under `completeness_enforcement = "enforce"` that reaches
`REVIEW REQUIRED`, exit 3.

## Environment values are never read

`langgraph.json`'s `env` is usually a **path** to a `.env` file, which
holds real values:

```json
{ "env": "./.env" }
```

That file is **never opened**. A path contributes only the fact that an
environment file is declared (`env:declared-env-file`). Only an inline
`env` mapping contributes `env:NAME` scopes, and only its keys.

A committed `.env` is a secret-leak problem for the secret scanner to
find; an adapter that parsed it would be one bug away from putting a
credential into an ACBOM. A redaction canary asserts a committed
credential never reaches the ACBOM.

## What is not read at all

- **`dockerfile_lines`, `python_version`, `store`, `auth`.** Deployment
  configuration, not capability.
- **`dependencies`.** Recorded as evidence for version governance;
  never installed, resolved, or fetched.
- **Tool implementations.** What `TavilySearchResults` *does* is not
  stated anywhere a scanner can read. Declare it in `controlloop.yaml`
  under `tool_capabilities`.
- **Anything at runtime.** No LangGraph code is imported, executed, or
  evaluated.

## Limitations

- Graph construction that this adapter cannot follow — a loop building
  nodes, a helper returning a builder — is reported as dynamic rather
  than partially discovered. Partial discovery of a graph is worse than
  none, because it looks complete.
- A passing scan is not a safety claim.
- The worked example is
  [`scenarios/research-graph`](reference-agent.md) in the reference
  repository.
