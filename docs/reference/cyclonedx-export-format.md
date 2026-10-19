---
type: reference
title: CycloneDX export format
tags:
  - reference
  - export
  - cyclonedx
created: 2026-08-21
---

# CycloneDX export format

`controlloop bom --format cyclonedx` projects an
already-built ACBOM into a CycloneDX 1.6 BOM document -- a reduced
projection, by a recorded design decision, never a full
re-serialization of the native ACBOM.

## Why reduced, not full

CycloneDX output travels further than any other artifact this CLI
produces -- to auditors, to customers, into procurement. The native
ACBOM carries source file paths, line ranges, parser/adapter
implementation detail, per-finding confidence grades, and analysis
diagnostics that are appropriate internally and inappropriate in a
compliance attachment. `controlloop.reporting.cyclonedx.render_cyclonedx`
never reads `Evidence.path`/`line_start`/`line_end`/`parser`/
`schema_id`, `Diagnostic` records, or `Node`/`Edge` `confidence` --
these fields are absent from the output by construction, not by a
filtering step layered on top that could regress.

## Node type mapping

CycloneDX 1.6 has no agent-specific component taxonomy. Three of the
eight ACBOM node types project into a CycloneDX `component`:

| ACBOM node type | CycloneDX `component.type` | Reasoning |
| --- | --- | --- |
| `agent` | `application` | An agent is itself executable software. |
| `tool` | `library` | An invocable capability the agent depends on. |
| `resource` | `data` | A collection of information the agent reads or writes. |

The other five node types (`identity`, `permission`, `data-class`,
`trigger`, `policy-boundary`) have no CycloneDX component
representation at all and are never emitted as one.

## Edge type mapping

Four of the eight ACBOM edge types, when both endpoints are themselves
projected nodes, become a CycloneDX `dependencies` entry (the source
node `dependsOn` the target node):

- `invokes`
- `reads`
- `writes`
- `receives-from`

The other four edge types (`authenticates-as`, `permitted-by`,
`delegates-to`, `constrained-by`) have no CycloneDX dependency
representation, regardless of their endpoints.

## Lossy export is never silent

Every node or edge the mappings above cannot represent produces one
lossy-export diagnostic string, naming the specific node or edge id and
its type. `bom --format cyclonedx` reports a one-line count of these to
standard error (see [CLI reference](cli.md#bom)); the CycloneDX
document itself never contains a placeholder or a fabricated
representation for something ACBOM found but CycloneDX cannot express.

## Specification version

Pinned to **CycloneDX 1.6**, the latest stable release at the time of
that decision. No formal CycloneDX agent-specific component type
or extension existed at that time -- re-verify the current CycloneDX
specification state at <https://cyclonedx.org> before assuming this
pin is still current; revisiting it, if CycloneDX ratifies an
agent-specific extension, is its own future decision, not silently
absorbed into this exporter.

## What is never included

- No timestamp anywhere in the document (`metadata.timestamp` is
  optional in the CycloneDX schema) -- identical input produces
  byte-identical output, the same determinism invariant every other
  `controlloop.reporting` module preserves.
- No source file path, line number, parser identity, or schema
  identity (`Evidence`'s own fields).
- No analysis diagnostic (`Diagnostic` records) or confidence grade
  (`Node`/`Edge.confidence`).
