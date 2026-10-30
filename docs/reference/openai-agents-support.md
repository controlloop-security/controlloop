---
type: reference
title: OpenAI Agents SDK support
tags:
  - reference
  - adapters
  - frameworks
created: 2026-09-01
---

# OpenAI Agents SDK support

**Status: available.** `controlloop scan` discovers agents, handoffs,
function tools, and agent-to-tool wiring. Every output below is real
recorded output.

Supported versions: **`openai-agents>=0.1,<2.0`**, governed by the same
registry as [CrewAI](crewai-support.md) and
[LangGraph](langgraph-support.md).

## There is no configuration file

Unlike LangGraph (`langgraph.json`), and CrewAI's scaffolded
`config/agents.yaml`, this SDK ships nothing declarative. Detection keys on the SDK's own
import instead:

```python
from agents import Agent, function_tool, handoff
```

A module that merely mentions `agents` as data is not claimed — the
check is on real import syntax.

## What is discovered

| Construct | Becomes |
| --- | --- |
| `Agent(name="Triage")` | an `agent` node |
| `handoffs=[billing_agent]` | a `delegates-to` edge |
| `@function_tool def lookup_order(...)` | a `tool` node |
| `@function_tool(name_override="issue-refund")` | a `tool` node under the override |
| `tools=[lookup_order]` | an `invokes` edge |
| `specialist.as_tool()` | an `invokes` edge — **not** a handoff |

### `as_tool` is not a handoff

A handoff **transfers the conversation**. `as_tool` calls into an agent
and returns. Collapsing them would overstate what the caller gave away,
so they produce different edge types.

## Tools are found at their definition site

This is the structural advantage this SDK has, and the reason it earns
an adapter despite shipping no config file.

`@function_tool` marks a tool where it is *defined*, so the set of tools
that exist is knowable even when the set an agent holds is not:

```python
@function_tool
def purge_customer(customer_id: str) -> str: ...
```

Nothing references that function. It is discovered anyway, and reported:

```
! tool 'purge_customer' is defined but wired to no agent, so nothing in
  this module can reach it
```

An unreferenced destructive function is exactly what a reviewer wants
told about, and an adapter reading only agent wiring would never see it.
It also means a dynamic `tools=[...]` costs you *which agent holds this*
without destroying *this tool exists* — a better degradation curve than
either other framework adapter gets.

## One resolution step, and exactly one

Neither other adapter needed to resolve a variable. This one does:

```python
billing_agent = Agent(name="Billing", tools=[issue_refund])
triage_agent = Agent(name="Triage", handoffs=[billing_agent])
```

ControlLoop maps a variable to the agent assigned to it, from
module-level assignments in the **same module**. That is the whole
mechanism. No import following, no cross-module resolution, no value
tracking through reassignment. Anything beyond it is reported, never
guessed — a partial Python interpreter is how a static analyzer starts
inventing capability paths a reviewer then trusts.

## What is reported as unknown

- a **computed agent name** — `Agent(name=build_name())` — reported
  rather than synthesized, because a made-up identity is worse than a
  missing one: a manifest would then match a name no human wrote;
- a non-literal `tools` or `handoffs` list;
- a handoff target that resolves to no declared agent;
- a `function_tool` decorator whose `name_override` is computed, since
  the name is what a manifest must match.

Each produces an `INCOMPLETE-UNRESOLVED-REFERENCE` **and**, for tool
wiring, a node whose attributes are literally `"unknown"` — which
classifies as `UNCLASSIFIED` and ranks worst in the
[material taxonomy](material-capability-taxonomy.md), so the blast
radius names it.

## Privacy

A function tool contributes its parameter **names** only, as
`param:<name>` scopes. No default value, docstring body, or literal
argument reaches identity material or evidence. A redaction canary
asserts a secret-shaped default never appears in the ACBOM.

## What is not read

- **Instructions and prompts.** Prompt text is not capability.
- **Guardrails.** Not modelled today.
- **What a tool does.** Discovery learns `issue-refund` exists, not that
  it moves money. Declare that in `controlloop.yaml` under
  `tool_capabilities`.
- **Anything at runtime.** No module is imported, executed, or
  evaluated.

## Worked example

[`scenarios/support-desk`](reference-agent.md) in the reference
repository: Triage reaches a refund tool **three hops away**, through
two handoffs, and neither agent's own definition shows it.
