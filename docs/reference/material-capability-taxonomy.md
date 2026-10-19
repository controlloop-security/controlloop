---
type: reference
title: Material capability taxonomy
tags:
  - reference
  - capability
created: 2026-08-20
---

# Material capability taxonomy

**Status: Implemented foundation.** The taxonomy and its classifier
are implemented and tested library code. `classify_material_capability`
is called throughout several registered rules (see [Concrete policy
rules](policy-rules.md)), all wired into `scan` and `gate`. This page is
written and reviewed in the same change as the behavior it documents.

## What this is

A versioned classification of what makes a capability consequential.
Every downstream consumer that says "material," "privileged," or
"worst reachable action" resolves to this taxonomy -- defined once so
that the diff summaries, the blast-radius statement, several policy
rules, and others do not each invent their own severity ladder.

## The eight classes

```python
class MaterialCapabilityClass(StrEnum):
    UNCLASSIFIED = "unclassified"
    DESTRUCTIVE_ACTION = "destructive-action"
    FINANCIAL_ACTION = "financial-action"
    CODE_EXECUTION = "code-execution"
    EXTERNAL_COMMUNICATION = "external-communication"
    SENSITIVE_DATA_ACCESS = "sensitive-data-access"
    DELEGATION = "delegation"
    WRITE_ACCESS = "write-access"
```

Seven are substantive classes; `UNCLASSIFIED` is an eighth, for a
capability this taxonomy could not resolve one way or the other (see
"Unknown, never harmless" below).

## Defined by observable graph properties, not name matching

Every class reads a field the canonical ACBOM already models on every
node and edge -- nothing here inspects a node's or edge's *name*:

| Class | Observable property |
| --- | --- |
| Destructive action | `security_attributes.destructive` |
| Financial action | `security_attributes.financial_action` |
| Code execution | `security_attributes.code_execution` |
| External communication | `security_attributes.external_communication` |
| Sensitive-data access | `security_attributes.sensitivity` in `{confidential, restricted}`, or a non-empty `data_classifications` |
| Delegation | the edge's own `type` is `delegates-to` |
| Write access | the edge's own `type` is `writes`, or `invokes` with `security_attributes.read_only` explicitly `false` |

`classify_material_capability` takes a `SecurityAttributes` value
directly (and, for the two structural classes, an optional `EdgeType`)
-- not a `CapabilityPath` or an `EffectiveAuthorityEntry`. Neither of
those two models carries `SecurityAttributes` itself:
`EffectiveAuthorityEntry` is a flattened `(agent_id, action,
resource_id, permitting_identity_id)` fact, and a `CapabilityPath`'s
hops carry edge IDs, types, and evidence, not security attributes. A
caller classifying a path or an authority entry looks up the relevant
node's or edge's own `security_attributes` and passes it here.

```python
def classify_material_capability(
    security_attributes: SecurityAttributes,
    *,
    edge_type: EdgeType | None = None,
) -> frozenset[MaterialCapabilityClass]: ...
```

## Multiple classes, all reported

The return type is a `frozenset`, not a single value. A tool that both
deletes data and posts a webhook is both `destructive-action` and
`external-communication` -- both are reported, never collapsed to one.

## Unknown, never harmless

Every relevant `SecurityAttributes` field is `KnownBoolean | None`,
where `KnownBoolean = bool | Literal["unknown"]` -- three states, not
two:

- `None` -- no adapter asserted anything about this field. Ordinary
  absence, not ambiguity. Contributes nothing.
- `False` -- definitively known not to apply. Contributes nothing.
- `"unknown"` -- explicitly asserted as indeterminate. Adds
  `MaterialCapabilityClass.UNCLASSIFIED` to the result.

The distinction matters: an adapter that never populated
`destructive` at all (`None`) is not making the same claim as one that
inspected the value and could not determine it (`"unknown"`). Only the
second is unclassifiable, and it is marked as such rather than
silently treated as harmless -- the same "unknown, never omitted"
principle this codebase applies everywhere else.

## Worst reachable action

```python
def worst_class(
    classes: Iterable[MaterialCapabilityClass],
) -> MaterialCapabilityClass: ...
```

Ordered worst to least severe, by blast radius and reversibility:

1. **`unclassified`** -- an unknown risk must never be treated as safer
   than a known one.
2. **`destructive-action`** -- direct, often irreversible harm.
3. **`financial-action`** -- direct, often irreversible monetary harm.
4. **`code-execution`** -- an unbounded escalation primitive that can
   lead to any of the others.
5. **`external-communication`** -- risks exfiltration.
6. **`sensitive-data-access`** -- read-level exposure, no action taken
   yet.
7. **`delegation`** -- expands the trust boundary only indirectly,
   through another agent.
8. **`write-access`** -- to an otherwise unclassified resource, the
   mildest form of "material."

This ordering is a disclosed, reasoned judgment call, not derived from
anything already in the codebase -- there was no prior severity ranking
to reuse. It remains open to revision.

## Determinism

`classify_material_capability` is a pure function of its arguments: the
same `SecurityAttributes` and `EdgeType` always produce the same
result. Every one of the eight classes has its own positive test
fixture, plus fixtures distinguishing `None` from `"unknown"` for every
relevant field.

## Known limitations

- `classify_material_capability` is consumed directly by several
  registered rules (see [Concrete policy rules](policy-rules.md)), all
  wired into `scan` and `gate`; the diff's change classification and
  material change summary do not call it themselves -- it exists as
  tested library code there, the same position
  `compute_effective_authority` and `compute_direct_capability_paths`
  were in before their own downstream consumers existed.
- The severity ordering is a reasoned judgment call, not derived from
  an external standard, and remains open to revision.

## Next steps

- Review [Effective authority model](effective-authority-model.md) for
  the capability-analysis models this taxonomy is meant to classify.
- Review [Adapter status](../adapters/readme.md) for what discovery
  currently produces the `SecurityAttributes` this taxonomy reads.

## Nothing is classified until the repository declares it

`classify_material_capability` reads a node's `SecurityAttributes`. No
shipped offline adapter sets `destructive`, `financial_action`,
`read_only`, or `sensitivity`, and the two attributes adapters do set --
`code_execution` on an MCP server, `external_communication` on an
external delegation target -- sit on nodes no agent has an edge to.

So before `tool_capabilities` existed, **no real repository scan could
classify anything as material**: `compute_blast_radius` always returned `None`, the
material change summary was always empty, and the capability reduction
report could never name a class. Every golden report in
`tests/fixtures/golden/` still shows that original state as
`"blast_radius": null`.

A repository makes its capabilities classifiable by declaring what its
tools do, with
[`tool_capabilities`](manifest-schema.md#declaring-what-a-tool-does-tool_capabilities)
in `controlloop.yaml`. Tools are the annotation point because an agent
reaches its tools in one `invokes` hop. Resources are **not** reachable
from an agent at all: the only edges into them are
`tool --reads/writes--> resource`, and neither `reads` nor `writes` is a
traversable edge type in `compute_transitive_capability_paths`. That is
why the `resource:`-keyed `data_classification` field cannot serve this
purpose.
