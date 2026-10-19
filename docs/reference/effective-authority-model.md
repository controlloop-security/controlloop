---
type: reference
title: Effective authority model
tags:
  - reference
  - capability
created: 2026-08-20
---

# Effective authority model

**Status: Implemented foundation.** The model and computation described
below are implemented and tested library code. `compute_effective_authority`
is called from `cli.py`'s `init`, `diff`, and the shared baseline path
`scan` and `gate` both use, computing effective authority from a live
scan. This page is written and reviewed in the same change as the
behavior it documents, so that the model is documented before
implementation, not after.

## What this is

Effective authority is the set of facts a scan actually establishes:
*this agent can take this action on this resource, and this identity is
what permits it.* Every downstream diff, policy rule, and report is
meant to compute against this set rather than walking the raw ACBOM
graph itself -- one shared, versioned definition of "what can this
agent really do," not a different interpretation in every consumer.

## The model

```python
class EffectiveAuthorityEntry:
    schema_version: str  # semantic version, e.g. "1.0.0"
    agent_id: str  # the acting agent's canonical node ID
    action: EdgeType  # reads | writes | invokes
    resource_id: str  # the target node's canonical node ID
    permitting_identity_id: str | None  # None = identity unknown
    confidence: Confidence
    evidence: tuple[Evidence, ...]
```

`action` is restricted, at the model level, to `reads`, `writes`, and
`invokes` -- the edge types that represent an agent doing something to
a resource. `delegates-to`, `authenticates-as`, `permitted-by`,
`constrained-by`, and `receives-from` describe the graph's structure,
not an action on a resource, so they cannot appear here by construction.

## Scope: direct authority only

`EffectiveAuthorityEntry` records **direct** authority only: one
`agent --action--> resource` edge, from an agent node directly (never a
tool acting on the agent's behalf), paired with whatever
`agent --authenticates-as--> identity` edge exists for that same agent,
if any.

Two separate models build on this one rather than this one absorbing
their scope:

- **Direct capability paths** (implemented -- see below) -- what is
  directly reachable from an agent, by any single edge, across a
  broader set of target categories than this model's resource-only
  scope.
- **Bounded transitive capability paths** (implemented -- see below) --
  multi-hop authority reachable through chains: delegation,
  tool-calls-tool, and similar.

The definition -- "effective authority is defined as a set of
agent-to-action-on-resource tuples with the identity that permits each
one" -- requires *defining* the tuple and computing its simplest,
single-edge case; it does not require graph traversal, which is the
transitive paths' job. Building that traversal here would widen this
model's scope silently.

## Direct capability paths

`CapabilityPath` (`controlloop.capability.compute_direct_capability_paths`)
answers a different, complementary question: not "what action is this
agent authorized to take on a resource, and under what identity" but
"what is directly reachable from this agent, and by what edge." It is
broader than `EffectiveAuthorityEntry` in the target categories it
covers -- tool, resource, identity, permission, and data-class nodes,
not just resources reached by a reads/writes/invokes edge -- and more
structural in what it records: every path names the full sequence of
hops that produced it (`hops: tuple[PathHop, ...]`), each hop carrying
its own evidence, not just the path's endpoints.

```python
class PathHop:
    edge_id: str
    edge_type: EdgeType
    source_id: str
    target_id: str
    evidence: tuple[Evidence, ...]


class CapabilityPath:
    schema_version: str  # semantic version, e.g. "1.0.0"
    agent_id: str
    target_id: str
    target_type: NodeType  # tool | resource | identity | permission | data-class
    hops: tuple[PathHop, ...]  # non-empty; direct paths populate exactly one
    confidence: Confidence
```

`hops` is plural and ordered for the bounded transitive paths below --
a direct path only ever populates exactly one hop: a direct edge from an
agent node to one of the five target categories.

**Disclosed gap: "data class" paths.** None of the eight canonical edge
types represents "this resource carries this data classification" --
`SecurityAttributes.data_classifications` is an inline attribute tuple
on a node itself, not a graph edge to a standalone `data-class` node.
`compute_direct_capability_paths` is still structurally ready for a
`data-class`-typed node reached by any edge -- the target-type check is
generic, not restricted to specific edge types -- but since no adapter
currently produces a standalone `data-class` node, this path category
is honestly empty today, not fabricated.

`EffectiveAuthorityEntry` and `CapabilityPath` are deliberately kept as
two distinct models rather than unified into one: the former is a
narrow, security-focused two-edge join evaluated for its own sake; the
latter is a general graph path that the transitive computation below
extends into real multi-hop traversal.

## Bounded transitive capability paths

`compute_transitive_capability_paths` is the multi-hop counterpart both
effective authority and direct capability paths explicitly leave out:
this is the whole premise of the product -- a reviewer who can only
see direct grants can already read a config file; the value is in the
second and third hop. Starting from every agent node, it walks `invokes`, `delegates-to`,
`authenticates-as`, and `permitted-by` edges (the four edge types that
connect an agent to something else it can reach through, as opposed to
`reads`/`writes`, which are terminal actions) up to a configurable,
enforced `max_depth` (default 5), and reports every tool, resource,
identity, permission, or data-class node reached **only**
transitively -- at two hops or more -- with its full hop chain, never
collapsed to its endpoint.

```python
def compute_transitive_capability_paths(
    nodes: tuple[Node, ...],
    edges: tuple[Edge, ...],
    *,
    max_depth: int = 5,
    max_explored_paths: int = 10_000,
    max_returned_paths: int = 1_000,
    max_seconds: float = 5.0,
) -> tuple[tuple[CapabilityPath, ...], tuple[Diagnostic, ...]]: ...
```

A target reachable in exactly one hop through one of these same four
edge types is `compute_direct_capability_paths`'s own result --
`compute_transitive_capability_paths` does not repeat it, so combining
both functions' output never double-counts a path.

**Reaching the depth bound is reported, not silently truncated.** A
node reached exactly at `max_depth` that still has an outgoing
transitive edge this walk did not follow produces one
`INCOMPLETE-BOUND-EXCEEDED` diagnostic per such node (an already
registered code), deduplicated regardless of how many
paths reached it. Confidence across a multi-hop path is the weakest
confidence of any hop in the chain, the same "a chain is only as strong
as its weakest link" reasoning effective authority's identity pairing
already uses.

**Model change: `CapabilityPath` now validates that hops actually
connect.** Previously, `CapabilityPath` only checked that the first
hop started at `agent_id` and the last hop ended at `target_id` --
vacuously true for single-hop direct paths, but not sufficient for a
genuine multi-hop chain. `validate_hops_form_a_contiguous_chain` now
requires `hops[i].target_id == hops[i+1].source_id` for every
consecutive pair, so a non-contiguous "path" is rejected by the model
itself, not just by whichever compute function happens to build it
correctly.

Graph explosion bounds (see below) and cycle protection (see below)
have since closed both of this section's original disclosed gaps -- a
cycle can no longer be walked around repeatedly within the
depth budget, and a highly connected acyclic graph can no longer
produce an unbounded number of paths within `max_depth` either.

## Cycle protection

Each stack frame `compute_transitive_capability_paths` traverses now
carries the set of node IDs already visited on its *own* chain
(starting from the originating agent). Before following an edge, if its
target is already in that set, the edge is not followed: this is a
cycle -- self-delegation, mutual delegation, or a longer ring of
tool-calls-tool -- and continuing would flatten it into an arbitrarily
long path that just happens to stop at `max_depth`, rather than
representing what actually happened.

A blocked edge produces one `INCOMPLETE-CYCLE-DETECTED` diagnostic
(the diagnostic registry's third extension), deduplicated by the
closing edge's ID -- the same closing edge reached from multiple
originating chains produces one diagnostic, not one per chain. Two agents independently discovering the *same* two-node cycle
from opposite directions genuinely close on two different edges (A's
chain closes on the B-\>A edge, B's chain closes on the A-\>B edge), so
that case is correctly reported as two diagnostics, not deduplicated
away.

This tracking is deliberately per-path, not a single global "ever
visited" set: two different chains legitimately converging on the same
node from different directions (a diamond, not a cycle) must still be
explored both ways and both paths reported -- direct capability
paths' own dedup-by-full-hop-sequence design already assumes this.

Any `CapabilityPath` already recorded for nodes visited *before* a
cycle's closing edge remains valid and unaffected; only the specific
revisit is stopped, so genuine progress made before a cycle closes is
never lost.

## Graph explosion bounds

Three further bounds, checked once per outgoing edge examined, guard
`compute_transitive_capability_paths` against a large or adversarial
graph -- one per resource dimension: work, result size, and time:

- **`max_explored_paths`** (default 10,000) -- total traversal work,
  counted as one unit per node the walk actually looks at.
- **`max_returned_paths`** (default 1,000) -- the size of the result.
  "Memory" is deliberately not measured as a live OS reading, which
  would vary by machine and run and so could never satisfy the
  determinism requirement below -- it is represented instead by the one
  thing this function allocates that scales with graph size: the result
  itself. The same reasoning `controlloop.repository.TraversalBounds`
  already applies to its own byte-count-based resource bounds rather
  than live memory reads.
- **`max_seconds`** (default 5.0, matching `mcp_live.py`'s own existing
  timeout convention) -- a real wall-clock deadline.

Hitting any of the three stops the whole walk immediately (at most one
of the three ever fires per call) and produces one
`INCOMPLETE-BOUND-EXCEEDED` diagnostic naming the specific bound that
was hit and pointing at the evidence of the last edge examined.

**The determinism claim holds fully for the first two bounds, and is
explicitly disclosed as not holding for the third.** `max_explored_
paths` and `max_returned_paths` are pure counts over a traversal order
that is also independent of input order and of
`PYTHONHASHSEED` -- agent IDs are sorted before seeding the walk, and
each node's outgoing edges are sorted by edge ID, rather than relying
on `set`/`dict` iteration order (which the codebase's own determinism
harness, `tests/determinism_support.py`, deliberately varies across
processes). `max_seconds` cannot make the same promise: wall-clock
elapsed time is inherently machine- and load-dependent, so it is a
disclosed non-deterministic safety net, not this function's primary
defense -- checking an integer counter is so much cheaper than doing
real traversal work that `max_explored_paths` realistically always
fires first on any graph the count bound was sized to catch.

## Determinism and the digest

Identical input -- the same nodes and edges, in any order -- always
produces the same effective authority set: computation deduplicates by
`(agent_id, action, resource_id, permitting_identity_id)`, unions the
evidence of exact duplicates, and returns entries in a fixed sorted
order. `effective_authority_digest` hashes that canonical, sorted list
using the same canonicalization primitive
(`controlloop.acbom.serialization.canonical_json_bytes`) the ACBOM's
own `compute_digest` uses, so "contributes to the canonical digest"
 is the same mechanism applied to a new input, not a second one.

## Unknown authority is never dropped

An `agent --action--> resource` edge with no matching
`authenticates-as` edge still produces an entry --
`permitting_identity_id=None`, `confidence=Confidence.UNKNOWN` -- rather
than being silently omitted. A capability whose granting identity is
unknown is still a capability; omitting it would produce a confident
pass on authority that was never actually verified, the worst failure
mode this product can have.

## Known limitations

- `compute_effective_authority` is called from `cli.py` (`init`, `diff`,
  and the shared baseline path `scan`/`gate` use), and the
  capability-path functions are called by multiple registered rules
  wired into `scan`/`gate`.
- `EffectiveAuthorityEntry` is still direct, single-edge only by
  design -- see its own scope section above.
- `compute_transitive_capability_paths` has cycle protection and
  graph explosion bounds. Its `max_seconds` bound is disclosed as
  the one non-deterministic safety net among its bounds -- see the
  graph explosion bounds section above.
- The "data class" capability path category is structurally ready but
  empty today; see the disclosed gap above.
- The schema is not yet published at a public URL, the same position
  the ACBOM's and the manifest's own schemas are in.

## Next steps

- Review [Adapter status](../adapters/readme.md) for what discovery
  currently produces this model computes against.
- Review [Capability ceiling declaration](capability-ceiling.md) for
  the manifest-side boundary this model's output is checked against.

## Whether an entry is *material* depends on the manifest

An `EffectiveAuthorityEntry` records that an agent can take an action on
a target. Whether that fact is **material** -- worth a blast-radius
statement, a material change summary line, or a reduction report entry
-- is decided by `classify_material_capability` from the target node's
own `SecurityAttributes`.

Discovery alone almost never sets those. A repository declares them with
[`tool_capabilities`](manifest-schema.md#declaring-what-a-tool-does-tool_capabilities);
see [Material capability taxonomy](material-capability-taxonomy.md) for
why tools rather than resources are the annotation point.
