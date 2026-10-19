"""Computes direct effective authority, direct capability paths, and
bounded transitive capability paths from already-discovered ACBOM
evidence.

`compute_effective_authority` and `compute_direct_capability_paths` are
deliberately direct-only, as their own docstrings say.
`compute_transitive_capability_paths` is the multi-hop counterpart
those two explicitly deferred: starting from every agent node, it walks
`invokes`, `delegates-to`, `authenticates-as`, and `permitted-by` edges
up to a configurable, enforced depth, and reports every tool, resource,
identity, permission, or data-class node reached *only* transitively --
at two hops or more -- with its full hop chain, never collapsed to its
endpoint. A one-hop path through one of these same four edge types is
already covered by `compute_direct_capability_paths`; this function
does not repeat it. Reaching the depth bound with more of the graph
left unexplored is reported as an `INCOMPLETE-BOUND-EXCEEDED`
diagnostic; a cycle -- an edge that would revisit a node already on the
same path -- is recognized and stopped rather than flattened into an
arbitrarily long path, reported as an `INCOMPLETE-CYCLE-DETECTED`
diagnostic; and a large or adversarial graph that would otherwise
explore or return too much, or run too long, is stopped by one of three
further configurable bounds (`max_explored_paths`, `max_returned_paths`,
`max_seconds`), also reported as `INCOMPLETE-BOUND-EXCEEDED`. None of
these is ever a silent, confident partial answer. See
docs/reference/effective-authority-model.md.
"""

from __future__ import annotations

import hashlib
import time

from controlloop.acbom import (
    Confidence,
    Diagnostic,
    Edge,
    EdgeType,
    Evidence,
    Node,
    NodeType,
    incomplete_diagnostic,
)
from controlloop.acbom.models import Sha256Digest
from controlloop.acbom.serialization import canonical_json_bytes
from controlloop.capability.models import (
    CURRENT_CAPABILITY_SCHEMA_VERSION,
    CapabilityPath,
    EffectiveAuthorityEntry,
    PathHop,
)

_ACTION_EDGE_TYPES = frozenset({EdgeType.READS, EdgeType.WRITES, EdgeType.INVOKES})
#: Mirrors controlloop.capability.models' own (private) constant of the
#: same name -- each module stays self-contained, the same duplication
#: this module already accepts for _ACTION_EDGE_TYPES.
_CAPABILITY_PATH_TARGET_TYPES = frozenset(
    {
        NodeType.TOOL,
        NodeType.RESOURCE,
        NodeType.IDENTITY,
        NodeType.PERMISSION,
        NodeType.DATA_CLASS,
    }
)
_MAX_EVIDENCE = 32
_CONFIDENCE_RANK: dict[Confidence, int] = {
    Confidence.UNKNOWN: 0,
    Confidence.LOW: 1,
    Confidence.MEDIUM: 2,
    Confidence.HIGH: 3,
}

#: The four edge types a transitive walk may chain through: an agent
#: invoking a tool, delegating to another agent, authenticating as an
#: identity, or an identity being permitted-by a permission.
#: Structural/relationship edges, not the read/write/invoke *action*
#: edges `_ACTION_EDGE_TYPES` already covers -- an action is a leaf, not
#: a hop to somewhere else.
_TRANSITIVE_EDGE_TYPES = frozenset(
    {
        EdgeType.INVOKES,
        EdgeType.DELEGATES_TO,
        EdgeType.AUTHENTICATES_AS,
        EdgeType.PERMITTED_BY,
    }
)

#: Conservative default so a naive bounded walk stays cheap on a
#: typical repository-sized graph without every caller having to pick
#: a value themselves.
_DEFAULT_MAX_TRANSITIVE_DEPTH = 5

#: The three graph-explosion bounds. `max_explored_paths`
#: bounds total traversal work (one unit per stack frame popped);
#: `max_returned_paths` bounds the size of the result, a deterministic
#: proxy for memory held by it; `max_seconds` is a wall-clock safety net
#: -- see `compute_transitive_capability_paths`'s own docstring for why
#: only the first two are guaranteed to truncate at the same place on
#: the same graph.
_DEFAULT_MAX_EXPLORED_PATHS = 10_000
_DEFAULT_MAX_RETURNED_PATHS = 1_000
_DEFAULT_MAX_SECONDS = 5.0

_BOUND_EXCEEDED_CODE = "INCOMPLETE-BOUND-EXCEEDED"
_CYCLE_DETECTED_CODE = "INCOMPLETE-CYCLE-DETECTED"
#: Bracket-marker convention for evidence with no
#: real repository-relative path to point to (here: a global bound hit
#: before any edge in the current frame was examined).
_NO_EVIDENCE_MARKER = "<transitive-capability-walk>"

_Key = tuple[str, EdgeType, str, str | None]


def _weaker(left: Confidence, right: Confidence) -> Confidence:
    return left if _CONFIDENCE_RANK[left] <= _CONFIDENCE_RANK[right] else right


def _sort_key(key: _Key) -> tuple[str, str, str, str]:
    agent_id, action, resource_id, permitting_identity_id = key
    return (agent_id, str(action), resource_id, permitting_identity_id or "")


def compute_effective_authority(
    nodes: tuple[Node, ...], edges: tuple[Edge, ...]
) -> tuple[EffectiveAuthorityEntry, ...]:
    """Direct agent-to-action-on-resource authority, one entry per
    unique fact regardless of how many edges assert it or in what order
    they are given, deterministically ordered. An action edge with no
    matching identity still produces an entry, at `Confidence.UNKNOWN`,
    rather than being dropped."""

    agent_ids = {node.id for node in nodes if node.type is NodeType.AGENT}

    identities_by_agent: dict[str, list[tuple[str, Edge]]] = {}
    for edge in edges:
        if edge.type is EdgeType.AUTHENTICATES_AS and edge.source in agent_ids:
            identities_by_agent.setdefault(edge.source, []).append((edge.target, edge))

    accumulated: dict[_Key, tuple[Confidence, list[Evidence]]] = {}

    def _accumulate(
        key: _Key, confidence: Confidence, evidence: tuple[Evidence, ...]
    ) -> None:
        existing = accumulated.get(key)
        if existing is None:
            accumulated[key] = (confidence, list(evidence))
        else:
            existing_confidence, existing_evidence = existing
            existing_evidence.extend(evidence)
            accumulated[key] = (
                _weaker(existing_confidence, confidence),
                existing_evidence,
            )

    for edge in edges:
        if edge.type not in _ACTION_EDGE_TYPES or edge.source not in agent_ids:
            continue

        identities = identities_by_agent.get(edge.source, ())
        if not identities:
            key: _Key = (edge.source, edge.type, edge.target, None)
            _accumulate(key, Confidence.UNKNOWN, edge.evidence)
            continue

        for identity_id, identity_edge in identities:
            key = (edge.source, edge.type, edge.target, identity_id)
            confidence = _weaker(edge.confidence, identity_edge.confidence)
            _accumulate(key, confidence, edge.evidence + identity_edge.evidence)

    entries = []
    for key in sorted(accumulated, key=_sort_key):
        agent_id, action, resource_id, permitting_identity_id = key
        confidence, evidence = accumulated[key]
        deduplicated_evidence = tuple(dict.fromkeys(evidence))[:_MAX_EVIDENCE]
        entries.append(
            EffectiveAuthorityEntry(
                schema_version=CURRENT_CAPABILITY_SCHEMA_VERSION,
                agent_id=agent_id,
                action=action,
                resource_id=resource_id,
                permitting_identity_id=permitting_identity_id,
                confidence=confidence,
                evidence=deduplicated_evidence,
            )
        )
    return tuple(entries)


def effective_authority_digest(
    entries: tuple[EffectiveAuthorityEntry, ...],
) -> Sha256Digest:
    """SHA-256 digest of `entries`, canonicalized the same way the
    ACBOM's own `compute_digest` canonicalizes a document."""

    payload = [entry.model_dump(mode="json") for entry in entries]
    digest_input = canonical_json_bytes(payload)
    return f"sha256:{hashlib.sha256(digest_input).hexdigest()}"


def compute_direct_capability_paths(
    nodes: tuple[Node, ...], edges: tuple[Edge, ...]
) -> tuple[CapabilityPath, ...]:
    """Direct paths from an agent to a tool, resource, identity,
    permission, or data-class node: one path per edge whose source is
    an agent and whose target is one of those five categories, naming
    that edge as the path's single hop with its own evidence.
    Deduplicated by edge ID and deterministically ordered regardless of
    input order."""

    agent_ids = {node.id for node in nodes if node.type is NodeType.AGENT}
    node_type_by_id = {node.id: node.type for node in nodes}

    paths: dict[str, CapabilityPath] = {}
    for edge in edges:
        if edge.id in paths or edge.source not in agent_ids:
            continue
        target_type = node_type_by_id.get(edge.target)
        if target_type not in _CAPABILITY_PATH_TARGET_TYPES:
            continue

        hop = PathHop(
            edge_id=edge.id,
            edge_type=edge.type,
            source_id=edge.source,
            target_id=edge.target,
            evidence=edge.evidence[:_MAX_EVIDENCE],
        )
        paths[edge.id] = CapabilityPath(
            schema_version=CURRENT_CAPABILITY_SCHEMA_VERSION,
            agent_id=edge.source,
            target_id=edge.target,
            target_type=target_type,
            hops=(hop,),
            confidence=edge.confidence,
        )

    return tuple(
        sorted(
            paths.values(),
            key=lambda path: (
                path.agent_id,
                path.target_id,
                str(path.hops[0].edge_type),
            ),
        )
    )


def compute_transitive_capability_paths(
    nodes: tuple[Node, ...],
    edges: tuple[Edge, ...],
    *,
    max_depth: int = _DEFAULT_MAX_TRANSITIVE_DEPTH,
    max_explored_paths: int = _DEFAULT_MAX_EXPLORED_PATHS,
    max_returned_paths: int = _DEFAULT_MAX_RETURNED_PATHS,
    max_seconds: float = _DEFAULT_MAX_SECONDS,
) -> tuple[tuple[CapabilityPath, ...], tuple[Diagnostic, ...]]:
    """Bounded multi-hop paths from an agent to a tool, resource,
    identity, permission, or data-class node, reached only at two hops
    or more through `invokes`, `delegates-to`, `authenticates-as`, or
    `permitted-by` edges. `max_depth` is enforced by an iterative,
    explicitly bounded walk -- never recursion -- so a graph deeper than
    `max_depth` cannot be walked past it regardless of its shape. Every
    returned path names its full hop chain; a one-hop path is
    `compute_direct_capability_paths`'s result, not repeated here.

    A node reached exactly at `max_depth` that still has an outgoing
    transitive edge this walk did not follow produces one
    `INCOMPLETE-BOUND-EXCEEDED` diagnostic per such node, deduplicated
    regardless of how many paths reached it.

    An edge that would revisit a node already present earlier on the
    *same* path is never followed: each
    stack frame carries the set of node IDs already on its own chain,
    so a cycle (self-delegation, a two-node mutual reference, or a
    longer cycle) is recognized and stopped at the closing edge rather
    than being flattened into an arbitrarily long path that just
    happens to stop at `max_depth`. Recognizing and stopping a cycle
    produces one `INCOMPLETE-CYCLE-DETECTED` diagnostic per closing
    edge, deduplicated the same way bound-exceeded diagnostics are.
    Since cycle membership depends only on a path's own chain, not on
    traversal order, this is deterministic regardless of which agent or
    entry point a cycle is first reached from.

    Three further bounds guard against a large or adversarial graph,
    checked once per node popped off the stack: `max_explored_paths`
    caps total traversal work, `max_returned_paths` caps the size of the
    result (a deterministic proxy for the memory it holds), and
    `max_seconds` is a wall-clock safety net. Hitting any of them stops
    the whole walk immediately and produces one
    `INCOMPLETE-BOUND-EXCEEDED` diagnostic naming which bound and
    pointing at the evidence of the last edge examined.
    `max_explored_paths` and `max_returned_paths` are pure counts
    evaluated over a traversal order that is itself made independent of
    input order and of `PYTHONHASHSEED` (agent IDs and each node's
    outgoing edges are processed in a fixed, sorted order rather than
    set/dict iteration order), so the same graph truncates at the same
    place on every run. `max_seconds` cannot make that same promise --
    wall-clock elapsed time is inherently machine- and load-dependent --
    so it is deliberately a secondary, disclosed-non-deterministic
    safety net that realistically only ever fires if the two count-based
    bounds somehow do not, not the primary defense.

    Raises nothing: an empty `nodes`/`edges` input simply produces no
    paths and no diagnostics.
    """

    if max_depth < 1:
        raise ValueError("max_depth must be at least 1")
    if max_explored_paths < 1:
        raise ValueError("max_explored_paths must be at least 1")
    if max_returned_paths < 1:
        raise ValueError("max_returned_paths must be at least 1")
    if max_seconds <= 0:
        raise ValueError("max_seconds must be greater than 0")

    # Sorted, not a bare set/dict-iteration order: the same graph must
    # truncate at the same place regardless of PYTHONHASHSEED, which set
    # iteration order for strings does not guarantee across processes.
    agent_ids = sorted(node.id for node in nodes if node.type is NodeType.AGENT)
    node_type_by_id = {node.id: node.type for node in nodes}
    confidence_by_edge_id: dict[str, Confidence] = {
        edge.id: edge.confidence for edge in edges
    }
    edges_by_source: dict[str, list[Edge]] = {}
    for edge in edges:
        if edge.type in _TRANSITIVE_EDGE_TYPES:
            edges_by_source.setdefault(edge.source, []).append(edge)
    for edge_list in edges_by_source.values():
        edge_list.sort(key=lambda edge: edge.id)

    paths: dict[tuple[str, ...], CapabilityPath] = {}
    truncated_at: dict[str, Evidence] = {}
    cycles_at: dict[str, Evidence] = {}
    exploded_reason: str | None = None
    last_evidence = Evidence(adapter="capability", path=_NO_EVIDENCE_MARKER)

    # Explicit stack, not recursion (bounded, iterative traversal is
    # preferred throughout): one frame per
    # (node reached, hop chain that reached it, originating agent, set
    # of node IDs already visited on this specific chain).
    stack: list[tuple[str, tuple[PathHop, ...], str, frozenset[str]]] = [
        (agent_id, (), agent_id, frozenset({agent_id})) for agent_id in agent_ids
    ]

    explored_count = 0
    deadline = time.monotonic() + max_seconds

    while stack and exploded_reason is None:
        current_id, hops_so_far, origin_agent_id, visited = stack.pop()
        explored_count += 1

        for edge in edges_by_source.get(current_id, ()):
            # Checked per edge, not just once per node popped: a single
            # node's outgoing edges can add several results in one
            # batch, and only a per-edge check keeps `max_returned_paths`
            # a real bound rather than one a single batch can overshoot.
            if explored_count > max_explored_paths:
                exploded_reason = (
                    f"the configured explored-path bound of {max_explored_paths}"
                )
                break
            if len(paths) >= max_returned_paths:
                exploded_reason = (
                    f"the configured returned-path bound of {max_returned_paths}"
                )
                break
            if time.monotonic() >= deadline:
                exploded_reason = (
                    f"the configured wall-clock bound of {max_seconds} seconds"
                )
                break

            last_evidence = edge.evidence[0]

            if len(hops_so_far) >= max_depth:
                if edge.source not in truncated_at:
                    truncated_at[edge.source] = edge.evidence[0]
                continue

            if edge.target in visited:
                if edge.id not in cycles_at:
                    cycles_at[edge.id] = edge.evidence[0]
                continue

            hop = PathHop(
                edge_id=edge.id,
                edge_type=edge.type,
                source_id=edge.source,
                target_id=edge.target,
                evidence=edge.evidence[:_MAX_EVIDENCE],
            )
            new_hops = (*hops_so_far, hop)

            if len(new_hops) >= 2:
                target_type = node_type_by_id.get(edge.target)
                if target_type in _CAPABILITY_PATH_TARGET_TYPES:
                    key = tuple(h.edge_id for h in new_hops)
                    if key not in paths:
                        combined_confidence = Confidence.HIGH
                        for chain_hop in new_hops:
                            combined_confidence = _weaker(
                                combined_confidence,
                                confidence_by_edge_id[chain_hop.edge_id],
                            )
                        paths[key] = CapabilityPath(
                            schema_version=CURRENT_CAPABILITY_SCHEMA_VERSION,
                            agent_id=origin_agent_id,
                            target_id=edge.target,
                            target_type=target_type,
                            hops=new_hops,
                            confidence=combined_confidence,
                        )

            stack.append(
                (edge.target, new_hops, origin_agent_id, visited | {edge.target})
            )

    bound_diagnostics = [
        incomplete_diagnostic(
            code=_BOUND_EXCEEDED_CODE,
            message=(
                f"transitive capability traversal stopped at the "
                f"configured depth bound of {max_depth}; further "
                "capabilities reachable from this node were not explored"
            ),
            evidence=(evidence,),
        )
        for evidence in truncated_at.values()
    ]
    if exploded_reason is not None:
        bound_diagnostics.append(
            incomplete_diagnostic(
                code=_BOUND_EXCEEDED_CODE,
                message=(
                    f"transitive capability traversal stopped early because "
                    f"{exploded_reason} was reached; the result is a partial "
                    "view of the graph, not a confident complete answer"
                ),
                evidence=(last_evidence,),
            )
        )
    cycle_diagnostics = (
        incomplete_diagnostic(
            code=_CYCLE_DETECTED_CODE,
            message=(
                "transitive capability traversal detected a cycle and "
                "stopped rather than looping or reporting an arbitrarily "
                "long path through it"
            ),
            evidence=(evidence,),
        )
        for evidence in cycles_at.values()
    )
    diagnostics = tuple(
        sorted(
            (*bound_diagnostics, *cycle_diagnostics),
            key=lambda diagnostic: (diagnostic.evidence[0].path or "", diagnostic.code),
        )
    )

    ordered_paths = tuple(
        sorted(
            paths.values(),
            key=lambda path: (
                path.agent_id,
                path.target_id,
                tuple(hop.edge_id for hop in path.hops),
            ),
        )
    )
    return ordered_paths, diagnostics
