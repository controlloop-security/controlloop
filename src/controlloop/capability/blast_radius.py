"""Blast-radius statement.

Every result leads with one sentence naming the worst action now
reachable, before any list of findings. `compute_blast_radius` scans
one ACBOM graph's full capability surface -- every direct
effective-authority fact (`compute_effective_authority`) and every
bounded transitive capability path (`compute_transitive_capability_paths`,
two hops or more; a one-hop path is a direct fact's own result, never
double-counted) -- classifies each against
`controlloop.capability.taxonomy`'s material classes, and names the
single worst-ranked one by `worst_class`'s already-defined ordering.
This module computes over *one* graph; it has no dependency on
`controlloop.diff` and performs no baseline comparison -- the question
it answers ("what is the worst thing this graph's capability surface
reaches") is the same "what can this agent really do" question every
other `controlloop.capability` module already answers, not a
before/after diff.

`CapabilityPath` carries no `permitting_identity_id` field the way
`EffectiveAuthorityEntry` does. For a transitive fact, the permitting
identity (when present) is derived by scanning the path's own hops for
an `AUTHENTICATES_AS` edge and naming its target -- not a new field on
an already-shipped model.

The statement is generated deterministically from structured data by
template, and no model produces it. That holds by construction:
`describe_blast_radius` renders `BlastRadiusStatement`'s own
already-computed fields through a fixed template -- there is no model
call anywhere in this module's or its callees' import graph.

Where analysis is incomplete, the statement is qualified: `incomplete`
is `True` whenever `compute_transitive_capability_paths` returned any
`INCOMPLETE-BOUND-EXCEEDED`/`INCOMPLETE-CYCLE-DETECTED` diagnostic
anywhere in the graph, regardless of whether the winning fact itself was
direct or transitive -- an unexplored deeper path could always turn out
worse, so any bound firing anywhere means this statement cannot claim
completeness.

The statement appears first in human output and as a discrete field in
machine output. That is satisfied structurally, not by an actual report
assembler: no scan or gate report existed when this module was written
for this statement to literally be prepended to. `BlastRadiusStatement`
is designed to be a top-level field in a future JSON/SARIF report, never
folded into a findings array, and `describe_blast_radius`'s returned
lines are designed to be emitted before any findings list -- a contract
for that future report assembler to honor, disclosed here and in
docs/reference/diff-output-format.md rather than silently assumed.

The worst reachable action also accounts for agent authority. A
code-execution hook is already a fact like any other (`invokes` a hook
that executes code). Two things are not edges, so the statement names
them alongside the worst action: agent hosts or subagents configured in
a bypass mode (`bypass_agents`), which act on every reachable capability
without asking, and over-privileged workflow runtimes
(`overprivileged_workflows`, `controlloop.capability.agent_authority`).
Both are left out of the serialized statement when empty, so a graph
with no agent authority serializes exactly as before.
"""

from __future__ import annotations

from pydantic import Field

from controlloop.acbom.models import DisplayName, Edge, EdgeType, Node, NodeId
from controlloop.capability.agent_authority import overprivileged_workflow_reason
from controlloop.capability.compute import (
    compute_effective_authority,
    compute_transitive_capability_paths,
)
from controlloop.capability.models import (
    CapabilityPath,
    EffectiveAuthorityEntry,
    PathHop,
    _CapabilityModel,
)
from controlloop.capability.taxonomy import (
    MaterialCapabilityClass,
    classify_material_capability,
    worst_class,
)

CURRENT_BLAST_RADIUS_SCHEMA_VERSION = "1.0.0"


class BlastRadiusStatement(_CapabilityModel):
    """The single worst-ranked reachable action in a graph, as a
    discrete, independently serializable field -- never folded into
    prose-only text."""

    schema_version: str
    material_class: MaterialCapabilityClass
    agent_id: NodeId
    agent_name: DisplayName
    action: EdgeType
    target_id: NodeId
    target_name: DisplayName
    permitting_identity_id: NodeId | None = None
    permitting_identity_name: DisplayName | None = None
    transitive: bool
    path: tuple[PathHop, ...] = ()
    incomplete: bool
    bypass_agents: tuple[DisplayName, ...] = Field(
        default=(), exclude_if=lambda value: not value
    )
    overprivileged_workflows: tuple[DisplayName, ...] = Field(
        default=(), exclude_if=lambda value: not value
    )


def _node_lookup(nodes: tuple[Node, ...]) -> dict[NodeId, Node]:
    return {node.id: node for node in nodes}


def _permitting_identity_from_path(
    path: CapabilityPath, node_by_id: dict[NodeId, Node]
) -> Node | None:
    for hop in reversed(path.hops):
        if hop.edge_type is EdgeType.AUTHENTICATES_AS:
            return node_by_id.get(hop.target_id)
    return None


def _direct_candidates(
    entries: tuple[EffectiveAuthorityEntry, ...],
    node_by_id: dict[NodeId, Node],
) -> list[tuple[MaterialCapabilityClass, BlastRadiusStatement]]:
    candidates: list[tuple[MaterialCapabilityClass, BlastRadiusStatement]] = []
    for entry in entries:
        agent = node_by_id.get(entry.agent_id)
        resource = node_by_id.get(entry.resource_id)
        if agent is None or resource is None:
            continue
        identity = (
            node_by_id.get(entry.permitting_identity_id)
            if entry.permitting_identity_id is not None
            else None
        )
        classes = classify_material_capability(
            resource.security_attributes, edge_type=entry.action
        )
        for material_class in classes:
            candidates.append(
                (
                    material_class,
                    BlastRadiusStatement(
                        schema_version=CURRENT_BLAST_RADIUS_SCHEMA_VERSION,
                        material_class=material_class,
                        agent_id=agent.id,
                        agent_name=agent.name,
                        action=entry.action,
                        target_id=resource.id,
                        target_name=resource.name,
                        permitting_identity_id=identity.id if identity else None,
                        permitting_identity_name=identity.name if identity else None,
                        transitive=False,
                        path=(),
                        incomplete=False,
                    ),
                )
            )
    return candidates


def _transitive_candidates(
    paths: tuple[CapabilityPath, ...],
    node_by_id: dict[NodeId, Node],
) -> list[tuple[MaterialCapabilityClass, BlastRadiusStatement]]:
    candidates: list[tuple[MaterialCapabilityClass, BlastRadiusStatement]] = []
    for path in paths:
        # Unlike `_direct_candidates` above, `compute_transitive_
        # capability_paths` only ever builds a `CapabilityPath` whose
        # `agent_id`/`target_id` are drawn from the very same `nodes`
        # tuple it walked -- so both are always present in `node_by_id`
        # here; a plain lookup (not `.get()`) is deliberate, matching
        # the identical precedent in `controlloop.diff.material_summary`.
        agent = node_by_id[path.agent_id]
        target = node_by_id[path.target_id]
        identity = _permitting_identity_from_path(path, node_by_id)
        last_hop_edge_type = path.hops[-1].edge_type
        classes = classify_material_capability(
            target.security_attributes, edge_type=last_hop_edge_type
        )
        for material_class in classes:
            candidates.append(
                (
                    material_class,
                    BlastRadiusStatement(
                        schema_version=CURRENT_BLAST_RADIUS_SCHEMA_VERSION,
                        material_class=material_class,
                        agent_id=agent.id,
                        agent_name=agent.name,
                        action=last_hop_edge_type,
                        target_id=target.id,
                        target_name=target.name,
                        permitting_identity_id=identity.id if identity else None,
                        permitting_identity_name=identity.name if identity else None,
                        transitive=True,
                        path=path.hops,
                        incomplete=False,
                    ),
                )
            )
    return candidates


def _sort_key(
    item: tuple[MaterialCapabilityClass, BlastRadiusStatement],
) -> tuple[str, str, str, bool, int]:
    _material_class, statement = item
    return (
        statement.agent_id,
        statement.target_id,
        statement.action.value,
        statement.transitive,
        len(statement.path),
    )


def compute_blast_radius(
    nodes: tuple[Node, ...],
    edges: tuple[Edge, ...],
    *,
    max_depth: int = 5,
) -> BlastRadiusStatement | None:
    """Find the single worst-ranked reachable action in this graph,
    across every direct and bounded-transitive fact. Returns `None` when
    nothing in the graph classifies to any material class at all.

    Ties among facts sharing the worst class are broken by a fixed
    deterministic sort key -- identical input always picks the
    same fact, regardless of the order `nodes`/`edges` are given in.

    `max_depth` is the one bound this function exposes directly;
    `compute_transitive_capability_paths`'s other three bounds use
    that function's own defaults."""

    node_by_id = _node_lookup(nodes)

    entries = compute_effective_authority(nodes, edges)
    paths, diagnostics = compute_transitive_capability_paths(
        nodes, edges, max_depth=max_depth
    )

    candidates = _direct_candidates(entries, node_by_id) + _transitive_candidates(
        paths, node_by_id
    )
    if not candidates:
        return None

    worst = worst_class(material_class for material_class, _statement in candidates)
    matching = sorted((item for item in candidates if item[0] == worst), key=_sort_key)
    winner = matching[0][1]

    if diagnostics:
        winner = winner.model_copy(update={"incomplete": True})
    bypass_agents = tuple(
        sorted(
            node.name
            for node in nodes
            if node.subtype in ("host", "subagent")
            and node.security_attributes.bypass_mode is True
        )
    )
    overprivileged = tuple(
        sorted(
            {
                node.attributes.get("workflow", node.name)
                for node in nodes
                if node.subtype == "workflow-runtime"
                and overprivileged_workflow_reason(node.attributes) is not None
            }
        )
    )
    if bypass_agents or overprivileged:
        winner = winner.model_copy(
            update={
                "bypass_agents": bypass_agents,
                "overprivileged_workflows": overprivileged,
            }
        )
    return winner


#: The base-verb phrase a one-hop headline reads after "can". An edge
#: type's value is third person ("invokes"), so
#: "can {action.value}" printed "can invokes". Every `EdgeType` has an
#: entry, which a test enforces, so a new edge type needs a wording
#: decision here.
_HEADLINE_VERB: dict[EdgeType, str] = {
    EdgeType.INVOKES: "invoke",
    EdgeType.READS: "read",
    EdgeType.WRITES: "write",
    EdgeType.AUTHENTICATES_AS: "authenticate as",
    EdgeType.PERMITTED_BY: "be permitted by",
    EdgeType.DELEGATES_TO: "delegate to",
    EdgeType.RECEIVES_FROM: "receive from",
    EdgeType.CONSTRAINED_BY: "be constrained by",
}


def _describe_headline(statement: BlastRadiusStatement) -> str:
    identity_clause = (
        f", permitted by {statement.permitting_identity_name}"
        if statement.permitting_identity_name is not None
        else ""
    )
    incomplete_clause = (
        " -- analysis incomplete, a worse action may be reachable beyond a"
        " configured bound"
        if statement.incomplete
        else ""
    )

    authority_clause = ""
    if statement.bypass_agents:
        authority_clause += (
            "; without asking, since "
            + ", ".join(statement.bypass_agents)
            + (" is" if len(statement.bypass_agents) == 1 else " are")
            + " in a bypass mode"
        )
    if statement.overprivileged_workflows:
        authority_clause += (
            "; also from over-privileged workflow"
            + ("s " if len(statement.overprivileged_workflows) > 1 else " ")
            + ", ".join(statement.overprivileged_workflows)
        )

    if statement.transitive:
        return (
            f"! WORST REACHABLE  {statement.material_class.value}: "
            f"{statement.agent_name} can reach {statement.target_name} via "
            f"{statement.action.value} ({len(statement.path)}-hop chain)"
            f"{identity_clause}{authority_clause}{incomplete_clause}"
        )
    return (
        f"! WORST REACHABLE  {statement.material_class.value}: "
        f"{statement.agent_name} can {_HEADLINE_VERB[statement.action]} "
        f"{statement.target_name}{identity_clause}{authority_clause}"
        f"{incomplete_clause}"
    )


def _describe_hop(hop: PathHop, index: int) -> str:
    return f"    {index}. {hop.edge_type.value} -> {hop.target_id}"


def describe_blast_radius(statement: BlastRadiusStatement | None) -> tuple[str, ...]:
    """Render `statement` as CLI-voice text lines, headline first (the
    "appears first" contract for a caller to honor). When
    `statement.transitive`, one line per hop follows directly beneath
    the headline. `None` renders a single explicit "no material
    capability is reachable" line."""

    if statement is None:
        return ("• no material capability is reachable",)

    lines = [_describe_headline(statement)]
    if statement.transitive:
        lines.extend(
            _describe_hop(hop, index) for index, hop in enumerate(statement.path, 1)
        )
    return tuple(lines)
