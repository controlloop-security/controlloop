"""Material capability change summary.

`compute_material_change_summary` answers the question a raw
`DiffResult` does not: not *which* nodes, edges, or
effective-authority facts differ, but *what real-world power the agent
gained or lost*, in terms of `controlloop.capability.taxonomy`'s
already-defined material classes (destructive action, financial
action, code execution, external communication, sensitive-data access,
delegation, write access, or unclassified). This module is the
translation step between "here is a diff" and "here is what that diff
means" -- it performs no discovery, analysis, or classification design
of its own, only classification lookups against nodes already
provided and against `controlloop.capability.taxonomy`'s already-tested
rules.

Two sources feed the summary, both already-diffed elsewhere:

1. Direct effective-authority changes (`controlloop.diff.compute.
   diff_effective_authority`) -- one agent-action-resource fact.
2. Bounded transitive capability-path changes (`controlloop.diff.
   compute.diff_transitive_capability_paths`) -- the "adds authority
   only transitively" case, reported with the specific path
   (`MaterialChange.path`) that delivers it. `compute_transitive_
   capability_paths` only ever returns paths of two hops or more (a
   one-hop path is direct-effective-authority's own result), so the
   two sources never double-report the same fact.

A change whose resource or path target carries no material
`SecurityAttributes` at all (`classify_material_capability` returns an
empty set) contributes nothing to the summary -- "a cosmetic change
producing no effective authority change is reported as no
material change" extends naturally to "an effective-authority change
that carries no material classification is likewise not material,"
since this summary's own purpose ("what real-world power the agent
gained -- not which files changed") is exactly the judgment an empty
classification set already makes. An empty `MaterialChangeSummary`
(`is_empty`) *is* "no material change" -- there is no separate
sentinel value for it, the same structural-omission design
`controlloop.diff.models.DiffResult` already uses.

"Summary language is generated from structured data, never from a
model" is satisfied by construction: `describe_material_change_summary`
renders `MaterialChangeSummary`'s own already-computed fields through a
fixed, deterministic template -- there is no model call, and could not
be one, anywhere in this module's import graph.

Known limitation: if either side's transitive walk
(`compute_transitive_capability_paths`) hits one of its own bounds
(`INCOMPLETE-BOUND-EXCEEDED`/`INCOMPLETE-CYCLE-DETECTED`), this
module does not surface that incompleteness in the summary itself --
the comparison may under-report a transitively gained or lost
capability beyond the bound. Disclosed here rather than silently
assumed complete; see docs/reference/diff-output-format.md.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from controlloop.acbom.models import DisplayName, Edge, EdgeType, Node, NodeId
from controlloop.capability.compute import (
    compute_effective_authority,
    compute_transitive_capability_paths,
)
from controlloop.capability.models import PathHop
from controlloop.capability.taxonomy import (
    MaterialCapabilityClass,
    classify_material_capability,
)
from controlloop.diff.compute import (
    diff_effective_authority,
    diff_transitive_capability_paths,
)
from controlloop.diff.models import ChangeKind

CURRENT_MATERIAL_CHANGE_SUMMARY_SCHEMA_VERSION = "1.0.0"


class _MaterialSummaryModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        strict=True,
    )


class MaterialChangeKind(StrEnum):
    """How one material capability changed against the baseline,
    mirroring `controlloop.diff.models.ChangeKind` one-for-one but
    named for this summary's own vocabulary ("gained authority")
    rather than the generic diff vocabulary."""

    GAINED = "gained"
    LOST = "lost"
    CHANGED = "changed"
    UNKNOWN = "unknown"


_CHANGE_KIND_TO_MATERIAL_KIND: dict[ChangeKind, MaterialChangeKind] = {
    ChangeKind.ADDED: MaterialChangeKind.GAINED,
    ChangeKind.REMOVED: MaterialChangeKind.LOST,
    ChangeKind.CHANGED: MaterialChangeKind.CHANGED,
    ChangeKind.UNKNOWN: MaterialChangeKind.UNKNOWN,
}


class MaterialChange(_MaterialSummaryModel):
    """One material capability's classification against the baseline.
    `agent_name`/`target_name` are the resolved `Node.name` display
    strings at the time this was computed -- denormalized here
    (rather than requiring a caller to re-resolve `agent_id`/`target_id`
    against a node set just to render a sentence) so the "generated from
    structured data" summary can name something a person
    recognizes, not only a content-addressed ID."""

    kind: MaterialChangeKind
    material_class: MaterialCapabilityClass
    agent_id: NodeId
    agent_name: DisplayName
    action: EdgeType
    target_id: NodeId
    target_name: DisplayName
    transitive: bool
    path: tuple[PathHop, ...] = ()


class MaterialChangeSummary(_MaterialSummaryModel):
    """Complete material capability change summary. Contains only
    changes with at least one matched material class -- "no material
    change" is `is_empty` being `True`, not a separate
    sentinel entry."""

    schema_version: str
    changes: tuple[MaterialChange, ...]

    @property
    def is_empty(self) -> bool:
        return not self.changes


def _node_lookup(nodes: tuple[Node, ...]) -> dict[NodeId, Node]:
    return {node.id: node for node in nodes}


def compute_material_change_summary(
    *,
    baseline_nodes: tuple[Node, ...],
    baseline_edges: tuple[Edge, ...],
    current_nodes: tuple[Node, ...],
    current_edges: tuple[Edge, ...],
    max_depth: int = 5,
) -> MaterialChangeSummary:
    """Classify every material capability change between two ACBOM
    graphs. Effective authority and transitive capability paths
    are both computed fresh from each side's own `nodes`/`edges` --
    never taken as inputs -- the same discipline
    `controlloop.diff.compute.compute_diff` already follows.

    `max_depth` is the one bound this function exposes to callers
    directly; `compute_transitive_capability_paths`'s other three
    bounds (`max_explored_paths`, `max_returned_paths`, `max_seconds`)
    use that function's own defaults."""

    baseline_node_by_id = _node_lookup(baseline_nodes)
    current_node_by_id = _node_lookup(current_nodes)

    baseline_authority = compute_effective_authority(baseline_nodes, baseline_edges)
    current_authority = compute_effective_authority(current_nodes, current_edges)
    authority_changes = diff_effective_authority(baseline_authority, current_authority)

    baseline_paths, _baseline_diagnostics = compute_transitive_capability_paths(
        baseline_nodes, baseline_edges, max_depth=max_depth
    )
    current_paths, _current_diagnostics = compute_transitive_capability_paths(
        current_nodes, current_edges, max_depth=max_depth
    )
    path_changes = diff_transitive_capability_paths(baseline_paths, current_paths)

    changes: list[MaterialChange] = []

    for authority_change in authority_changes:
        node_by_id = (
            baseline_node_by_id
            if authority_change.kind is ChangeKind.REMOVED
            else current_node_by_id
        )
        agent = node_by_id.get(authority_change.agent_id)
        resource = node_by_id.get(authority_change.resource_id)
        if agent is None or resource is None:
            continue

        classes = classify_material_capability(
            resource.security_attributes, edge_type=authority_change.action
        )
        for material_class in sorted(classes):
            changes.append(
                MaterialChange(
                    kind=_CHANGE_KIND_TO_MATERIAL_KIND[authority_change.kind],
                    material_class=material_class,
                    agent_id=agent.id,
                    agent_name=agent.name,
                    action=authority_change.action,
                    target_id=resource.id,
                    target_name=resource.name,
                    transitive=False,
                    path=(),
                )
            )

    for path_change in path_changes:
        path = (
            path_change.after
            if path_change.kind is not ChangeKind.REMOVED
            else path_change.before
        )
        assert path is not None
        node_by_id = (
            baseline_node_by_id
            if path_change.kind is ChangeKind.REMOVED
            else current_node_by_id
        )
        # Unlike the effective-authority loop above,
        # `compute_transitive_capability_paths` only ever builds a
        # `CapabilityPath` whose `agent_id`/`target_id` are drawn from
        # the very same `nodes` tuple it walked -- so both are always
        # present in the matching node set here; a plain lookup (not
        # `.get()`) is deliberate, not an oversight.
        agent = node_by_id[path_change.agent_id]
        target = node_by_id[path_change.target_id]

        last_hop_edge_type = path.hops[-1].edge_type
        classes = classify_material_capability(
            target.security_attributes, edge_type=last_hop_edge_type
        )
        for material_class in sorted(classes):
            changes.append(
                MaterialChange(
                    kind=_CHANGE_KIND_TO_MATERIAL_KIND[path_change.kind],
                    material_class=material_class,
                    agent_id=agent.id,
                    agent_name=agent.name,
                    action=last_hop_edge_type,
                    target_id=target.id,
                    target_name=target.name,
                    transitive=True,
                    path=path.hops,
                )
            )

    ordered_changes = tuple(
        sorted(
            changes,
            key=lambda change: (
                change.agent_id,
                change.target_id,
                change.action.value,
                change.material_class.value,
                change.kind.value,
                change.transitive,
            ),
        )
    )

    return MaterialChangeSummary(
        schema_version=CURRENT_MATERIAL_CHANGE_SUMMARY_SCHEMA_VERSION,
        changes=ordered_changes,
    )


_GLYPH_BY_KIND: dict[MaterialChangeKind, str] = {
    MaterialChangeKind.GAINED: "•",
    MaterialChangeKind.LOST: "•",
    MaterialChangeKind.CHANGED: "•",
    MaterialChangeKind.UNKNOWN: "!",
}


def describe_material_change_summary(summary: MaterialChangeSummary) -> tuple[str, ...]:
    """Render `summary` as CLI-voice text lines, one per
    `MaterialChange`, following the brand style's stable symbol
    convention (`• INFO`, `! WARNING`). An empty summary renders as a
    single explicit "no material change" line rather than
    an empty tuple, so a caller printing this never has to special-case
    "nothing to show" separately from "nothing changed."""

    if summary.is_empty:
        return ("• no material capability change",)

    lines = []
    for change in summary.changes:
        glyph = _GLYPH_BY_KIND[change.kind]
        if change.transitive:
            lines.append(
                f"{glyph} {change.kind.value.upper():<8}{change.material_class.value}: "
                f"{change.agent_name} reaches {change.target_name} via "
                f"{change.action.value} ({len(change.path)}-hop chain)"
            )
        else:
            lines.append(
                f"{glyph} {change.kind.value.upper():<8}{change.material_class.value}: "
                f"{change.agent_name} {change.action.value} {change.target_name}"
            )
    return tuple(lines)
