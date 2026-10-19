"""Tests for controlloop.diff.material_summary."""

from __future__ import annotations

import random

from controlloop.acbom import (
    Confidence,
    Edge,
    EdgeStatus,
    EdgeType,
    Evidence,
    Node,
    NodeType,
    SecurityAttributes,
    Sensitivity,
)
from controlloop.capability.taxonomy import MaterialCapabilityClass
from controlloop.diff import (
    MaterialChange,
    MaterialChangeKind,
    MaterialChangeSummary,
    compute_material_change_summary,
    describe_material_change_summary,
)

_AGENT_ID = f"clp:agent:sha256:{'a' * 64}"
_TOOL_ID = f"clp:tool:sha256:{'b' * 64}"
_RESOURCE_ID = f"clp:resource:sha256:{'c' * 64}"
_IDENTITY_ID = f"clp:identity:sha256:{'d' * 64}"


def _node(
    node_id: str,
    node_type: NodeType,
    *,
    name: str = "x",
    security_attributes: SecurityAttributes | None = None,
    line_start: int | None = None,
) -> Node:
    return Node(
        id=node_id,
        type=node_type,
        name=name,
        security_attributes=security_attributes or SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=(Evidence(adapter="mcp", path="a.json", line_start=line_start),),
    )


def _edge(
    edge_type: EdgeType, source: str, target: str, *, edge_id_seed: str = "f"
) -> Edge:
    return Edge(
        id=f"clp:edge:sha256:{edge_id_seed * 64}",
        source=source,
        target=target,
        type=edge_type,
        status=EdgeStatus.DIRECT,
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=(Evidence(adapter="mcp", path="a.json"),),
    )


_AGENT_NODE = _node(_AGENT_ID, NodeType.AGENT, name="refund-agent")
_IDENTITY_NODE = _node(_IDENTITY_ID, NodeType.IDENTITY, name="service-account")


def _destructive_resource_node(node_id: str = _RESOURCE_ID, *, name: str) -> Node:
    return _node(
        node_id,
        NodeType.RESOURCE,
        name=name,
        security_attributes=SecurityAttributes(destructive=True),
    )


def _unclassified_resource_node(node_id: str = _RESOURCE_ID, *, name: str) -> Node:
    return _node(node_id, NodeType.RESOURCE, name=name)


class TestGainedDirectCapability:
    """A direct effective-authority change is summarized by its material
    class."""

    def test_gaining_a_destructive_read_is_gained_destructive_action(self) -> None:
        resource = _destructive_resource_node(name="billing-db")
        current_nodes = (_AGENT_NODE, resource)
        current_edges = (_edge(EdgeType.READS, _AGENT_ID, _RESOURCE_ID),)

        summary = compute_material_change_summary(
            baseline_nodes=(),
            baseline_edges=(),
            current_nodes=current_nodes,
            current_edges=current_edges,
        )

        assert not summary.is_empty
        assert len(summary.changes) == 1
        change = summary.changes[0]
        assert change.kind is MaterialChangeKind.GAINED
        assert change.material_class is MaterialCapabilityClass.DESTRUCTIVE_ACTION
        assert change.agent_id == _AGENT_ID
        assert change.agent_name == "refund-agent"
        assert change.target_id == _RESOURCE_ID
        assert change.target_name == "billing-db"
        assert change.transitive is False
        assert change.path == ()

    def test_losing_a_destructive_read_is_lost_destructive_action(self) -> None:
        resource = _destructive_resource_node(name="billing-db")
        baseline_nodes = (_AGENT_NODE, resource)
        baseline_edges = (_edge(EdgeType.READS, _AGENT_ID, _RESOURCE_ID),)

        summary = compute_material_change_summary(
            baseline_nodes=baseline_nodes,
            baseline_edges=baseline_edges,
            current_nodes=(),
            current_edges=(),
        )

        assert len(summary.changes) == 1
        assert summary.changes[0].kind is MaterialChangeKind.LOST

    def test_a_change_matching_multiple_classes_emits_one_entry_per_class(
        self,
    ) -> None:
        resource = _node(
            _RESOURCE_ID,
            NodeType.RESOURCE,
            name="customer-db",
            security_attributes=SecurityAttributes(
                destructive=True, sensitivity=Sensitivity.RESTRICTED
            ),
        )
        current_nodes = (_AGENT_NODE, resource)
        current_edges = (_edge(EdgeType.WRITES, _AGENT_ID, _RESOURCE_ID),)

        summary = compute_material_change_summary(
            baseline_nodes=(),
            baseline_edges=(),
            current_nodes=current_nodes,
            current_edges=current_edges,
        )

        classes = {change.material_class for change in summary.changes}
        assert MaterialCapabilityClass.DESTRUCTIVE_ACTION in classes
        assert MaterialCapabilityClass.SENSITIVE_DATA_ACCESS in classes
        assert MaterialCapabilityClass.WRITE_ACCESS in classes


class TestNoMaterialChange:
    """A cosmetic change (or one with no material classification) is
    reported as no material change."""

    def test_evidence_only_difference_is_no_material_change(self) -> None:
        resource = _destructive_resource_node(name="billing-db")
        baseline_nodes = (_AGENT_NODE, resource)
        current_nodes = (
            _AGENT_NODE,
            _destructive_resource_node(name="billing-db"),  # identical content
        )
        edges = (_edge(EdgeType.WRITES, _AGENT_ID, _RESOURCE_ID),)

        summary = compute_material_change_summary(
            baseline_nodes=baseline_nodes,
            baseline_edges=edges,
            current_nodes=current_nodes,
            current_edges=edges,
        )

        assert summary.is_empty is True
        assert summary.changes == ()

    def test_unclassified_resource_gain_is_no_material_change(self) -> None:
        """Design note: an effective-authority change is real, but the
        resource carries no material `SecurityAttributes` at all, so
        `classify_material_capability` returns an empty set and the summary
        reports nothing -- it describes material capability change, not
        "which files changed"."""

        resource = _unclassified_resource_node(name="scratch-file")
        current_nodes = (_AGENT_NODE, resource)
        current_edges = (_edge(EdgeType.READS, _AGENT_ID, _RESOURCE_ID),)

        summary = compute_material_change_summary(
            baseline_nodes=(),
            baseline_edges=(),
            current_nodes=current_nodes,
            current_edges=current_edges,
        )

        assert summary.is_empty is True

    def test_identical_repository_against_itself_is_no_material_change(self) -> None:
        resource = _destructive_resource_node(name="billing-db")
        nodes = (_AGENT_NODE, resource)
        edges = (_edge(EdgeType.WRITES, _AGENT_ID, _RESOURCE_ID),)

        summary = compute_material_change_summary(
            baseline_nodes=nodes,
            baseline_edges=edges,
            current_nodes=nodes,
            current_edges=edges,
        )

        assert summary.is_empty is True

    def test_an_effective_authority_edge_with_no_matching_resource_node_is_skipped(
        self,
    ) -> None:
        """Defensive branch: `compute_effective_authority` does not
        itself require `edge.target` to exist in `nodes` -- a real
        `ACBOMDocument` guarantees this (`validate_graph_integrity`),
        but this function is called directly here with a deliberately
        mismatched pair to prove a missing resource node is skipped
        rather than raising."""

        current_nodes = (_AGENT_NODE,)  # no resource node at all
        current_edges = (_edge(EdgeType.WRITES, _AGENT_ID, _RESOURCE_ID),)

        summary = compute_material_change_summary(
            baseline_nodes=(),
            baseline_edges=(),
            current_nodes=current_nodes,
            current_edges=current_edges,
        )

        assert summary.is_empty is True


class TestTransitiveGainWithPath:
    """A change that adds authority only transitively is summarized as
    gained authority, with its path."""

    def test_transitive_only_gain_reports_the_path(self) -> None:
        tool = _destructive_resource_node(_TOOL_ID, name="delete-tool")
        current_nodes = (_AGENT_NODE, _IDENTITY_NODE, tool)
        current_edges = (
            _edge(EdgeType.DELEGATES_TO, _AGENT_ID, _IDENTITY_ID, edge_id_seed="1"),
            _edge(EdgeType.INVOKES, _IDENTITY_ID, _TOOL_ID, edge_id_seed="2"),
        )

        summary = compute_material_change_summary(
            baseline_nodes=(),
            baseline_edges=(),
            current_nodes=current_nodes,
            current_edges=current_edges,
        )

        assert len(summary.changes) == 1
        change = summary.changes[0]
        assert change.kind is MaterialChangeKind.GAINED
        assert change.transitive is True
        assert len(change.path) == 2
        assert change.path[0].edge_type is EdgeType.DELEGATES_TO
        assert change.path[-1].edge_type is EdgeType.INVOKES
        assert change.target_id == _TOOL_ID

    def test_direct_one_hop_gain_is_not_transitive(self) -> None:
        resource = _destructive_resource_node(name="billing-db")
        current_nodes = (_AGENT_NODE, resource)
        current_edges = (_edge(EdgeType.WRITES, _AGENT_ID, _RESOURCE_ID),)

        summary = compute_material_change_summary(
            baseline_nodes=(),
            baseline_edges=(),
            current_nodes=current_nodes,
            current_edges=current_edges,
        )

        assert all(change.transitive is False for change in summary.changes)

    def test_transitive_only_loss_is_reported_as_lost(self) -> None:
        tool = _destructive_resource_node(_TOOL_ID, name="delete-tool")
        baseline_nodes = (_AGENT_NODE, _IDENTITY_NODE, tool)
        baseline_edges = (
            _edge(EdgeType.DELEGATES_TO, _AGENT_ID, _IDENTITY_ID, edge_id_seed="1"),
            _edge(EdgeType.INVOKES, _IDENTITY_ID, _TOOL_ID, edge_id_seed="2"),
        )

        summary = compute_material_change_summary(
            baseline_nodes=baseline_nodes,
            baseline_edges=baseline_edges,
            current_nodes=(),
            current_edges=(),
        )

        assert len(summary.changes) == 1
        assert summary.changes[0].kind is MaterialChangeKind.LOST
        assert summary.changes[0].transitive is True


class TestDeterminism:
    """The summary is identical for identical input."""

    def test_summary_is_identical_regardless_of_node_and_edge_order(self) -> None:
        resource = _destructive_resource_node(name="billing-db")
        tool = _node(_TOOL_ID, NodeType.TOOL, name="refund-tool")
        current_nodes = [_AGENT_NODE, resource, _IDENTITY_NODE, tool]
        current_edges = [
            _edge(EdgeType.WRITES, _AGENT_ID, _RESOURCE_ID, edge_id_seed="1"),
            _edge(EdgeType.DELEGATES_TO, _AGENT_ID, _IDENTITY_ID, edge_id_seed="2"),
            _edge(EdgeType.INVOKES, _IDENTITY_ID, _TOOL_ID, edge_id_seed="3"),
        ]

        random.shuffle(current_nodes)
        random.shuffle(current_edges)
        first = compute_material_change_summary(
            baseline_nodes=(),
            baseline_edges=(),
            current_nodes=tuple(current_nodes),
            current_edges=tuple(current_edges),
        )

        random.shuffle(current_nodes)
        random.shuffle(current_edges)
        second = compute_material_change_summary(
            baseline_nodes=(),
            baseline_edges=(),
            current_nodes=tuple(current_nodes),
            current_edges=tuple(current_edges),
        )

        assert first == second
        assert first.model_dump_json() == second.model_dump_json()


class TestDescribeMaterialChangeSummary:
    """Summary language is generated from structured data, never a model."""

    def test_empty_summary_renders_a_single_explicit_line(self) -> None:
        summary = compute_material_change_summary(
            baseline_nodes=(), baseline_edges=(), current_nodes=(), current_edges=()
        )

        lines = describe_material_change_summary(summary)

        assert lines == ("• no material capability change",)

    def test_gained_line_names_the_agent_class_and_target(self) -> None:
        resource = _destructive_resource_node(name="billing-db")
        current_nodes = (_AGENT_NODE, resource)
        current_edges = (_edge(EdgeType.READS, _AGENT_ID, _RESOURCE_ID),)

        summary = compute_material_change_summary(
            baseline_nodes=(),
            baseline_edges=(),
            current_nodes=current_nodes,
            current_edges=current_edges,
        )
        lines = describe_material_change_summary(summary)

        assert len(lines) == 1
        assert lines[0].startswith("•")
        assert "GAINED" in lines[0]
        assert "destructive-action" in lines[0]
        assert "refund-agent" in lines[0]
        assert "billing-db" in lines[0]

    def test_transitive_line_names_the_hop_count(self) -> None:
        tool = _destructive_resource_node(_TOOL_ID, name="delete-tool")
        current_nodes = (_AGENT_NODE, _IDENTITY_NODE, tool)
        current_edges = (
            _edge(EdgeType.DELEGATES_TO, _AGENT_ID, _IDENTITY_ID, edge_id_seed="1"),
            _edge(EdgeType.INVOKES, _IDENTITY_ID, _TOOL_ID, edge_id_seed="2"),
        )

        summary = compute_material_change_summary(
            baseline_nodes=(),
            baseline_edges=(),
            current_nodes=current_nodes,
            current_edges=current_edges,
        )
        lines = describe_material_change_summary(summary)

        assert len(lines) == 1
        assert "2-hop chain" in lines[0]
        assert "reaches" in lines[0]

    def test_unknown_line_uses_the_warning_glyph(self) -> None:
        unknown_change = MaterialChange(
            kind=MaterialChangeKind.UNKNOWN,
            material_class=MaterialCapabilityClass.DESTRUCTIVE_ACTION,
            agent_id=_AGENT_ID,
            agent_name="refund-agent",
            action=EdgeType.WRITES,
            target_id=_RESOURCE_ID,
            target_name="billing-db",
            transitive=False,
        )
        unknown_summary = MaterialChangeSummary(
            schema_version="1.0.0", changes=(unknown_change,)
        )

        lines = describe_material_change_summary(unknown_summary)

        assert lines[0].startswith("!")


class TestMultipleRoutesToTheSameTarget:
    """Boundary: two distinct transitive routes to the same target are
    both reported as separate material changes."""

    def test_two_routes_both_reported(self) -> None:
        tool = _destructive_resource_node(_TOOL_ID, name="delete-tool")
        other_identity_id = f"clp:identity:sha256:{'e' * 64}"
        other_identity = _node(other_identity_id, NodeType.IDENTITY, name="other-svc")
        current_nodes = (_AGENT_NODE, _IDENTITY_NODE, other_identity, tool)
        current_edges = (
            _edge(EdgeType.DELEGATES_TO, _AGENT_ID, _IDENTITY_ID, edge_id_seed="1"),
            _edge(EdgeType.INVOKES, _IDENTITY_ID, _TOOL_ID, edge_id_seed="2"),
            _edge(
                EdgeType.AUTHENTICATES_AS,
                _AGENT_ID,
                other_identity_id,
                edge_id_seed="3",
            ),
            _edge(EdgeType.INVOKES, other_identity_id, _TOOL_ID, edge_id_seed="4"),
        )

        summary = compute_material_change_summary(
            baseline_nodes=(),
            baseline_edges=(),
            current_nodes=current_nodes,
            current_edges=current_edges,
        )

        transitive_changes = [c for c in summary.changes if c.transitive]
        assert len(transitive_changes) == 2
        assert {len(c.path) for c in transitive_changes} == {2}
