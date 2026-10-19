"""Tests for controlloop.capability.compute_direct_capability_paths."""

from __future__ import annotations

import random

import pytest

from controlloop.acbom import (
    Confidence,
    Edge,
    EdgeStatus,
    EdgeType,
    Evidence,
    Node,
    NodeType,
    SecurityAttributes,
)
from controlloop.capability import compute_direct_capability_paths

_AGENT_ID = f"clp:agent:sha256:{'a' * 64}"
_TOOL_ID = f"clp:tool:sha256:{'b' * 64}"
_RESOURCE_ID = f"clp:resource:sha256:{'c' * 64}"
_IDENTITY_ID = f"clp:identity:sha256:{'d' * 64}"
_PERMISSION_ID = f"clp:permission:sha256:{'e' * 64}"
_DATA_CLASS_ID = f"clp:data-class:sha256:{'f' * 64}"
_OTHER_AGENT_ID = f"clp:agent:sha256:{'0' * 64}"


def _node(node_id: str, node_type: NodeType, name: str = "x") -> Node:
    return Node(
        id=node_id,
        type=node_type,
        name=name,
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=(Evidence(adapter="mcp", path="a.json"),),
    )


def _edge(
    edge_type: EdgeType,
    source: str,
    target: str,
    *,
    edge_id_seed: str = "1",
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


_AGENT_NODE = _node(_AGENT_ID, NodeType.AGENT, "coordinator")


@pytest.mark.parametrize(
    ("target_id", "target_type", "edge_type"),
    [
        (_TOOL_ID, NodeType.TOOL, EdgeType.INVOKES),
        (_RESOURCE_ID, NodeType.RESOURCE, EdgeType.READS),
        (_IDENTITY_ID, NodeType.IDENTITY, EdgeType.AUTHENTICATES_AS),
        # Direct agent->permission and agent->data-class edges are not a
        # shape any adapter in this codebase currently produces, but
        # the contract names all five categories structurally --
        # this proves the mechanism is generic, not restricted to
        # today's specific edge-type/target-type combinations.
        (_PERMISSION_ID, NodeType.PERMISSION, EdgeType.PERMITTED_BY),
        (_DATA_CLASS_ID, NodeType.DATA_CLASS, EdgeType.CONSTRAINED_BY),
    ],
)
def test_path_is_computed_to_each_of_the_five_target_categories(
    target_id: str, target_type: NodeType, edge_type: EdgeType
) -> None:
    """A path is computed to each of the five target categories."""
    target_node = _node(target_id, target_type)
    edge = _edge(edge_type, _AGENT_ID, target_id)

    paths = compute_direct_capability_paths((_AGENT_NODE, target_node), (edge,))

    assert len(paths) == 1
    assert paths[0].agent_id == _AGENT_ID
    assert paths[0].target_id == target_id
    assert paths[0].target_type is target_type


def test_path_names_the_full_producing_hop() -> None:
    """A path names the full hop that produced it."""
    tool_node = _node(_TOOL_ID, NodeType.TOOL)
    edge = _edge(EdgeType.INVOKES, _AGENT_ID, _TOOL_ID)

    paths = compute_direct_capability_paths((_AGENT_NODE, tool_node), (edge,))

    assert len(paths) == 1
    hop = paths[0].hops[0]
    assert hop.edge_id == edge.id
    assert hop.edge_type is EdgeType.INVOKES
    assert hop.source_id == _AGENT_ID
    assert hop.target_id == _TOOL_ID


def test_every_hop_carries_its_own_evidence() -> None:
    """Every hop carries its own evidence."""
    tool_node = _node(_TOOL_ID, NodeType.TOOL)
    edge = _edge(EdgeType.INVOKES, _AGENT_ID, _TOOL_ID)

    paths = compute_direct_capability_paths((_AGENT_NODE, tool_node), (edge,))

    assert paths[0].hops[0].evidence == edge.evidence
    assert len(paths[0].hops[0].evidence) > 0


def test_non_agent_source_is_excluded() -> None:
    tool_node = _node(_TOOL_ID, NodeType.TOOL)
    edge = _edge(EdgeType.READS, _TOOL_ID, _AGENT_ID)  # tool -> agent, not agent -> *

    paths = compute_direct_capability_paths((_AGENT_NODE, tool_node), (edge,))

    assert paths == ()


def test_target_outside_the_five_categories_is_excluded() -> None:
    other_agent_node = _node(_OTHER_AGENT_ID, NodeType.AGENT, "sub-agent")
    edge = _edge(EdgeType.DELEGATES_TO, _AGENT_ID, _OTHER_AGENT_ID)

    paths = compute_direct_capability_paths((_AGENT_NODE, other_agent_node), (edge,))

    assert paths == ()


def test_duplicate_edges_produce_one_path() -> None:
    tool_node = _node(_TOOL_ID, NodeType.TOOL)
    edges = (
        _edge(EdgeType.INVOKES, _AGENT_ID, _TOOL_ID, edge_id_seed="1"),
        _edge(EdgeType.INVOKES, _AGENT_ID, _TOOL_ID, edge_id_seed="1"),
    )

    paths = compute_direct_capability_paths((_AGENT_NODE, tool_node), edges)

    assert len(paths) == 1


def test_input_order_does_not_affect_the_result() -> None:
    tool_node = _node(_TOOL_ID, NodeType.TOOL)
    resource_node = _node(_RESOURCE_ID, NodeType.RESOURCE)
    identity_node = _node(_IDENTITY_ID, NodeType.IDENTITY)
    nodes = (_AGENT_NODE, tool_node, resource_node, identity_node)
    edges = [
        _edge(EdgeType.INVOKES, _AGENT_ID, _TOOL_ID, edge_id_seed="1"),
        _edge(EdgeType.READS, _AGENT_ID, _RESOURCE_ID, edge_id_seed="2"),
        _edge(EdgeType.AUTHENTICATES_AS, _AGENT_ID, _IDENTITY_ID, edge_id_seed="3"),
    ]

    first = compute_direct_capability_paths(nodes, tuple(edges))
    shuffled = edges[:]
    random.Random(0).shuffle(shuffled)
    second = compute_direct_capability_paths(nodes, tuple(shuffled))

    assert first == second


def test_result_is_sorted_deterministically() -> None:
    tool_node = _node(_TOOL_ID, NodeType.TOOL)
    resource_node = _node(_RESOURCE_ID, NodeType.RESOURCE)
    edges = (
        _edge(EdgeType.READS, _AGENT_ID, _RESOURCE_ID, edge_id_seed="2"),
        _edge(EdgeType.INVOKES, _AGENT_ID, _TOOL_ID, edge_id_seed="1"),
    )

    paths = compute_direct_capability_paths(
        (_AGENT_NODE, tool_node, resource_node), edges
    )

    assert paths == tuple(
        sorted(paths, key=lambda p: (p.agent_id, p.target_id, str(p.hops[0].edge_type)))
    )


def test_no_edges_produces_no_paths() -> None:
    assert compute_direct_capability_paths((_AGENT_NODE,), ()) == ()
