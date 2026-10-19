"""Tests for controlloop.capability.compute_transitive_capability_paths."""

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
from controlloop.capability import (
    compute_direct_capability_paths,
    compute_transitive_capability_paths,
)

_AGENT_ID = f"clp:agent:sha256:{'a' * 64}"
_OTHER_AGENT_ID = f"clp:agent:sha256:{'1' * 64}"
_TOOL_A_ID = f"clp:tool:sha256:{'b' * 64}"
_TOOL_B_ID = f"clp:tool:sha256:{'c' * 64}"
_IDENTITY_ID = f"clp:identity:sha256:{'d' * 64}"
_PERMISSION_ID = f"clp:permission:sha256:{'e' * 64}"


def _node(
    node_id: str,
    node_type: NodeType,
    name: str = "x",
    *,
    security_attributes: SecurityAttributes | None = None,
) -> Node:
    return Node(
        id=node_id,
        type=node_type,
        name=name,
        security_attributes=security_attributes or SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=(Evidence(adapter="mcp", path="a.json"),),
    )


def _edge(
    edge_type: EdgeType,
    source: str,
    target: str,
    *,
    edge_id_seed: str,
    confidence: Confidence = Confidence.HIGH,
) -> Edge:
    return Edge(
        id=f"clp:edge:sha256:{edge_id_seed * 64}",
        source=source,
        target=target,
        type=edge_type,
        status=EdgeStatus.DIRECT,
        security_attributes=SecurityAttributes(),
        confidence=confidence,
        evidence=(Evidence(adapter="mcp", path="a.json"),),
    )


_AGENT_NODE = _node(_AGENT_ID, NodeType.AGENT, "coordinator")


def test_two_hop_path_via_invokes_is_reported() -> None:
    """A tool reachable only by invoking another tool first is reported with
    its full two-hop chain."""
    tool_a = _node(_TOOL_A_ID, NodeType.TOOL, "benign-router")
    tool_b = _node(_TOOL_B_ID, NodeType.TOOL, "privileged-tool")
    edges = (
        _edge(EdgeType.INVOKES, _AGENT_ID, _TOOL_A_ID, edge_id_seed="1"),
        _edge(EdgeType.INVOKES, _TOOL_A_ID, _TOOL_B_ID, edge_id_seed="2"),
    )

    paths, diagnostics = compute_transitive_capability_paths(
        (_AGENT_NODE, tool_a, tool_b), edges
    )

    assert diagnostics == ()
    assert len(paths) == 1
    path = paths[0]
    assert path.agent_id == _AGENT_ID
    assert path.target_id == _TOOL_B_ID
    assert path.target_type is NodeType.TOOL
    assert len(path.hops) == 2
    assert path.hops[0].source_id == _AGENT_ID
    assert path.hops[0].target_id == _TOOL_A_ID
    assert path.hops[1].source_id == _TOOL_A_ID
    assert path.hops[1].target_id == _TOOL_B_ID


def test_benign_tool_reaches_a_privileged_action_through_two_hops() -> None:
    """A benign-looking tool reaches a privileged action through two hops,
    asserted end to end."""
    benign_tool = _node(_TOOL_A_ID, NodeType.TOOL, "notes-formatter")
    privileged_tool = _node(
        _TOOL_B_ID,
        NodeType.TOOL,
        "delete-production-database",
        security_attributes=SecurityAttributes(destructive=True),
    )
    edges = (
        _edge(EdgeType.INVOKES, _AGENT_ID, _TOOL_A_ID, edge_id_seed="1"),
        _edge(EdgeType.INVOKES, _TOOL_A_ID, _TOOL_B_ID, edge_id_seed="2"),
    )

    paths, _diagnostics = compute_transitive_capability_paths(
        (_AGENT_NODE, benign_tool, privileged_tool), edges
    )

    assert len(paths) == 1
    assert paths[0].target_id == _TOOL_B_ID
    assert privileged_tool.security_attributes.destructive is True


def test_transitive_chain_through_delegation_and_invocation() -> None:
    """Delegates-to is a valid traversal edge, chaining into a capability
    the delegate reaches."""
    other_agent = _node(_OTHER_AGENT_ID, NodeType.AGENT, "sub-agent")
    tool = _node(_TOOL_A_ID, NodeType.TOOL, "files")
    edges = (
        _edge(EdgeType.DELEGATES_TO, _AGENT_ID, _OTHER_AGENT_ID, edge_id_seed="1"),
        _edge(EdgeType.INVOKES, _OTHER_AGENT_ID, _TOOL_A_ID, edge_id_seed="2"),
    )

    paths, _diagnostics = compute_transitive_capability_paths(
        (_AGENT_NODE, other_agent, tool), edges
    )

    assert len(paths) == 1
    assert paths[0].hops[0].edge_type is EdgeType.DELEGATES_TO
    assert paths[0].hops[1].edge_type is EdgeType.INVOKES


def test_transitive_chain_through_authentication_and_permission() -> None:
    """Authenticates-as and permitted-by are valid traversal edges, chaining
    an agent's identity into a permission."""
    identity = _node(_IDENTITY_ID, NodeType.IDENTITY, "service-account")
    permission = _node(_PERMISSION_ID, NodeType.PERMISSION, "admin-write")
    edges = (
        _edge(EdgeType.AUTHENTICATES_AS, _AGENT_ID, _IDENTITY_ID, edge_id_seed="1"),
        _edge(EdgeType.PERMITTED_BY, _IDENTITY_ID, _PERMISSION_ID, edge_id_seed="2"),
    )

    paths, _diagnostics = compute_transitive_capability_paths(
        (_AGENT_NODE, identity, permission), edges
    )

    assert len(paths) == 1
    assert paths[0].target_type is NodeType.PERMISSION
    assert paths[0].hops[0].edge_type is EdgeType.AUTHENTICATES_AS
    assert paths[0].hops[1].edge_type is EdgeType.PERMITTED_BY


def test_one_hop_reachable_targets_are_not_duplicated() -> None:
    """A target reachable directly in one hop is compute_direct_
    capability_paths's own result -- the transitive function does not
    repeat it."""
    tool = _node(_TOOL_A_ID, NodeType.TOOL, "files")
    edges = (_edge(EdgeType.INVOKES, _AGENT_ID, _TOOL_A_ID, edge_id_seed="1"),)

    direct_paths = compute_direct_capability_paths((_AGENT_NODE, tool), edges)
    transitive_paths, _diagnostics = compute_transitive_capability_paths(
        (_AGENT_NODE, tool), edges
    )

    assert len(direct_paths) == 1
    assert transitive_paths == ()


def test_depth_bound_is_enforced() -> None:
    """A target reachable only beyond max_depth is never returned."""
    nodes: list[Node] = [_AGENT_NODE]
    edges: list[Edge] = []
    previous = _AGENT_ID
    # Six hops: agent -> n1 -> n2 -> n3 -> n4 -> n5 -> n6 (target).
    chain_ids = [f"clp:tool:sha256:{str(i) * 64}" for i in range(6)]
    for index, node_id in enumerate(chain_ids):
        nodes.append(_node(node_id, NodeType.TOOL, f"tool-{index}"))
        edges.append(
            _edge(EdgeType.INVOKES, previous, node_id, edge_id_seed=str(index + 1))
        )
        previous = node_id

    paths, diagnostics = compute_transitive_capability_paths(
        tuple(nodes), tuple(edges), max_depth=3
    )

    reached_ids = {path.target_id for path in paths}
    assert chain_ids[2] in reached_ids  # 3 hops: within bound
    assert chain_ids[5] not in reached_ids  # 6 hops: beyond bound
    assert all(len(path.hops) <= 3 for path in paths)
    assert len(diagnostics) == 1
    assert diagnostics[0].code == "INCOMPLETE-BOUND-EXCEEDED"


def test_depth_bound_truncation_produces_an_incomplete_diagnostic() -> None:
    """Reaching the depth bound with more graph left unexplored is marked
    incomplete, never a silent partial answer."""
    tool_a = _node(_TOOL_A_ID, NodeType.TOOL, "a")
    tool_b = _node(_TOOL_B_ID, NodeType.TOOL, "b")
    edges = (
        _edge(EdgeType.INVOKES, _AGENT_ID, _TOOL_A_ID, edge_id_seed="1"),
        _edge(EdgeType.INVOKES, _TOOL_A_ID, _TOOL_B_ID, edge_id_seed="2"),
    )

    _paths, diagnostics = compute_transitive_capability_paths(
        (_AGENT_NODE, tool_a, tool_b), edges, max_depth=1
    )

    assert len(diagnostics) == 1
    assert diagnostics[0].code == "INCOMPLETE-BOUND-EXCEEDED"
    assert diagnostics[0].incomplete is True
    assert diagnostics[0].confidence == Confidence.UNKNOWN
    assert len(diagnostics[0].evidence) == 1


def test_no_diagnostic_when_nothing_is_truncated() -> None:
    tool_a = _node(_TOOL_A_ID, NodeType.TOOL, "a")
    tool_b = _node(_TOOL_B_ID, NodeType.TOOL, "b")
    edges = (
        _edge(EdgeType.INVOKES, _AGENT_ID, _TOOL_A_ID, edge_id_seed="1"),
        _edge(EdgeType.INVOKES, _TOOL_A_ID, _TOOL_B_ID, edge_id_seed="2"),
    )

    _paths, diagnostics = compute_transitive_capability_paths(
        (_AGENT_NODE, tool_a, tool_b), edges, max_depth=5
    )

    assert diagnostics == ()


def test_max_depth_must_be_at_least_one() -> None:
    with pytest.raises(ValueError, match="max_depth"):
        compute_transitive_capability_paths((_AGENT_NODE,), (), max_depth=0)


def test_empty_input_produces_nothing() -> None:
    assert compute_transitive_capability_paths((), ()) == ((), ())


def test_result_is_independent_of_input_order() -> None:
    tool_a = _node(_TOOL_A_ID, NodeType.TOOL, "a")
    tool_b = _node(_TOOL_B_ID, NodeType.TOOL, "b")
    nodes = (_AGENT_NODE, tool_a, tool_b)
    edges = [
        _edge(EdgeType.INVOKES, _AGENT_ID, _TOOL_A_ID, edge_id_seed="1"),
        _edge(EdgeType.INVOKES, _TOOL_A_ID, _TOOL_B_ID, edge_id_seed="2"),
    ]

    first, first_diagnostics = compute_transitive_capability_paths(nodes, tuple(edges))
    shuffled = edges[:]
    random.Random(0).shuffle(shuffled)
    second, second_diagnostics = compute_transitive_capability_paths(
        nodes, tuple(shuffled)
    )

    assert first == second
    assert first_diagnostics == second_diagnostics


def test_combined_confidence_is_the_weakest_hop() -> None:
    tool_a = _node(_TOOL_A_ID, NodeType.TOOL, "a")
    tool_b = _node(_TOOL_B_ID, NodeType.TOOL, "b")
    edges = (
        _edge(
            EdgeType.INVOKES,
            _AGENT_ID,
            _TOOL_A_ID,
            edge_id_seed="1",
            confidence=Confidence.HIGH,
        ),
        _edge(
            EdgeType.INVOKES,
            _TOOL_A_ID,
            _TOOL_B_ID,
            edge_id_seed="2",
            confidence=Confidence.LOW,
        ),
    )

    paths, _diagnostics = compute_transitive_capability_paths(
        (_AGENT_NODE, tool_a, tool_b), edges
    )

    assert paths[0].confidence is Confidence.LOW
