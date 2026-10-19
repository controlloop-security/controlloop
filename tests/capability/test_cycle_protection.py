"""Tests for cycle protection in
controlloop.capability.compute_transitive_capability_paths."""

from __future__ import annotations

import random
import time

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
from controlloop.capability import compute_transitive_capability_paths

_AGENT_A_ID = f"clp:agent:sha256:{'a' * 64}"
_AGENT_B_ID = f"clp:agent:sha256:{'b' * 64}"
_TOOL_A_ID = f"clp:tool:sha256:{'1' * 64}"
_TOOL_B_ID = f"clp:tool:sha256:{'2' * 64}"
_TOOL_C_ID = f"clp:tool:sha256:{'3' * 64}"


def _node(node_id: str, node_type: NodeType, name: str = "x") -> Node:
    return Node(
        id=node_id,
        type=node_type,
        name=name,
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=(Evidence(adapter="mcp", path="a.json"),),
    )


def _edge(edge_type: EdgeType, source: str, target: str, *, edge_id_seed: str) -> Edge:
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


_AGENT_A_NODE = _node(_AGENT_A_ID, NodeType.AGENT, "coordinator")


def test_self_delegation_cycle_is_detected() -> None:
    """Self-delegation fixture. An agent delegating to itself is
    a cycle at the very first hop -- no progress, no path, one
    diagnostic."""
    self_delegation = _edge(
        EdgeType.DELEGATES_TO, _AGENT_A_ID, _AGENT_A_ID, edge_id_seed="1"
    )

    paths, diagnostics = compute_transitive_capability_paths(
        (_AGENT_A_NODE,), (self_delegation,)
    )

    assert paths == ()
    assert len(diagnostics) == 1
    assert diagnostics[0].code == "INCOMPLETE-CYCLE-DETECTED"
    assert diagnostics[0].incomplete is True


def test_two_node_cycle_is_detected() -> None:
    """Two-node cycle fixture (mutual delegation). Both A and B
    are agent nodes, so the walk starts a traversal from each; each
    origin discovers the cycle from its own direction and hits a
    different closing edge (A's chain closes on B->A, B's chain closes
    on A->B), so both are reported -- one diagnostic per distinct
    closing edge, not per cycle."""
    agent_b = _node(_AGENT_B_ID, NodeType.AGENT, "sub-agent")
    a_to_b = _edge(EdgeType.DELEGATES_TO, _AGENT_A_ID, _AGENT_B_ID, edge_id_seed="1")
    b_to_a = _edge(EdgeType.DELEGATES_TO, _AGENT_B_ID, _AGENT_A_ID, edge_id_seed="2")

    paths, diagnostics = compute_transitive_capability_paths(
        (_AGENT_A_NODE, agent_b), (a_to_b, b_to_a)
    )

    assert paths == ()  # neither agent is a capability-category target
    assert len(diagnostics) == 2
    assert all(d.code == "INCOMPLETE-CYCLE-DETECTED" for d in diagnostics)


def test_multi_node_cycle_is_detected_and_prior_progress_is_kept() -> None:
    """Multi-node (three-tool) cycle fixture. The cycle is
    reported, but the genuine capability paths discovered before the
    cycle closes are not lost."""
    tool_a = _node(_TOOL_A_ID, NodeType.TOOL, "a")
    tool_b = _node(_TOOL_B_ID, NodeType.TOOL, "b")
    tool_c = _node(_TOOL_C_ID, NodeType.TOOL, "c")
    edges = (
        _edge(EdgeType.INVOKES, _AGENT_A_ID, _TOOL_A_ID, edge_id_seed="1"),
        _edge(EdgeType.INVOKES, _TOOL_A_ID, _TOOL_B_ID, edge_id_seed="2"),
        _edge(EdgeType.INVOKES, _TOOL_B_ID, _TOOL_C_ID, edge_id_seed="3"),
        _edge(EdgeType.INVOKES, _TOOL_C_ID, _TOOL_A_ID, edge_id_seed="4"),  # closes it
    )

    paths, diagnostics = compute_transitive_capability_paths(
        (_AGENT_A_NODE, tool_a, tool_b, tool_c), edges
    )

    reached = {path.target_id: len(path.hops) for path in paths}
    assert reached == {_TOOL_B_ID: 2, _TOOL_C_ID: 3}
    assert len(diagnostics) == 1
    assert diagnostics[0].code == "INCOMPLETE-CYCLE-DETECTED"


def test_cycle_does_not_block_legitimate_diamond_reachability() -> None:
    """A node reached by two independent chains is not a cycle -- each
    chain has its own visited set, so both paths are reported."""
    tool_a = _node(_TOOL_A_ID, NodeType.TOOL, "a")
    tool_b = _node(_TOOL_B_ID, NodeType.TOOL, "b")
    tool_c = _node(_TOOL_C_ID, NodeType.TOOL, "c")
    edges = (
        _edge(EdgeType.INVOKES, _AGENT_A_ID, _TOOL_A_ID, edge_id_seed="1"),
        _edge(EdgeType.INVOKES, _AGENT_A_ID, _TOOL_B_ID, edge_id_seed="2"),
        _edge(EdgeType.INVOKES, _TOOL_A_ID, _TOOL_C_ID, edge_id_seed="3"),
        _edge(EdgeType.INVOKES, _TOOL_B_ID, _TOOL_C_ID, edge_id_seed="4"),
    )

    paths, diagnostics = compute_transitive_capability_paths(
        (_AGENT_A_NODE, tool_a, tool_b, tool_c), edges
    )

    paths_to_c = [path for path in paths if path.target_id == _TOOL_C_ID]
    assert len(paths_to_c) == 2
    assert diagnostics == ()


def test_traversal_terminates_on_a_tight_cycle_with_a_large_depth_bound() -> None:
    """A two-node cycle with a generous max_depth still
    terminates promptly and produces one diagnostic per distinct
    closing edge, never one per lap around the cycle."""
    agent_b = _node(_AGENT_B_ID, NodeType.AGENT, "sub-agent")
    a_to_b = _edge(EdgeType.DELEGATES_TO, _AGENT_A_ID, _AGENT_B_ID, edge_id_seed="1")
    b_to_a = _edge(EdgeType.DELEGATES_TO, _AGENT_B_ID, _AGENT_A_ID, edge_id_seed="2")

    start = time.monotonic()
    paths, diagnostics = compute_transitive_capability_paths(
        (_AGENT_A_NODE, agent_b), (a_to_b, b_to_a), max_depth=1000
    )
    elapsed = time.monotonic() - start

    assert paths == ()
    assert len(diagnostics) == 2
    assert elapsed < 5.0


def test_cycle_detection_is_independent_of_edge_order() -> None:
    """Deterministic regardless of entry point/traversal order."""
    tool_a = _node(_TOOL_A_ID, NodeType.TOOL, "a")
    tool_b = _node(_TOOL_B_ID, NodeType.TOOL, "b")
    nodes = (_AGENT_A_NODE, tool_a, tool_b)
    edges = [
        _edge(EdgeType.INVOKES, _AGENT_A_ID, _TOOL_A_ID, edge_id_seed="1"),
        _edge(EdgeType.INVOKES, _TOOL_A_ID, _TOOL_B_ID, edge_id_seed="2"),
        _edge(EdgeType.INVOKES, _TOOL_B_ID, _TOOL_A_ID, edge_id_seed="3"),
    ]

    first_paths, first_diagnostics = compute_transitive_capability_paths(
        nodes, tuple(edges)
    )
    shuffled = edges[:]
    random.Random(0).shuffle(shuffled)
    second_paths, second_diagnostics = compute_transitive_capability_paths(
        nodes, tuple(shuffled)
    )

    assert first_paths == second_paths
    assert first_diagnostics == second_diagnostics


def test_cycle_diagnostic_is_deduplicated_across_multiple_originating_chains() -> None:
    """The same closing edge, reached via two different agents, still
    produces exactly one diagnostic."""
    agent_b = _node(_AGENT_B_ID, NodeType.AGENT, "second-agent")
    tool_a = _node(_TOOL_A_ID, NodeType.TOOL, "a")
    tool_b = _node(_TOOL_B_ID, NodeType.TOOL, "b")
    edges = (
        _edge(EdgeType.INVOKES, _AGENT_A_ID, _TOOL_A_ID, edge_id_seed="1"),
        _edge(EdgeType.INVOKES, _AGENT_B_ID, _TOOL_A_ID, edge_id_seed="2"),
        _edge(EdgeType.INVOKES, _TOOL_A_ID, _TOOL_B_ID, edge_id_seed="3"),
        _edge(EdgeType.INVOKES, _TOOL_B_ID, _TOOL_A_ID, edge_id_seed="4"),
    )

    _paths, diagnostics = compute_transitive_capability_paths(
        (_AGENT_A_NODE, agent_b, tool_a, tool_b), edges
    )

    cycle_diagnostics = [
        d for d in diagnostics if d.code == "INCOMPLETE-CYCLE-DETECTED"
    ]
    assert len(cycle_diagnostics) == 1
