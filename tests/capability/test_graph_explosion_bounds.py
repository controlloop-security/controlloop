"""Tests for graph explosion bounds in
controlloop.capability.compute_transitive_capability_paths."""

from __future__ import annotations

import random
import time

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
from controlloop.capability import compute_transitive_capability_paths

_AGENT_ID = f"clp:agent:sha256:{'a' * 64}"


def _node(node_id: str, node_type: NodeType, name: str = "x") -> Node:
    return Node(
        id=node_id,
        type=node_type,
        name=name,
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=(Evidence(adapter="mcp", path="a.json"),),
    )


def _edge(edge_type: EdgeType, source: str, target: str, *, edge_id_seed: int) -> Edge:
    return Edge(
        id=f"clp:edge:sha256:{edge_id_seed:064x}",
        source=source,
        target=target,
        type=edge_type,
        status=EdgeStatus.DIRECT,
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=(Evidence(adapter="mcp", path="a.json"),),
    )


_AGENT_NODE = _node(_AGENT_ID, NodeType.AGENT, "coordinator")


def _tool_id(counter: int) -> str:
    return f"clp:tool:sha256:{counter:064x}"


def _build_fanout_graph(
    branching: int, levels: int
) -> tuple[tuple[Node, ...], tuple[Edge, ...]]:
    """A tree rooted at the agent: `branching` tools per level, `levels`
    deep -- `branching ** levels` leaf paths, combinatorially explosive
    for small `branching`/`levels` already."""

    nodes: list[Node] = [_AGENT_NODE]
    edges: list[Edge] = []
    counter = 0
    current_level = [_AGENT_ID]
    for _level in range(levels):
        next_level = []
        for parent_id in current_level:
            for _branch in range(branching):
                counter += 1
                child_id = _tool_id(counter)
                nodes.append(_node(child_id, NodeType.TOOL, f"tool-{counter}"))
                edges.append(
                    _edge(EdgeType.INVOKES, parent_id, child_id, edge_id_seed=counter)
                )
                next_level.append(child_id)
        current_level = next_level

    return tuple(nodes), tuple(edges)


class TestValidation:
    def test_max_explored_paths_must_be_at_least_one(self) -> None:
        with pytest.raises(ValueError, match="max_explored_paths"):
            compute_transitive_capability_paths(
                (_AGENT_NODE,), (), max_explored_paths=0
            )

    def test_max_returned_paths_must_be_at_least_one(self) -> None:
        with pytest.raises(ValueError, match="max_returned_paths"):
            compute_transitive_capability_paths(
                (_AGENT_NODE,), (), max_returned_paths=0
            )

    def test_max_seconds_must_be_greater_than_zero(self) -> None:
        with pytest.raises(ValueError, match="max_seconds"):
            compute_transitive_capability_paths((_AGENT_NODE,), (), max_seconds=0)


class TestExplodedPathsBound:
    def test_is_enforced_and_configurable(self) -> None:
        """Total paths explored is bounded and configurable."""
        nodes, edges = _build_fanout_graph(branching=4, levels=4)

        _paths, diagnostics = compute_transitive_capability_paths(
            nodes, edges, max_explored_paths=10
        )

        assert len(diagnostics) == 1
        assert diagnostics[0].code == "INCOMPLETE-BOUND-EXCEEDED"
        assert "explored-path" in diagnostics[0].message

    def test_default_does_not_truncate_a_small_graph(self) -> None:
        nodes, edges = _build_fanout_graph(branching=2, levels=2)

        paths, diagnostics = compute_transitive_capability_paths(nodes, edges)

        assert diagnostics == ()
        assert len(paths) > 0


class TestReturnedPathsBound:
    def test_is_enforced_and_configurable(self) -> None:
        """Memory, represented as bounded result size."""
        nodes, edges = _build_fanout_graph(branching=5, levels=2)

        paths, diagnostics = compute_transitive_capability_paths(
            nodes, edges, max_returned_paths=3
        )

        assert len(paths) <= 3
        assert len(diagnostics) == 1
        assert diagnostics[0].code == "INCOMPLETE-BOUND-EXCEEDED"
        assert "returned-path" in diagnostics[0].message


class TestSecondsBound:
    def test_is_enforced(self) -> None:
        """Wall-clock time is bounded and configurable. Exact
        truncation location is not asserted here -- see the module
        docstring's disclosed non-determinism for this one bound."""
        nodes, edges = _build_fanout_graph(branching=6, levels=4)

        start = time.monotonic()
        _paths, diagnostics = compute_transitive_capability_paths(
            nodes, edges, max_seconds=1e-9, max_explored_paths=10**9
        )
        elapsed = time.monotonic() - start

        assert len(diagnostics) == 1
        assert diagnostics[0].code == "INCOMPLETE-BOUND-EXCEEDED"
        assert "wall-clock" in diagnostics[0].message
        assert elapsed < 5.0


class TestDeterminism:
    def test_explored_path_truncation_is_independent_of_input_order(self) -> None:
        """The same graph truncates at the same place, regardless
        of the order nodes/edges are supplied in."""
        nodes, edges = _build_fanout_graph(branching=4, levels=4)

        first_paths, first_diagnostics = compute_transitive_capability_paths(
            nodes, edges, max_explored_paths=25
        )

        shuffled_nodes = list(nodes)
        shuffled_edges = list(edges)
        random.Random(0).shuffle(shuffled_nodes)
        random.Random(1).shuffle(shuffled_edges)
        second_paths, second_diagnostics = compute_transitive_capability_paths(
            tuple(shuffled_nodes), tuple(shuffled_edges), max_explored_paths=25
        )

        assert first_paths == second_paths
        assert first_diagnostics == second_diagnostics

    def test_returned_path_truncation_is_independent_of_input_order(self) -> None:
        nodes, edges = _build_fanout_graph(branching=5, levels=2)

        first_paths, first_diagnostics = compute_transitive_capability_paths(
            nodes, edges, max_returned_paths=4
        )

        shuffled_edges = list(edges)
        random.Random(2).shuffle(shuffled_edges)
        second_paths, second_diagnostics = compute_transitive_capability_paths(
            nodes, tuple(shuffled_edges), max_returned_paths=4
        )

        assert first_paths == second_paths
        assert first_diagnostics == second_diagnostics

    def test_truncation_is_repeatable_across_many_runs(self) -> None:
        """Stated directly: repeated calls over the identical
        input truncate identically every time."""
        nodes, edges = _build_fanout_graph(branching=3, levels=4)

        results = [
            compute_transitive_capability_paths(nodes, edges, max_explored_paths=15)
            for _ in range(5)
        ]

        assert all(result == results[0] for result in results)


def test_combinatorially_explosive_fixture_completes_promptly_and_truncates() -> None:
    """A combinatorially explosive fixture (here: 5 ** 5 =
    3125 potential leaf paths without any bound) completes within the
    configured bound and reports truncation."""
    nodes, edges = _build_fanout_graph(branching=5, levels=5)

    start = time.monotonic()
    paths, diagnostics = compute_transitive_capability_paths(
        nodes, edges, max_explored_paths=2_000
    )
    elapsed = time.monotonic() - start

    assert elapsed < 5.0
    assert len(diagnostics) == 1
    assert diagnostics[0].code == "INCOMPLETE-BOUND-EXCEEDED"
    assert len(paths) > 0  # some genuine progress was still made and reported
