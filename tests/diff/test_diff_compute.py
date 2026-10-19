"""Tests for controlloop.diff.compute."""

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
)
from controlloop.capability import EffectiveAuthorityEntry
from controlloop.capability.models import CapabilityPath, PathHop
from controlloop.diff import (
    ChangeKind,
    compute_diff,
    diff_edges,
    diff_effective_authority,
    diff_nodes,
    diff_transitive_capability_paths,
)
from controlloop.diff.compute import _classify

_AGENT_ID = f"clp:agent:sha256:{'a' * 64}"
_TOOL_ID = f"clp:tool:sha256:{'b' * 64}"
_RESOURCE_ID = f"clp:resource:sha256:{'c' * 64}"
_IDENTITY_ID = f"clp:identity:sha256:{'d' * 64}"
_OTHER_RESOURCE_ID = f"clp:resource:sha256:{'e' * 64}"


def _node(
    node_id: str,
    node_type: NodeType,
    *,
    name: str = "x",
    confidence: Confidence = Confidence.HIGH,
    path: str = "a.json",
    line_start: int | None = None,
) -> Node:
    return Node(
        id=node_id,
        type=node_type,
        name=name,
        security_attributes=SecurityAttributes(),
        confidence=confidence,
        evidence=(Evidence(adapter="mcp", path=path, line_start=line_start),),
    )


def _edge(
    edge_type: EdgeType,
    source: str,
    target: str,
    *,
    edge_id_seed: str = "f",
    confidence: Confidence = Confidence.HIGH,
    path: str = "a.json",
) -> Edge:
    return Edge(
        id=f"clp:edge:sha256:{edge_id_seed * 64}",
        source=source,
        target=target,
        type=edge_type,
        status=EdgeStatus.DIRECT,
        security_attributes=SecurityAttributes(),
        confidence=confidence,
        evidence=(Evidence(adapter="mcp", path=path),),
    )


def _entry(
    *,
    agent_id: str = _AGENT_ID,
    action: EdgeType = EdgeType.READS,
    resource_id: str = _RESOURCE_ID,
    permitting_identity_id: str | None = None,
    confidence: Confidence = Confidence.HIGH,
) -> EffectiveAuthorityEntry:
    return EffectiveAuthorityEntry(
        schema_version="1.0.0",
        agent_id=agent_id,
        action=action,
        resource_id=resource_id,
        permitting_identity_id=permitting_identity_id,
        confidence=confidence,
        evidence=(Evidence(adapter="mcp", path="a.json"),),
    )


def _hop(
    edge_type: EdgeType, source: str, target: str, *, edge_id_seed: str
) -> PathHop:
    return PathHop(
        edge_id=f"clp:edge:sha256:{edge_id_seed * 64}",
        edge_type=edge_type,
        source_id=source,
        target_id=target,
        evidence=(Evidence(adapter="mcp", path="a.json"),),
    )


def _path(
    agent_id: str,
    target_id: str,
    target_type: NodeType,
    hops: tuple[PathHop, ...],
    *,
    confidence: Confidence = Confidence.HIGH,
) -> CapabilityPath:
    return CapabilityPath(
        schema_version="1.0.0",
        agent_id=agent_id,
        target_id=target_id,
        target_type=target_type,
        hops=hops,
        confidence=confidence,
    )


_AGENT_NODE = _node(_AGENT_ID, NodeType.AGENT, name="refund-agent")
_TOOL_NODE = _node(_TOOL_ID, NodeType.TOOL, name="refund-tool")
_RESOURCE_NODE = _node(_RESOURCE_ID, NodeType.RESOURCE, name="billing-db")
_OTHER_RESOURCE_NODE = _node(_OTHER_RESOURCE_ID, NodeType.RESOURCE, name="orders-db")
_IDENTITY_NODE = _node(_IDENTITY_ID, NodeType.IDENTITY, name="service-account")


class TestDiffNodesAllFourStates:
    """Every node is classified as added, removed, changed, or unknown."""

    def test_node_only_in_current_is_added(self) -> None:
        changes = diff_nodes((), (_AGENT_NODE,))

        assert len(changes) == 1
        assert changes[0].kind is ChangeKind.ADDED
        assert changes[0].node_id == _AGENT_ID
        assert changes[0].before is None
        assert changes[0].after == _AGENT_NODE

    def test_node_only_in_baseline_is_removed(self) -> None:
        changes = diff_nodes((_AGENT_NODE,), ())

        assert len(changes) == 1
        assert changes[0].kind is ChangeKind.REMOVED
        assert changes[0].before == _AGENT_NODE
        assert changes[0].after is None

    def test_node_with_different_name_is_changed(self) -> None:
        renamed = _node(_AGENT_ID, NodeType.AGENT, name="renamed-agent")

        changes = diff_nodes((_AGENT_NODE,), (renamed,))

        assert len(changes) == 1
        assert changes[0].kind is ChangeKind.CHANGED
        assert changes[0].before == _AGENT_NODE
        assert changes[0].after == renamed

    def test_node_confidence_dropping_to_unknown_is_unknown_not_changed(self) -> None:
        degraded = _node(_AGENT_ID, NodeType.AGENT, confidence=Confidence.UNKNOWN)

        changes = diff_nodes((_AGENT_NODE,), (degraded,))

        assert len(changes) == 1
        assert changes[0].kind is ChangeKind.UNKNOWN

    def test_identical_node_produces_no_change(self) -> None:
        changes = diff_nodes((_AGENT_NODE,), (_AGENT_NODE,))

        assert changes == ()


class TestDiffNodesStableIdentity:
    """A moved or reformatted definition (evidence/line-number only
    difference) is not reported as a change, since `Node.id` never encodes
    evidence."""

    def test_line_number_only_difference_is_not_a_change(self) -> None:
        original = _node(_AGENT_ID, NodeType.AGENT, line_start=10)
        moved = _node(_AGENT_ID, NodeType.AGENT, line_start=200)

        changes = diff_nodes((original,), (moved,))

        assert changes == ()


class TestClassifyBothSidesAbsent:
    """`_classify(None, None)` is never reached through `diff_nodes`,
    `diff_edges`, or `diff_effective_authority` -- every key they pass
    to it comes from the union of both sides' own keys, so at least one
    side is always present. Exercised directly here purely as a
    defensive-branch guarantee, not a reachable product scenario."""

    def test_both_none_returns_none(self) -> None:
        assert _classify(None, None) is None


class TestDiffEdgesAllFourStates:
    """Every edge is classified as added, removed, changed, or unknown."""

    def test_edge_only_in_current_is_added(self) -> None:
        edge = _edge(EdgeType.READS, _AGENT_ID, _RESOURCE_ID)

        changes = diff_edges((), (edge,))

        assert len(changes) == 1
        assert changes[0].kind is ChangeKind.ADDED
        assert changes[0].edge_id == edge.id

    def test_edge_only_in_baseline_is_removed(self) -> None:
        edge = _edge(EdgeType.READS, _AGENT_ID, _RESOURCE_ID)

        changes = diff_edges((edge,), ())

        assert len(changes) == 1
        assert changes[0].kind is ChangeKind.REMOVED

    def test_edge_with_different_confidence_is_changed(self) -> None:
        before = _edge(
            EdgeType.READS, _AGENT_ID, _RESOURCE_ID, confidence=Confidence.HIGH
        )
        after = _edge(
            EdgeType.READS, _AGENT_ID, _RESOURCE_ID, confidence=Confidence.MEDIUM
        )

        changes = diff_edges((before,), (after,))

        assert len(changes) == 1
        assert changes[0].kind is ChangeKind.CHANGED

    def test_edge_confidence_dropping_to_unknown_is_unknown_not_changed(self) -> None:
        before = _edge(
            EdgeType.READS, _AGENT_ID, _RESOURCE_ID, confidence=Confidence.HIGH
        )
        after = _edge(
            EdgeType.READS, _AGENT_ID, _RESOURCE_ID, confidence=Confidence.UNKNOWN
        )

        changes = diff_edges((before,), (after,))

        assert len(changes) == 1
        assert changes[0].kind is ChangeKind.UNKNOWN

    def test_identical_edge_produces_no_change(self) -> None:
        edge = _edge(EdgeType.READS, _AGENT_ID, _RESOURCE_ID)

        changes = diff_edges((edge,), (edge,))

        assert changes == ()


class TestDiffEffectiveAuthorityAllFourStates:
    """Every effective-authority entry is classified as added, removed,
    changed, or unknown."""

    def test_entry_only_in_current_is_added(self) -> None:
        entry = _entry()

        changes = diff_effective_authority((), (entry,))

        assert len(changes) == 1
        assert changes[0].kind is ChangeKind.ADDED
        assert changes[0].agent_id == _AGENT_ID
        assert changes[0].action is EdgeType.READS
        assert changes[0].resource_id == _RESOURCE_ID

    def test_entry_only_in_baseline_is_removed(self) -> None:
        entry = _entry()

        changes = diff_effective_authority((entry,), ())

        assert len(changes) == 1
        assert changes[0].kind is ChangeKind.REMOVED

    def test_entry_with_different_permitting_identity_is_changed(self) -> None:
        before = _entry(permitting_identity_id=_IDENTITY_ID)
        after = _entry(permitting_identity_id=None, confidence=Confidence.MEDIUM)

        changes = diff_effective_authority((before,), (after,))

        assert len(changes) == 1
        assert changes[0].kind is ChangeKind.CHANGED

    def test_identical_entry_produces_no_change(self) -> None:
        entry = _entry()

        changes = diff_effective_authority((entry,), (entry,))

        assert changes == ()


class TestEffectiveAuthorityUnknownDistinctFromRemoved:
    """A capability that keeps existing but loses its permitting identity
    (confidence drops to UNKNOWN) is UNKNOWN, not REMOVED -- distinct from a
    capability that genuinely vanishes, which is REMOVED. Both scenarios
    share the same starting fixture so the two outcomes are directly
    comparable."""

    def test_confidence_dropping_to_unknown_with_the_same_key_is_unknown(self) -> None:
        before = _entry(permitting_identity_id=_IDENTITY_ID, confidence=Confidence.HIGH)
        after = _entry(permitting_identity_id=None, confidence=Confidence.UNKNOWN)

        changes = diff_effective_authority((before,), (after,))

        assert len(changes) == 1
        assert changes[0].kind is ChangeKind.UNKNOWN
        assert changes[0].before == before
        assert changes[0].after == after

    def test_the_same_fact_vanishing_entirely_is_removed_not_unknown(self) -> None:
        before = _entry(permitting_identity_id=_IDENTITY_ID, confidence=Confidence.HIGH)

        changes = diff_effective_authority((before,), ())

        assert len(changes) == 1
        assert changes[0].kind is ChangeKind.REMOVED

    def test_unknown_confidence_already_unknown_on_both_sides_is_no_change(
        self,
    ) -> None:
        entry = _entry(confidence=Confidence.UNKNOWN)

        changes = diff_effective_authority((entry,), (entry,))

        assert changes == ()

    def test_losing_the_permitting_identity_is_one_unknown_entry(self) -> None:
        """The scenario the unknown-vs-removed distinction exists for: an
        agent's read access to a resource keeps existing, but the edge
        asserting its permitting identity is gone, so the recomputed entry
        for the same (agent, action, resource) triple now carries
        `permitting_identity_id=None` and `confidence=UNKNOWN`. Keying on
        the narrower triple (not `EffectiveAuthorityEntry`'s own wider dedup
        key) is what collapses this into one `UNKNOWN` entry instead of an
        unrelated `REMOVED`+`ADDED` pair."""

        before_edges = (
            _edge(EdgeType.READS, _AGENT_ID, _RESOURCE_ID, edge_id_seed="1"),
            _edge(EdgeType.AUTHENTICATES_AS, _AGENT_ID, _IDENTITY_ID, edge_id_seed="2"),
        )
        after_edges = (
            _edge(EdgeType.READS, _AGENT_ID, _RESOURCE_ID, edge_id_seed="1"),
        )
        nodes = (_AGENT_NODE, _RESOURCE_NODE, _IDENTITY_NODE)

        changes = compute_diff(
            baseline_nodes=nodes,
            baseline_edges=before_edges,
            current_nodes=nodes,
            current_edges=after_edges,
        )

        assert len(changes.effective_authority_changes) == 1
        assert changes.effective_authority_changes[0].kind is ChangeKind.UNKNOWN


class TestComputeDiffIdenticalRepositoryIsEmpty:
    """An identical repository against its own baseline produces an empty
    diff."""

    def test_identical_graphs_produce_an_empty_diff(self) -> None:
        nodes = (_AGENT_NODE, _TOOL_NODE, _RESOURCE_NODE, _IDENTITY_NODE)
        edges = (
            _edge(EdgeType.INVOKES, _AGENT_ID, _TOOL_ID, edge_id_seed="1"),
            _edge(EdgeType.READS, _AGENT_ID, _RESOURCE_ID, edge_id_seed="2"),
            _edge(EdgeType.AUTHENTICATES_AS, _AGENT_ID, _IDENTITY_ID, edge_id_seed="3"),
        )

        result = compute_diff(
            baseline_nodes=nodes,
            baseline_edges=edges,
            current_nodes=nodes,
            current_edges=edges,
        )

        assert result.is_empty is True
        assert result.node_changes == ()
        assert result.edge_changes == ()
        assert result.effective_authority_changes == ()

    def test_both_sides_completely_empty_is_also_an_empty_diff(self) -> None:
        result = compute_diff(
            baseline_nodes=(), baseline_edges=(), current_nodes=(), current_edges=()
        )

        assert result.is_empty is True


class TestDeterministicOrdering:
    """Diff output order does not depend on input order."""

    def test_node_diff_order_is_independent_of_input_order(self) -> None:
        nodes = [
            _node(f"clp:agent:sha256:{digit * 64}", NodeType.AGENT, name=str(digit))
            for digit in "0123456789"
        ]
        random.shuffle(nodes)
        shuffled_current = tuple(nodes)
        random.shuffle(nodes)
        shuffled_again = tuple(nodes)

        first = diff_nodes((), shuffled_current)
        second = diff_nodes((), shuffled_again)

        assert [change.node_id for change in first] == sorted(
            change.node_id for change in first
        )
        assert first == second

    def test_edge_diff_order_is_independent_of_input_order(self) -> None:
        edges = [
            _edge(EdgeType.READS, _AGENT_ID, _RESOURCE_ID, edge_id_seed=str(digit))
            for digit in "0123456789"
        ]
        random.shuffle(edges)
        shuffled_current = tuple(edges)
        random.shuffle(edges)
        shuffled_again = tuple(edges)

        first = diff_edges((), shuffled_current)
        second = diff_edges((), shuffled_again)

        assert [change.edge_id for change in first] == sorted(
            change.edge_id for change in first
        )
        assert first == second

    def test_effective_authority_diff_order_is_independent_of_input_order(
        self,
    ) -> None:
        entries = [
            _entry(resource_id=f"clp:resource:sha256:{digit * 64}")
            for digit in "0123456789"
        ]
        random.shuffle(entries)
        shuffled_current = tuple(entries)
        random.shuffle(entries)
        shuffled_again = tuple(entries)

        first = diff_effective_authority((), shuffled_current)
        second = diff_effective_authority((), shuffled_again)

        assert [change.resource_id for change in first] == sorted(
            change.resource_id for change in first
        )
        assert first == second


class TestComputeDiffCombinesAllThreeDomains:
    def test_node_edge_and_effective_authority_changes_all_present(self) -> None:
        baseline_nodes = (_AGENT_NODE, _RESOURCE_NODE)
        baseline_edges = (
            _edge(EdgeType.READS, _AGENT_ID, _RESOURCE_ID, edge_id_seed="1"),
        )
        current_nodes = (_AGENT_NODE, _OTHER_RESOURCE_NODE)
        current_edges = (
            _edge(EdgeType.WRITES, _AGENT_ID, _OTHER_RESOURCE_ID, edge_id_seed="2"),
        )

        result = compute_diff(
            baseline_nodes=baseline_nodes,
            baseline_edges=baseline_edges,
            current_nodes=current_nodes,
            current_edges=current_edges,
        )

        assert result.is_empty is False
        assert any(change.kind is ChangeKind.REMOVED for change in result.node_changes)
        assert any(change.kind is ChangeKind.ADDED for change in result.node_changes)
        assert any(change.kind is ChangeKind.REMOVED for change in result.edge_changes)
        assert any(change.kind is ChangeKind.ADDED for change in result.edge_changes)
        assert any(
            change.kind is ChangeKind.REMOVED
            for change in result.effective_authority_changes
        )
        assert any(
            change.kind is ChangeKind.ADDED
            for change in result.effective_authority_changes
        )


class TestDiffTransitiveCapabilityPaths:
    """The same four-state classification, extended to `CapabilityPath`; the
    material summary depends on it."""

    def test_path_only_in_current_is_added(self) -> None:
        hops = (
            _hop(EdgeType.DELEGATES_TO, _AGENT_ID, _IDENTITY_ID, edge_id_seed="1"),
            _hop(EdgeType.INVOKES, _IDENTITY_ID, _TOOL_ID, edge_id_seed="2"),
        )
        path = _path(_AGENT_ID, _TOOL_ID, NodeType.TOOL, hops)

        changes = diff_transitive_capability_paths((), (path,))

        assert len(changes) == 1
        assert changes[0].kind is ChangeKind.ADDED
        assert changes[0].agent_id == _AGENT_ID
        assert changes[0].target_id == _TOOL_ID
        assert changes[0].target_type is NodeType.TOOL
        assert changes[0].after == path

    def test_path_only_in_baseline_is_removed(self) -> None:
        hops = (
            _hop(EdgeType.DELEGATES_TO, _AGENT_ID, _IDENTITY_ID, edge_id_seed="1"),
            _hop(EdgeType.INVOKES, _IDENTITY_ID, _TOOL_ID, edge_id_seed="2"),
        )
        path = _path(_AGENT_ID, _TOOL_ID, NodeType.TOOL, hops)

        changes = diff_transitive_capability_paths((path,), ())

        assert len(changes) == 1
        assert changes[0].kind is ChangeKind.REMOVED

    def test_identical_path_produces_no_change(self) -> None:
        hops = (
            _hop(EdgeType.DELEGATES_TO, _AGENT_ID, _IDENTITY_ID, edge_id_seed="1"),
            _hop(EdgeType.INVOKES, _IDENTITY_ID, _TOOL_ID, edge_id_seed="2"),
        )
        path = _path(_AGENT_ID, _TOOL_ID, NodeType.TOOL, hops)

        changes = diff_transitive_capability_paths((path,), (path,))

        assert changes == ()

    def test_confidence_dropping_to_unknown_is_unknown_not_changed(self) -> None:
        hops = (
            _hop(EdgeType.DELEGATES_TO, _AGENT_ID, _IDENTITY_ID, edge_id_seed="1"),
            _hop(EdgeType.INVOKES, _IDENTITY_ID, _TOOL_ID, edge_id_seed="2"),
        )
        before = _path(
            _AGENT_ID, _TOOL_ID, NodeType.TOOL, hops, confidence=Confidence.HIGH
        )
        after = _path(
            _AGENT_ID, _TOOL_ID, NodeType.TOOL, hops, confidence=Confidence.UNKNOWN
        )

        changes = diff_transitive_capability_paths((before,), (after,))

        assert len(changes) == 1
        assert changes[0].kind is ChangeKind.UNKNOWN

    def test_two_distinct_routes_to_the_same_target_are_both_reported(self) -> None:
        """Boundary case: `compute_transitive_capability_paths` can
        legitimately return more than one path to the same
        `(agent_id, target_id)` pair. Keying on the full edge-ID chain
        (not the narrower pair) must report both as independent
        `ADDED` changes, never collapse them into one."""

        route_one = _path(
            _AGENT_ID,
            _TOOL_ID,
            NodeType.TOOL,
            (
                _hop(EdgeType.DELEGATES_TO, _AGENT_ID, _IDENTITY_ID, edge_id_seed="1"),
                _hop(EdgeType.INVOKES, _IDENTITY_ID, _TOOL_ID, edge_id_seed="2"),
            ),
        )
        route_two = _path(
            _AGENT_ID,
            _TOOL_ID,
            NodeType.TOOL,
            (
                _hop(
                    EdgeType.AUTHENTICATES_AS,
                    _AGENT_ID,
                    _RESOURCE_ID,
                    edge_id_seed="3",
                ),
                _hop(EdgeType.INVOKES, _RESOURCE_ID, _TOOL_ID, edge_id_seed="4"),
            ),
        )

        changes = diff_transitive_capability_paths((), (route_one, route_two))

        assert len(changes) == 2
        assert {change.kind for change in changes} == {ChangeKind.ADDED}
        assert {change.after for change in changes} == {route_one, route_two}

    def test_order_is_independent_of_input_order(self) -> None:
        paths = [
            _path(
                _AGENT_ID,
                f"clp:tool:sha256:{digit * 64}",
                NodeType.TOOL,
                (
                    _hop(
                        EdgeType.DELEGATES_TO,
                        _AGENT_ID,
                        _IDENTITY_ID,
                        edge_id_seed="1",
                    ),
                    _hop(
                        EdgeType.INVOKES,
                        _IDENTITY_ID,
                        f"clp:tool:sha256:{digit * 64}",
                        edge_id_seed=digit,
                    ),
                ),
            )
            for digit in "0123456789"
        ]
        random.shuffle(paths)
        first = diff_transitive_capability_paths((), tuple(paths))
        random.shuffle(paths)
        second = diff_transitive_capability_paths((), tuple(paths))

        assert [change.target_id for change in first] == sorted(
            change.target_id for change in first
        )
        assert first == second
