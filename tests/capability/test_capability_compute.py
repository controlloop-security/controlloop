"""Tests for controlloop.capability.compute."""

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
from controlloop.capability import (
    compute_effective_authority,
    effective_authority_digest,
)

_AGENT_ID = f"clp:agent:sha256:{'a' * 64}"
_TOOL_ID = f"clp:tool:sha256:{'b' * 64}"
_RESOURCE_ID = f"clp:resource:sha256:{'c' * 64}"
_IDENTITY_ID = f"clp:identity:sha256:{'d' * 64}"
_OTHER_RESOURCE_ID = f"clp:resource:sha256:{'e' * 64}"


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
    edge_id_seed: str = "f",
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


_AGENT_NODE = _node(_AGENT_ID, NodeType.AGENT, "refund-agent")
_TOOL_NODE = _node(_TOOL_ID, NodeType.TOOL, "refund-tool")
_RESOURCE_NODE = _node(_RESOURCE_ID, NodeType.RESOURCE, "billing-db")
_IDENTITY_NODE = _node(_IDENTITY_ID, NodeType.IDENTITY, "service-account")


class TestDirectAuthority:
    """An agent's direct action edge produces an effective-authority
    entry."""

    def test_reads_edge_produces_an_entry(self) -> None:
        edges = (_edge(EdgeType.READS, _AGENT_ID, _RESOURCE_ID),)

        entries = compute_effective_authority((_AGENT_NODE, _RESOURCE_NODE), edges)

        assert len(entries) == 1
        assert entries[0].agent_id == _AGENT_ID
        assert entries[0].action is EdgeType.READS
        assert entries[0].resource_id == _RESOURCE_ID

    def test_entry_includes_permitting_identity_when_present(self) -> None:
        edges = (
            _edge(EdgeType.WRITES, _AGENT_ID, _RESOURCE_ID, edge_id_seed="1"),
            _edge(EdgeType.AUTHENTICATES_AS, _AGENT_ID, _IDENTITY_ID, edge_id_seed="2"),
        )

        entries = compute_effective_authority(
            (_AGENT_NODE, _RESOURCE_NODE, _IDENTITY_NODE), edges
        )

        assert len(entries) == 1
        assert entries[0].permitting_identity_id == _IDENTITY_ID
        assert entries[0].confidence is Confidence.HIGH

    def test_edge_from_a_non_agent_source_is_excluded(self) -> None:
        """A tool reading a resource on the agent's behalf is not
        misattributed to the agent -- connecting that back is the multi-hop
        computation's job, not this direct-only computation's."""
        edges = (
            _edge(EdgeType.INVOKES, _AGENT_ID, _TOOL_ID, edge_id_seed="1"),
            _edge(EdgeType.READS, _TOOL_ID, _RESOURCE_ID, edge_id_seed="2"),
        )

        entries = compute_effective_authority(
            (_AGENT_NODE, _TOOL_NODE, _RESOURCE_NODE), edges
        )

        # Only the agent->tool invokes edge produces an entry; the
        # tool->resource reads edge has a tool, not an agent, source.
        assert len(entries) == 1
        assert entries[0].action is EdgeType.INVOKES

    def test_structural_edges_alone_produce_no_entries(self) -> None:
        edges = (_edge(EdgeType.AUTHENTICATES_AS, _AGENT_ID, _IDENTITY_ID),)

        entries = compute_effective_authority((_AGENT_NODE, _IDENTITY_NODE), edges)

        assert entries == ()


class TestUnknownIdentity:
    """An action edge with no identity is never dropped."""

    def test_missing_identity_still_produces_an_entry(self) -> None:
        edges = (_edge(EdgeType.WRITES, _AGENT_ID, _RESOURCE_ID),)

        entries = compute_effective_authority((_AGENT_NODE, _RESOURCE_NODE), edges)

        assert len(entries) == 1
        assert entries[0].permitting_identity_id is None
        assert entries[0].confidence is Confidence.UNKNOWN


class TestDeduplicationAndDeterminism:
    """Duplicate edges collapse to one entry, and output order is
    deterministic."""

    def test_duplicate_edges_produce_one_entry(self) -> None:
        edges = (
            _edge(EdgeType.READS, _AGENT_ID, _RESOURCE_ID, edge_id_seed="1"),
            _edge(EdgeType.READS, _AGENT_ID, _RESOURCE_ID, edge_id_seed="1"),
        )

        entries = compute_effective_authority((_AGENT_NODE, _RESOURCE_NODE), edges)

        assert len(entries) == 1

    def test_input_order_does_not_affect_the_result(self) -> None:
        edges = [
            _edge(EdgeType.READS, _AGENT_ID, _RESOURCE_ID, edge_id_seed="1"),
            _edge(EdgeType.WRITES, _AGENT_ID, _OTHER_RESOURCE_ID, edge_id_seed="2"),
            _edge(EdgeType.AUTHENTICATES_AS, _AGENT_ID, _IDENTITY_ID, edge_id_seed="3"),
        ]
        nodes = (_AGENT_NODE, _RESOURCE_NODE, _IDENTITY_NODE)

        first = compute_effective_authority(nodes, tuple(edges))
        shuffled = edges[:]
        random.Random(0).shuffle(shuffled)
        second = compute_effective_authority(nodes, tuple(shuffled))

        assert first == second

    def test_result_is_sorted_deterministically(self) -> None:
        edges = (
            _edge(EdgeType.WRITES, _AGENT_ID, _OTHER_RESOURCE_ID, edge_id_seed="1"),
            _edge(EdgeType.READS, _AGENT_ID, _RESOURCE_ID, edge_id_seed="2"),
        )

        entries = compute_effective_authority(
            (_AGENT_NODE, _RESOURCE_NODE, _node(_OTHER_RESOURCE_ID, NodeType.RESOURCE)),
            edges,
        )

        assert entries == tuple(
            sorted(entries, key=lambda e: (e.agent_id, str(e.action), e.resource_id))
        )

    def test_digest_is_stable_across_equivalent_orderings(self) -> None:
        edges = [
            _edge(EdgeType.READS, _AGENT_ID, _RESOURCE_ID, edge_id_seed="1"),
            _edge(EdgeType.WRITES, _AGENT_ID, _OTHER_RESOURCE_ID, edge_id_seed="2"),
        ]
        nodes = (
            _AGENT_NODE,
            _RESOURCE_NODE,
            _node(_OTHER_RESOURCE_ID, NodeType.RESOURCE),
        )

        first = effective_authority_digest(
            compute_effective_authority(nodes, tuple(edges))
        )
        second = effective_authority_digest(
            compute_effective_authority(nodes, tuple(reversed(edges)))
        )

        assert first == second

    def test_digest_differs_for_genuinely_different_input(self) -> None:
        edges_a = (_edge(EdgeType.READS, _AGENT_ID, _RESOURCE_ID),)
        edges_b = (_edge(EdgeType.WRITES, _AGENT_ID, _RESOURCE_ID),)
        nodes = (_AGENT_NODE, _RESOURCE_NODE)

        digest_a = effective_authority_digest(
            compute_effective_authority(nodes, edges_a)
        )
        digest_b = effective_authority_digest(
            compute_effective_authority(nodes, edges_b)
        )

        assert digest_a != digest_b

    def test_no_input_produces_a_stable_digest(self) -> None:
        assert effective_authority_digest(()).startswith("sha256:")
