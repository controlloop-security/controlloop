"""Tests for merge_duplicate_edges.

The merge function unions and deduplicates evidence only. A disagreement
on type, status, confidence, or security attributes between two edges
sharing an ID is a genuine adapter disagreement, not a duplicate, and is
never silently resolved.
"""

from __future__ import annotations

import pytest

from controlloop.acbom import (
    Confidence,
    Edge,
    EdgeMergeConflictError,
    EdgeStatus,
    EdgeType,
    Evidence,
    SecurityAttributes,
    merge_duplicate_edges,
)

_AGENT_ID = f"clp:agent:sha256:{'a' * 64}"
_TOOL_ID = f"clp:tool:sha256:{'b' * 64}"
_RESOURCE_ID = f"clp:resource:sha256:{'e' * 64}"
_EDGE_ID = f"clp:edge:sha256:{'c' * 64}"
_OTHER_EDGE_ID = f"clp:edge:sha256:{'d' * 64}"


def _edge(
    *,
    id: str = _EDGE_ID,
    evidence: tuple[Evidence, ...],
    type: EdgeType = EdgeType.INVOKES,
    status: EdgeStatus = EdgeStatus.DIRECT,
    confidence: Confidence = Confidence.HIGH,
    security_attributes: SecurityAttributes | None = None,
) -> Edge:
    return Edge(
        id=id,
        source=_AGENT_ID,
        target=_TOOL_ID,
        type=type,
        status=status,
        security_attributes=(
            security_attributes
            if security_attributes is not None
            else SecurityAttributes()
        ),
        confidence=confidence,
        evidence=evidence,
    )


def test_empty_input_returns_empty_tuple() -> None:
    assert merge_duplicate_edges([]) == ()


def test_single_edge_passes_through_unchanged() -> None:
    edge = _edge(evidence=(Evidence(adapter="mcp", path="mcp/tools.json"),))

    result = merge_duplicate_edges([edge])

    assert result == (edge,)


def test_non_duplicate_edges_all_pass_through_unchanged() -> None:
    first = _edge(id=_EDGE_ID, evidence=(Evidence(adapter="mcp", path="a.json"),))
    second = _edge(
        id=_OTHER_EDGE_ID, evidence=(Evidence(adapter="a2a", path="b.json"),)
    )

    result = merge_duplicate_edges([first, second])

    assert set(result) == {first, second}
    assert len(result) == 2


def test_duplicate_edges_merge_evidence_preserving_both_records() -> None:
    """Merging duplicate edges preserves both evidence records."""
    mcp_evidence = Evidence(adapter="mcp", path="mcp/tools.json", line_start=1)
    a2a_evidence = Evidence(adapter="a2a", path="agent-card.json", line_start=2)
    from_mcp = _edge(evidence=(mcp_evidence,))
    from_a2a = _edge(evidence=(a2a_evidence,))

    result = merge_duplicate_edges([from_mcp, from_a2a])

    assert len(result) == 1
    assert set(result[0].evidence) == {mcp_evidence, a2a_evidence}


def test_merge_deduplicates_identical_evidence_from_both_sources() -> None:
    shared_evidence = Evidence(adapter="mcp", path="mcp/tools.json", line_start=1)
    first = _edge(evidence=(shared_evidence,))
    second = _edge(evidence=(shared_evidence,))

    result = merge_duplicate_edges([first, second])

    assert len(result) == 1
    assert result[0].evidence == (shared_evidence,)


def test_three_way_merge_combines_evidence_from_all_sources() -> None:
    evidence_a = Evidence(adapter="mcp", path="a.json")
    evidence_b = Evidence(adapter="a2a", path="b.json")
    evidence_c = Evidence(adapter="openapi", path="c.json")
    edges = [
        _edge(evidence=(evidence_a,)),
        _edge(evidence=(evidence_b,)),
        _edge(evidence=(evidence_c,)),
    ]

    result = merge_duplicate_edges(edges)

    assert len(result) == 1
    assert set(result[0].evidence) == {evidence_a, evidence_b, evidence_c}


def test_merge_result_is_independent_of_input_order() -> None:
    first = _edge(evidence=(Evidence(adapter="mcp", path="a.json"),))
    second = _edge(evidence=(Evidence(adapter="a2a", path="b.json"),))

    forward = merge_duplicate_edges([first, second])
    reverse = merge_duplicate_edges([second, first])

    assert len(forward) == len(reverse) == 1
    assert set(forward[0].evidence) == set(reverse[0].evidence)


@pytest.mark.parametrize(
    "conflicting",
    [
        {"type": EdgeType.READS},
        {"status": EdgeStatus.INFERRED},
        {"confidence": Confidence.LOW},
        {"security_attributes": SecurityAttributes(trusted=True)},
    ],
    ids=["type", "status", "confidence", "security_attributes"],
)
def test_duplicates_disagreeing_on_a_field_raise_instead_of_merging(
    conflicting: dict[str, object],
) -> None:
    first = _edge(evidence=(Evidence(adapter="mcp", path="a.json"),))
    second = _edge(
        evidence=(Evidence(adapter="a2a", path="b.json"),),
        **conflicting,  # type: ignore[arg-type]
    )

    with pytest.raises(EdgeMergeConflictError, match=_EDGE_ID):
        merge_duplicate_edges([first, second])


def test_unrelated_edges_with_different_endpoints_never_collide() -> None:
    invokes_tool = _edge(
        id=_EDGE_ID, evidence=(Evidence(adapter="mcp", path="a.json"),)
    )
    reads_resource = Edge(
        id=_OTHER_EDGE_ID,
        source=_AGENT_ID,
        target=_RESOURCE_ID,
        type=EdgeType.READS,
        status=EdgeStatus.DIRECT,
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=(Evidence(adapter="mcp", path="b.json"),),
    )

    result = merge_duplicate_edges([invokes_tool, reads_resource])

    assert set(result) == {invokes_tool, reads_resource}
