"""Tests for merge_duplicate_nodes.

Mirrors test_edge_merge.py's structure. The one deliberate difference: this
merge also unions standards_identifiers alongside evidence, since both are
source-contributed reference data rather than part of the asserted fact.
"""

from __future__ import annotations

import pytest

from controlloop.acbom import (
    Confidence,
    Evidence,
    Node,
    NodeMergeConflictError,
    NodeType,
    SecurityAttributes,
    StandardIdentifier,
    merge_duplicate_nodes,
)

_AGENT_ID = f"clp:agent:sha256:{'a' * 64}"
_TOOL_ID = f"clp:tool:sha256:{'b' * 64}"


def _node(
    *,
    id: str = _AGENT_ID,
    evidence: tuple[Evidence, ...],
    type: NodeType = NodeType.AGENT,
    subtype: str | None = None,
    name: str = "Refund agent",
    confidence: Confidence = Confidence.HIGH,
    security_attributes: SecurityAttributes | None = None,
    standards_identifiers: tuple[StandardIdentifier, ...] = (),
) -> Node:
    return Node(
        id=id,
        type=type,
        subtype=subtype,
        name=name,
        security_attributes=(
            security_attributes
            if security_attributes is not None
            else SecurityAttributes()
        ),
        confidence=confidence,
        evidence=evidence,
        standards_identifiers=standards_identifiers,
    )


def test_empty_input_returns_empty_tuple() -> None:
    assert merge_duplicate_nodes([]) == ()


def test_single_node_passes_through_unchanged() -> None:
    node = _node(evidence=(Evidence(adapter="mcp", path="mcp/tools.json"),))

    result = merge_duplicate_nodes([node])

    assert result == (node,)


def test_non_duplicate_nodes_all_pass_through_unchanged() -> None:
    first = _node(id=_AGENT_ID, evidence=(Evidence(adapter="mcp", path="a.json"),))
    second = _node(
        id=_TOOL_ID,
        type=NodeType.TOOL,
        name="Refund tool",
        evidence=(Evidence(adapter="a2a", path="b.json"),),
    )

    result = merge_duplicate_nodes([first, second])

    assert set(result) == {first, second}
    assert len(result) == 2


def test_duplicate_nodes_merge_evidence_preserving_both_records() -> None:
    """Merging duplicate nodes preserves both evidence records."""
    mcp_evidence = Evidence(adapter="mcp", path="mcp/tools.json", line_start=1)
    a2a_evidence = Evidence(adapter="a2a", path="agent-card.json", line_start=2)
    from_mcp = _node(evidence=(mcp_evidence,))
    from_a2a = _node(evidence=(a2a_evidence,))

    result = merge_duplicate_nodes([from_mcp, from_a2a])

    assert len(result) == 1
    assert set(result[0].evidence) == {mcp_evidence, a2a_evidence}


def test_merge_deduplicates_identical_evidence_from_both_sources() -> None:
    shared_evidence = Evidence(adapter="mcp", path="mcp/tools.json", line_start=1)
    first = _node(evidence=(shared_evidence,))
    second = _node(evidence=(shared_evidence,))

    result = merge_duplicate_nodes([first, second])

    assert len(result) == 1
    assert result[0].evidence == (shared_evidence,)


def test_three_way_merge_combines_evidence_from_all_sources() -> None:
    evidence_a = Evidence(adapter="mcp", path="a.json")
    evidence_b = Evidence(adapter="a2a", path="b.json")
    evidence_c = Evidence(adapter="openapi", path="c.json")
    nodes = [
        _node(evidence=(evidence_a,)),
        _node(evidence=(evidence_b,)),
        _node(evidence=(evidence_c,)),
    ]

    result = merge_duplicate_nodes(nodes)

    assert len(result) == 1
    assert set(result[0].evidence) == {evidence_a, evidence_b, evidence_c}


def test_merge_result_is_independent_of_input_order() -> None:
    first = _node(evidence=(Evidence(adapter="mcp", path="a.json"),))
    second = _node(evidence=(Evidence(adapter="a2a", path="b.json"),))

    forward = merge_duplicate_nodes([first, second])
    reverse = merge_duplicate_nodes([second, first])

    assert len(forward) == len(reverse) == 1
    assert set(forward[0].evidence) == set(reverse[0].evidence)


def test_merge_unions_standards_identifiers_rather_than_requiring_agreement() -> None:
    """The deliberate difference from merge_duplicate_edges: two adapters
    can contribute different standards identifiers for the same node
    without that being a conflict."""
    mcp_identifier = StandardIdentifier(namespace="mcp", identifier="refund-tool")
    cyclonedx_identifier = StandardIdentifier(
        namespace="cyclonedx", identifier="pkg:refund-tool"
    )
    first = _node(
        evidence=(Evidence(adapter="mcp", path="a.json"),),
        standards_identifiers=(mcp_identifier,),
    )
    second = _node(
        evidence=(Evidence(adapter="cyclonedx", path="b.json"),),
        standards_identifiers=(cyclonedx_identifier,),
    )

    result = merge_duplicate_nodes([first, second])

    assert len(result) == 1
    assert set(result[0].standards_identifiers) == {
        mcp_identifier,
        cyclonedx_identifier,
    }


def test_merge_deduplicates_identical_standards_identifiers() -> None:
    shared_identifier = StandardIdentifier(namespace="mcp", identifier="refund-tool")
    first = _node(
        evidence=(Evidence(adapter="mcp", path="a.json"),),
        standards_identifiers=(shared_identifier,),
    )
    second = _node(
        evidence=(Evidence(adapter="mcp", path="b.json"),),
        standards_identifiers=(shared_identifier,),
    )

    result = merge_duplicate_nodes([first, second])

    assert result[0].standards_identifiers == (shared_identifier,)


@pytest.mark.parametrize(
    "conflicting",
    [
        {"type": NodeType.TOOL},
        {"subtype": "mcp-tool"},
        {"name": "Different display name"},
        {"confidence": Confidence.LOW},
        {"security_attributes": SecurityAttributes(trusted=True)},
    ],
    ids=["type", "subtype", "name", "confidence", "security_attributes"],
)
def test_duplicates_disagreeing_on_a_field_raise_instead_of_merging(
    conflicting: dict[str, object],
) -> None:
    first = _node(evidence=(Evidence(adapter="mcp", path="a.json"),))
    second = _node(
        evidence=(Evidence(adapter="a2a", path="b.json"),),
        **conflicting,  # type: ignore[arg-type]
    )

    with pytest.raises(NodeMergeConflictError, match=_AGENT_ID):
        merge_duplicate_nodes([first, second])


def test_unrelated_nodes_with_different_ids_never_collide() -> None:
    agent = _node(id=_AGENT_ID, evidence=(Evidence(adapter="mcp", path="a.json"),))
    tool = _node(
        id=_TOOL_ID,
        type=NodeType.TOOL,
        name="Refund tool",
        evidence=(Evidence(adapter="mcp", path="b.json"),),
    )

    result = merge_duplicate_nodes([agent, tool])

    assert set(result) == {agent, tool}
