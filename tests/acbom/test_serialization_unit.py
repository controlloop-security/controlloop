"""Focused unit tests for canonical ACBOM serialization."""

from __future__ import annotations

import math

import pytest
from pydantic import ValidationError

from controlloop.acbom import (
    ACBOMDocument,
    CanonicalizationError,
    Confidence,
    Diagnostic,
    DiagnosticSeverity,
    Edge,
    EdgeStatus,
    EdgeType,
    Evidence,
    Generator,
    Node,
    NodeType,
    Repository,
    SecurityAttributes,
    StandardIdentifier,
    canonical_json_bytes,
    compute_digest,
    serialize_document,
    with_digest,
)

_AGENT_ID = f"clp:agent:sha256:{'a' * 64}"
_TOOL_ID = f"clp:tool:sha256:{'b' * 64}"
_EDGE_ID = f"clp:edge:sha256:{'c' * 64}"
_PLACEHOLDER_DIGEST = f"sha256:{'0' * 64}"


def _document(*, reverse: bool) -> ACBOMDocument:
    first_evidence = Evidence(adapter="a2a", path="agent-card.json", line_start=1)
    second_evidence = Evidence(adapter="mcp", path="mcp/tools.json", line_start=2)
    evidence = (
        (second_evidence, first_evidence)
        if reverse
        else (
            first_evidence,
            second_evidence,
        )
    )

    agent = Node(
        id=_AGENT_ID,
        type=NodeType.AGENT,
        name="Refund agent",
        security_attributes=SecurityAttributes(
            data_classifications=("restricted", "internal")
            if reverse
            else ("internal", "restricted")
        ),
        confidence=Confidence.HIGH,
        evidence=evidence,
        standards_identifiers=(
            StandardIdentifier(namespace="z", identifier="agent"),
            StandardIdentifier(namespace="a", identifier="agent"),
        )
        if reverse
        else (
            StandardIdentifier(namespace="a", identifier="agent"),
            StandardIdentifier(namespace="z", identifier="agent"),
        ),
    )
    tool = Node(
        id=_TOOL_ID,
        type=NodeType.TOOL,
        name="Refund tool",
        security_attributes=SecurityAttributes(
            permission_scopes=("write", "read") if reverse else ("read", "write")
        ),
        confidence=Confidence.HIGH,
        evidence=(second_evidence,),
    )
    edge = Edge(
        id=_EDGE_ID,
        source=_AGENT_ID,
        target=_TOOL_ID,
        type=EdgeType.INVOKES,
        status=EdgeStatus.DIRECT,
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=evidence,
    )
    diagnostics = (
        Diagnostic(
            code="Z-LAST",
            severity=DiagnosticSeverity.WARNING,
            message="Later diagnostic",
            confidence=Confidence.MEDIUM,
            incomplete=False,
            evidence=(second_evidence,),
        ),
        Diagnostic(
            code="A-FIRST",
            severity=DiagnosticSeverity.INFO,
            message="Earlier diagnostic",
            confidence=Confidence.HIGH,
            incomplete=False,
            evidence=(first_evidence,),
        ),
    )

    return ACBOMDocument(
        schema_version="1.0.0",
        generator=Generator(name="controlloop", version="0.1.0"),
        repository=Repository(commit="abc123", root_digest=f"sha256:{'d' * 64}"),
        nodes=(tool, agent) if reverse else (agent, tool),
        edges=(edge,),
        diagnostics=diagnostics if reverse else tuple(reversed(diagnostics)),
        digest=_PLACEHOLDER_DIGEST,
    )


def test_permuted_collections_have_identical_bytes_and_digest() -> None:
    forward = _document(reverse=False)
    reverse = _document(reverse=True)

    assert serialize_document(forward) == serialize_document(reverse)
    assert compute_digest(forward) == compute_digest(reverse)


def test_with_digest_returns_new_canonical_frozen_document() -> None:
    source = _document(reverse=True)

    result = with_digest(source)

    assert result is not source
    assert source.digest == _PLACEHOLDER_DIGEST
    assert result.digest == compute_digest(source)
    assert result.nodes[0].id == _AGENT_ID
    with pytest.raises(ValidationError, match="frozen"):
        result.digest = _PLACEHOLDER_DIGEST


def test_digest_excludes_the_existing_document_digest() -> None:
    source = _document(reverse=False)
    different_digest = source.model_copy(update={"digest": f"sha256:{'f' * 64}"})

    assert compute_digest(source) == compute_digest(different_digest)


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_nonfinite_numbers_are_rejected_without_raw_values(value: float) -> None:
    with pytest.raises(
        CanonicalizationError,
        match=r"^canonical JSON contains a nonfinite number$",
    ) as error:
        canonical_json_bytes({"value": value})

    assert repr(value) not in str(error.value)


def test_unsupported_values_are_rejected_without_raw_values() -> None:
    canary = "raw-secret-canary"

    with pytest.raises(
        CanonicalizationError,
        match=r"^canonical JSON contains an unsupported value category$",
    ) as error:
        canonical_json_bytes({"value": {canary}})

    assert canary not in str(error.value)


def _document_with_every_node_type(*, reverse: bool) -> ACBOMDocument:
    """Fixture: one node of every NodeType in one document."""
    evidence = Evidence(adapter="fixture", path="src/example.py", line_start=1)
    node_ids = {
        node_type: f"clp:{node_type.value}:sha256:{digit * 64}"
        for node_type, digit in zip(NodeType, "01234567", strict=True)
    }
    node_types = tuple(reversed(tuple(NodeType))) if reverse else tuple(NodeType)
    nodes = tuple(
        Node(
            id=node_ids[node_type],
            type=node_type,
            name=f"Example {node_type.value}",
            security_attributes=SecurityAttributes(),
            confidence=Confidence.MEDIUM,
            evidence=(evidence,),
        )
        for node_type in node_types
    )
    edge = Edge(
        id=f"clp:edge:sha256:{'9' * 64}",
        source=node_ids[NodeType.AGENT],
        target=node_ids[NodeType.TOOL],
        type=EdgeType.INVOKES,
        status=EdgeStatus.DIRECT,
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=(evidence,),
    )

    return ACBOMDocument(
        schema_version="1.0.0",
        generator=Generator(name="controlloop", version="0.1.0"),
        repository=Repository(commit="abc123", root_digest=f"sha256:{'d' * 64}"),
        nodes=nodes,
        edges=(edge,),
        diagnostics=(),
        digest=_PLACEHOLDER_DIGEST,
    )


def test_round_trip_reproduces_the_digest_for_every_node_type() -> None:
    """The digest round-trips across the full eight-type set, not just two.

    Strict models reject a JSON array parsed into a Python ``list`` where a
    ``tuple`` field is declared, so the round trip must validate directly
    from JSON bytes (``model_validate_json``), not ``json.loads`` followed
    by ``model_validate`` on the resulting dict -- confirmed by reproducing
    the ``tuple_type`` error the latter raises before writing this test.
    """
    document = with_digest(_document_with_every_node_type(reverse=False))

    round_tripped = ACBOMDocument.model_validate_json(serialize_document(document))

    assert compute_digest(round_tripped) == document.digest
    assert {node.type for node in round_tripped.nodes} == set(NodeType)


def test_digest_is_permutation_invariant_across_the_full_node_type_set() -> None:
    forward = _document_with_every_node_type(reverse=False)
    reverse = _document_with_every_node_type(reverse=True)

    assert compute_digest(forward) == compute_digest(reverse)
    assert serialize_document(with_digest(forward)) == serialize_document(
        with_digest(reverse)
    )


def _document_with_two_edges(*, reverse: bool) -> ACBOMDocument:
    """Fixture with two edges: the earlier permutation test only ever used
    one edge, so it never proved edge *ordering* itself -- as opposed to
    node or diagnostic ordering -- is deterministic."""
    resource_id = f"clp:resource:sha256:{'8' * 64}"
    agent = Node(
        id=_AGENT_ID,
        type=NodeType.AGENT,
        name="Refund agent",
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=(Evidence(adapter="a2a", path="agent-card.json", line_start=1),),
    )
    tool = Node(
        id=_TOOL_ID,
        type=NodeType.TOOL,
        name="Refund tool",
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=(Evidence(adapter="mcp", path="mcp/tools.json", line_start=1),),
    )
    resource = Node(
        id=resource_id,
        type=NodeType.RESOURCE,
        name="Payments database",
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=(Evidence(adapter="iam", path="iam/policy.json", line_start=1),),
    )
    invokes = Edge(
        id=_EDGE_ID,
        source=_AGENT_ID,
        target=_TOOL_ID,
        type=EdgeType.INVOKES,
        status=EdgeStatus.DIRECT,
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=(Evidence(adapter="mcp", path="mcp/tools.json", line_start=2),),
    )
    writes = Edge(
        id=f"clp:edge:sha256:{'7' * 64}",
        source=_TOOL_ID,
        target=resource_id,
        type=EdgeType.WRITES,
        status=EdgeStatus.DIRECT,
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=(Evidence(adapter="iam", path="iam/policy.json", line_start=2),),
    )
    edges = (writes, invokes) if reverse else (invokes, writes)

    return ACBOMDocument(
        schema_version="1.0.0",
        generator=Generator(name="controlloop", version="0.1.0"),
        repository=Repository(commit="abc123", root_digest=f"sha256:{'d' * 64}"),
        nodes=(agent, tool, resource),
        edges=edges,
        diagnostics=(),
        digest=_PLACEHOLDER_DIGEST,
    )


def test_edge_ordering_in_canonical_output_is_deterministic() -> None:
    """Canonical ordering holds with two edges rather than one."""
    forward = _document_with_two_edges(reverse=False)
    reverse = _document_with_two_edges(reverse=True)

    assert compute_digest(forward) == compute_digest(reverse)
    assert serialize_document(with_digest(forward)) == serialize_document(
        with_digest(reverse)
    )

    canonical = with_digest(forward)
    assert [edge.id for edge in canonical.edges] == sorted(
        edge.id for edge in canonical.edges
    )
