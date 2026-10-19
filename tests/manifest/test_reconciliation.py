"""Tests for controlloop.manifest.reconciliation."""

from __future__ import annotations

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
from controlloop.manifest import (
    CURRENT_MANIFEST_SCHEMA_VERSION,
    AllowedDelegation,
    DataClassificationDeclaration,
    ManifestDocument,
    ProhibitedCapability,
    reconcile_manifest,
)

_AGENT_ID = f"clp:agent:sha256:{'a' * 64}"
_RESOURCE_ID = f"clp:resource:sha256:{'b' * 64}"
_OTHER_AGENT_ID = f"clp:agent:sha256:{'c' * 64}"
_EDGE_ID = f"clp:edge:sha256:{'d' * 64}"


def _manifest(**overrides: object) -> ManifestDocument:
    payload: dict[str, object] = {
        "schema_version": CURRENT_MANIFEST_SCHEMA_VERSION,
        "owner": "security-team",
    }
    payload.update(overrides)
    return ManifestDocument.model_validate(payload)


def _agent_node(node_id: str, name: str) -> Node:
    return Node(
        id=node_id,
        type=NodeType.AGENT,
        name=name,
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=(Evidence(adapter="mcp", path="a.json"),),
    )


def _resource_node(name: str) -> Node:
    return Node(
        id=_RESOURCE_ID,
        type=NodeType.RESOURCE,
        name=name,
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=(Evidence(adapter="mcp", path="a.json"),),
    )


def _edge(edge_type: EdgeType, source: str, target: str) -> Edge:
    return Edge(
        id=_EDGE_ID,
        source=source,
        target=target,
        type=edge_type,
        status=EdgeStatus.DIRECT,
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=(Evidence(adapter="mcp", path="a.json"),),
    )


def test_reconciliation_only_ever_returns_diagnostics() -> None:
    """Structural -- the return type is tuple[Diagnostic, ...], so there is
    no way for this function to delete or modify a discovered node or edge;
    it can only report."""
    import inspect

    signature = inspect.signature(reconcile_manifest)
    assert "Diagnostic" in str(signature.return_annotation)


def test_corroborated_declarations_produce_no_diagnostics() -> None:
    """Positive case: everything the manifest declares is corroborated by
    discovery, so nothing is flagged."""
    manifest = _manifest(
        data_classification=(
            DataClassificationDeclaration(
                resource="billing-db", sensitivity=Sensitivity.CONFIDENTIAL
            ),
        )
    )
    nodes = (_resource_node("billing-db"),)

    diagnostics = reconcile_manifest(manifest, nodes, ())

    assert diagnostics == ()


def test_prohibited_capability_found_in_discovery_is_a_contradiction() -> None:
    """A declared-prohibited capability that discovery finds is a
    contradiction."""
    manifest = _manifest(
        prohibited_capabilities=(
            ProhibitedCapability(
                agent="refund-agent",
                edge_type=EdgeType.WRITES,
                target="billing-db",
            ),
        )
    )
    nodes = (
        _agent_node(_AGENT_ID, "refund-agent"),
        _resource_node("billing-db"),
    )
    edges = (_edge(EdgeType.WRITES, _AGENT_ID, _RESOURCE_ID),)

    diagnostics = reconcile_manifest(manifest, nodes, edges)

    assert len(diagnostics) == 1
    assert diagnostics[0].code == "MANIFEST-CONTRADICTS-DISCOVERY"
    assert diagnostics[0].incomplete is False


def test_prohibited_capability_absent_from_discovery_is_not_flagged() -> None:
    manifest = _manifest(
        prohibited_capabilities=(
            ProhibitedCapability(
                agent="refund-agent",
                edge_type=EdgeType.WRITES,
                target="billing-db",
            ),
        )
    )
    nodes = (
        _agent_node(_AGENT_ID, "refund-agent"),
        _resource_node("billing-db"),
    )
    edges = (_edge(EdgeType.READS, _AGENT_ID, _RESOURCE_ID),)

    diagnostics = reconcile_manifest(manifest, nodes, edges)

    assert diagnostics == ()


def test_delegation_outside_allowed_set_is_a_contradiction() -> None:
    """Delegation outside the declared allowed set is a contradiction."""
    manifest = _manifest(
        allowed_delegation=(
            AllowedDelegation(agent="coordinator", targets=("researcher",)),
        )
    )
    nodes = (
        _agent_node(_AGENT_ID, "coordinator"),
        _agent_node(_OTHER_AGENT_ID, "unapproved-agent"),
    )
    edges = (_edge(EdgeType.DELEGATES_TO, _AGENT_ID, _OTHER_AGENT_ID),)

    diagnostics = reconcile_manifest(manifest, nodes, edges)

    assert len(diagnostics) == 1
    assert diagnostics[0].code == "MANIFEST-CONTRADICTS-DISCOVERY"


def test_delegation_inside_allowed_set_is_not_flagged() -> None:
    manifest = _manifest(
        allowed_delegation=(
            AllowedDelegation(agent="coordinator", targets=("researcher",)),
        )
    )
    nodes = (
        _agent_node(_AGENT_ID, "coordinator"),
        _agent_node(_OTHER_AGENT_ID, "researcher"),
    )
    edges = (_edge(EdgeType.DELEGATES_TO, _AGENT_ID, _OTHER_AGENT_ID),)

    diagnostics = reconcile_manifest(manifest, nodes, edges)

    assert diagnostics == ()


def test_uncorroborated_data_classification_is_unverified() -> None:
    """A data classification discovery cannot corroborate is unverified."""
    manifest = _manifest(
        data_classification=(
            DataClassificationDeclaration(
                resource="billing-db", sensitivity=Sensitivity.CONFIDENTIAL
            ),
        )
    )

    diagnostics = reconcile_manifest(manifest, (), ())

    assert len(diagnostics) == 1
    assert diagnostics[0].code == "INCOMPLETE-UNVERIFIED-DECLARATION"
    assert diagnostics[0].incomplete is True
    assert diagnostics[0].confidence is Confidence.UNKNOWN


def test_result_is_deterministic() -> None:
    manifest = _manifest(
        prohibited_capabilities=(
            ProhibitedCapability(
                agent="refund-agent",
                edge_type=EdgeType.WRITES,
                target="billing-db",
            ),
        )
    )
    nodes = (
        _agent_node(_AGENT_ID, "refund-agent"),
        _resource_node("billing-db"),
    )
    edges = (_edge(EdgeType.WRITES, _AGENT_ID, _RESOURCE_ID),)

    first = reconcile_manifest(manifest, nodes, edges)
    second = reconcile_manifest(manifest, nodes, edges)

    assert first == second
