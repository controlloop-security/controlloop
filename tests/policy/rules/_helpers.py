"""Shared test builders for `controlloop.policy.rules`. Mirrors the
hand-typed-content-addressed-ID fixture pattern already established in
`tests/policy/test_policy_engine.py` and
`tests/findings/test_finding_construction.py`, rather than
computing real IDs via `controlloop.acbom.identity` -- unit tests for
rule logic do not need genuinely content-addressed identity, only
structurally valid, stable IDs."""

from __future__ import annotations

from controlloop.acbom.models import (
    ACBOMDocument,
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
)
from controlloop.manifest.models import (
    CURRENT_MANIFEST_SCHEMA_VERSION,
    ManifestDocument,
)
from controlloop.policy.models import RuleContext

PLACEHOLDER_DIGEST = f"sha256:{'0' * 64}"


def hex_id(prefix: str, filler: str) -> str:
    return f"clp:{prefix}:sha256:{filler * 64}"


def one_evidence(
    *, path: str = "server.py", line_start: int | None = 10
) -> tuple[Evidence, ...]:
    return (Evidence(adapter="fixture", path=path, line_start=line_start),)


def agent_node(node_id: str, *, name: str, path: str | None = None) -> Node:
    return Node(
        id=node_id,
        type=NodeType.AGENT,
        name=name,
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=one_evidence(path=path or f"{name}.json"),
    )


def tool_node(
    node_id: str,
    *,
    name: str,
    security_attributes: SecurityAttributes | None = None,
    confidence: Confidence = Confidence.HIGH,
    path: str = "server.py",
    line_start: int | None = 10,
) -> Node:
    return Node(
        id=node_id,
        type=NodeType.TOOL,
        name=name,
        security_attributes=security_attributes or SecurityAttributes(),
        confidence=confidence,
        evidence=one_evidence(path=path, line_start=line_start),
    )


def resource_node(
    node_id: str,
    *,
    name: str,
    security_attributes: SecurityAttributes | None = None,
    confidence: Confidence = Confidence.HIGH,
    path: str = "server.py",
    line_start: int | None = 10,
) -> Node:
    return Node(
        id=node_id,
        type=NodeType.RESOURCE,
        name=name,
        security_attributes=security_attributes or SecurityAttributes(),
        confidence=confidence,
        evidence=one_evidence(path=path, line_start=line_start),
    )


def identity_node(
    node_id: str,
    *,
    name: str,
    security_attributes: SecurityAttributes | None = None,
    confidence: Confidence = Confidence.HIGH,
    path: str = "server.py",
    line_start: int | None = 10,
) -> Node:
    return Node(
        id=node_id,
        type=NodeType.IDENTITY,
        name=name,
        security_attributes=security_attributes or SecurityAttributes(),
        confidence=confidence,
        evidence=one_evidence(path=path, line_start=line_start),
    )


def permission_node(
    node_id: str,
    *,
    name: str,
    security_attributes: SecurityAttributes | None = None,
    confidence: Confidence = Confidence.HIGH,
    path: str = "server.py",
    line_start: int | None = 10,
) -> Node:
    return Node(
        id=node_id,
        type=NodeType.PERMISSION,
        name=name,
        security_attributes=security_attributes or SecurityAttributes(),
        confidence=confidence,
        evidence=one_evidence(path=path, line_start=line_start),
    )


def data_class_node(
    node_id: str,
    *,
    name: str,
    security_attributes: SecurityAttributes | None = None,
    confidence: Confidence = Confidence.HIGH,
    path: str = "server.py",
    line_start: int | None = 10,
) -> Node:
    return Node(
        id=node_id,
        type=NodeType.DATA_CLASS,
        name=name,
        security_attributes=security_attributes or SecurityAttributes(),
        confidence=confidence,
        evidence=one_evidence(path=path, line_start=line_start),
    )


def invokes_edge(
    edge_id: str, *, source: str, target: str, confidence: Confidence = Confidence.HIGH
) -> Edge:
    return Edge(
        id=edge_id,
        source=source,
        target=target,
        type=EdgeType.INVOKES,
        status=EdgeStatus.DIRECT,
        security_attributes=SecurityAttributes(),
        confidence=confidence,
        evidence=one_evidence(),
    )


def reads_edge(
    edge_id: str, *, source: str, target: str, confidence: Confidence = Confidence.HIGH
) -> Edge:
    return Edge(
        id=edge_id,
        source=source,
        target=target,
        type=EdgeType.READS,
        status=EdgeStatus.DIRECT,
        security_attributes=SecurityAttributes(),
        confidence=confidence,
        evidence=one_evidence(),
    )


def writes_edge(
    edge_id: str, *, source: str, target: str, confidence: Confidence = Confidence.HIGH
) -> Edge:
    return Edge(
        id=edge_id,
        source=source,
        target=target,
        type=EdgeType.WRITES,
        status=EdgeStatus.DIRECT,
        security_attributes=SecurityAttributes(),
        confidence=confidence,
        evidence=one_evidence(),
    )


def delegates_to_edge(
    edge_id: str, *, source: str, target: str, confidence: Confidence = Confidence.HIGH
) -> Edge:
    return Edge(
        id=edge_id,
        source=source,
        target=target,
        type=EdgeType.DELEGATES_TO,
        status=EdgeStatus.DIRECT,
        security_attributes=SecurityAttributes(),
        confidence=confidence,
        evidence=one_evidence(),
    )


def receives_from_edge(
    edge_id: str, *, source: str, target: str, confidence: Confidence = Confidence.HIGH
) -> Edge:
    return Edge(
        id=edge_id,
        source=source,
        target=target,
        type=EdgeType.RECEIVES_FROM,
        status=EdgeStatus.DIRECT,
        security_attributes=SecurityAttributes(),
        confidence=confidence,
        evidence=one_evidence(),
    )


def trigger_node(node_id: str, *, name: str, path: str | None = None) -> Node:
    return Node(
        id=node_id,
        type=NodeType.TRIGGER,
        name=name,
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=one_evidence(path=path or f"{name}.json"),
    )


def dynamic_registration_diagnostic(
    *, path: str = "server.py", line_start: int | None = 42, message: str | None = None
) -> Diagnostic:
    return Diagnostic(
        code="INCOMPLETE-DYNAMIC-REGISTRATION",
        severity=DiagnosticSeverity.WARNING,
        message=(
            message
            or "A tool is registered at runtime via a dynamic dispatch table "
            "and cannot be resolved to a concrete node statically."
        ),
        confidence=Confidence.UNKNOWN,
        incomplete=True,
        evidence=one_evidence(path=path, line_start=line_start),
    )


def acbom(
    *,
    nodes: tuple[Node, ...] = (),
    edges: tuple[Edge, ...] = (),
    diagnostics: tuple[Diagnostic, ...] = (),
) -> ACBOMDocument:
    return ACBOMDocument(
        schema_version="1.0.0",
        generator=Generator(name="controlloop", version="0.1.0"),
        repository=Repository(commit="abc123", root_digest=PLACEHOLDER_DIGEST),
        nodes=nodes,
        edges=edges,
        diagnostics=diagnostics,
        digest=PLACEHOLDER_DIGEST,
    )


def manifest(**overrides: object) -> ManifestDocument:
    payload: dict[str, object] = {
        "schema_version": CURRENT_MANIFEST_SCHEMA_VERSION,
        "owner": "security-team",
    }
    payload.update(overrides)
    return ManifestDocument(**payload)  # type: ignore[arg-type]


def context(**overrides: object) -> RuleContext:
    payload: dict[str, object] = {
        "acbom": acbom(),
        "policy_version": "policy-v1",
        "diff": None,
        "manifest": None,
    }
    payload.update(overrides)
    return RuleContext(**payload)  # type: ignore[arg-type]
