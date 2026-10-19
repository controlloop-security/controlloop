"""A2A Agent Card ingestion and delegation edges.

Discovers Agent-to-Agent protocol Agent Cards committed to a repository
at well-established locations, mapping the card to an agent node, its
declared skills to tool nodes connected by invokes edges, its declared
security schemes to identity nodes, and its declared delegation targets
to delegates-to edges. A card is never fetched live over the network --
only ones already committed as repository files are read; this
module never imports `socket`, and also runs inside `adapter_sandbox`,
which denies it regardless. Card-supplied text flows only into
`DisplayName`/`SafeText`-constrained canonical fields, which already
reject control characters and oversized text structurally.

Confidence note: unlike MCP and OpenAPI, whose shapes are known with very
high confidence, A2A's `skills`/`securitySchemes` shape is
well-documented and stable, but the exact set of currently-supported
`protocolVersion` strings is a best-effort range, not a verified
authoritative list.

Delegation field-name disclosure: the real A2A specification does not
currently standardize a field for one agent declaring delegation to
another -- delegation happens at runtime, not via a static card field.
Rather than guess at an unverified field name, this module reads an
explicitly controlloop-owned, `x-`-prefixed vendor extension key,
`x-controlloop-delegates-to` (a list of repository-relative paths or
URLs), the same convention `OpenApiAdapter` relies on across the
OpenAPI ecosystem for data a real spec doesn't yet standardize.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from controlloop.acbom import (
    Confidence,
    Diagnostic,
    Edge,
    EdgeStatus,
    EdgeType,
    Evidence,
    Node,
    NodeType,
    SecurityAttributes,
)
from controlloop.acbom.completeness import incomplete_diagnostic
from controlloop.acbom.identity import (
    EdgeIdentityMaterial,
    NodeIdentityMaterial,
    SemanticIdentity,
    edge_id,
    node_id,
)
from controlloop.adapters.framework import DetectionResult, DiscoveryResult, ScanContext
from controlloop.bounded_recursion import bounded_recursion
from controlloop.repository import ContainmentError, assert_within_root, walk_repository

_NAME = "a2a"
_SUPPORTED_VERSIONS: tuple[str, ...] = ("0.1", "0.2", "0.3")
_CARD_PATHS = (
    ".well-known/agent.json",
    ".well-known/agent-card.json",
    "agent-card.json",
)
_NAMESPACE = "a2a.agent-card"
_DELEGATION_FIELD = "x-controlloop-delegates-to"
_REMOTE_TARGET_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


def _claimed_paths(context: ScanContext) -> tuple[str, ...]:
    found = set()
    for item in walk_repository(context.root):
        if isinstance(item, Path):
            relative = item.relative_to(context.root.path).as_posix()
            if relative in _CARD_PATHS:
                found.add(relative)
    return tuple(sorted(found))


def _malformed_diagnostic(evidence: tuple[Evidence, ...], reason: str) -> Diagnostic:
    return incomplete_diagnostic(
        code="INCOMPLETE-UNPARSED-REGION",
        message=f"A2A Agent Card could not be parsed: {reason}.",
        evidence=evidence,
    )


def _unresolved_diagnostic(evidence: tuple[Evidence, ...], reason: str) -> Diagnostic:
    return incomplete_diagnostic(
        code="INCOMPLETE-UNRESOLVED-REFERENCE",
        message=f"A2A delegation target could not be resolved: {reason}.",
        evidence=evidence,
    )


def _build_node(
    relative_path: str,
    in_document_key: str,
    node_type: NodeType,
    subtype: str,
    name: str,
    evidence: tuple[Evidence, ...],
    *,
    confidence: Confidence = Confidence.HIGH,
    security_attributes: SecurityAttributes | None = None,
) -> Node:
    identity_material = NodeIdentityMaterial(
        node_type=node_type,
        namespace=_NAMESPACE,
        semantic_identity=SemanticIdentity(
            source_path=relative_path, in_document_key=in_document_key
        ),
    )
    return Node(
        id=node_id(identity_material),
        type=node_type,
        subtype=subtype,
        name=name,
        security_attributes=security_attributes or SecurityAttributes(),
        confidence=confidence,
        evidence=evidence,
    )


def _security_scheme_nodes(
    card: dict[str, Any], relative_path: str, evidence: tuple[Evidence, ...]
) -> list[Node]:
    schemes = card.get("securitySchemes")
    if not isinstance(schemes, dict):
        return []
    nodes: list[Node] = []
    for scheme_name, scheme_def in schemes.items():
        if not isinstance(scheme_name, str) or not isinstance(scheme_def, dict):
            continue
        try:
            nodes.append(
                _build_node(
                    relative_path,
                    f"securityScheme:{scheme_name}",
                    NodeType.IDENTITY,
                    "a2a-security-scheme",
                    scheme_name,
                    evidence,
                )
            )
        except ValueError:
            continue
    return nodes


def _skill_nodes_and_edges(
    card: dict[str, Any],
    relative_path: str,
    agent_node: Node,
    evidence: tuple[Evidence, ...],
) -> tuple[list[Node], list[Edge], list[Diagnostic]]:
    skills = card.get("skills")
    if not isinstance(skills, list):
        return [], [], []

    nodes: list[Node] = []
    edges: list[Edge] = []
    diagnostics: list[Diagnostic] = []
    for skill in skills:
        if not isinstance(skill, dict):
            diagnostics.append(
                _malformed_diagnostic(evidence, "a skill entry is not a JSON object")
            )
            continue
        skill_id = skill.get("id")
        skill_name = skill.get("name")
        display_name = (
            skill_name if isinstance(skill_name, str) and skill_name else skill_id
        )
        if (
            not isinstance(skill_id, str)
            or not skill_id
            or not isinstance(display_name, str)
        ):
            diagnostics.append(
                _malformed_diagnostic(
                    evidence, "a skill entry has no usable id or name"
                )
            )
            continue

        try:
            skill_node = _build_node(
                relative_path,
                f"skill:{skill_id}",
                NodeType.TOOL,
                "a2a-skill",
                display_name,
                evidence,
            )
            edge_material = EdgeIdentityMaterial(
                relationship_type=EdgeType.INVOKES,
                source_id=agent_node.id,
                target_id=skill_node.id,
                relationship_discriminator=f"a2a:skill:{skill_id}",
            )
            edge = Edge(
                id=edge_id(edge_material),
                source=agent_node.id,
                target=skill_node.id,
                type=EdgeType.INVOKES,
                status=EdgeStatus.DIRECT,
                security_attributes=SecurityAttributes(),
                confidence=Confidence.HIGH,
                evidence=evidence,
            )
        except ValueError:
            diagnostics.append(
                _malformed_diagnostic(
                    evidence, "a skill entry could not be represented"
                )
            )
            continue
        nodes.append(skill_node)
        edges.append(edge)

    return nodes, edges, diagnostics


def _external_delegation_target_node(
    target: str, evidence: tuple[Evidence, ...]
) -> Node | Diagnostic:
    """Builds the bounded external node for a URL delegation target
    identified by the URL itself and never fetched."""

    try:
        identity_material = NodeIdentityMaterial(
            node_type=NodeType.AGENT,
            namespace=_NAMESPACE,
            semantic_identity=SemanticIdentity(identifier=target),
        )
        return Node(
            id=node_id(identity_material),
            type=NodeType.AGENT,
            subtype="a2a-external-delegation-target",
            name=target,
            security_attributes=SecurityAttributes(external_communication=True),
            confidence=Confidence.LOW,
            evidence=evidence,
        )
    except ValueError:
        return _unresolved_diagnostic(
            evidence, f"external delegation target {target!r} could not be represented"
        )


def _local_delegation_target_node(
    context: ScanContext, target: str, evidence: tuple[Evidence, ...]
) -> Node | Diagnostic:
    """Resolves a repository-relative delegation target directly,
    reading that exact file rather than relying on `_claimed_paths`'
    three fixed locations, since a delegation target may live anywhere
    in the repository. Uses the same identity scheme `_discover_file`
    uses for a full card, so the two records merge
    (`merge_duplicate_nodes`) if the target is also independently
    discovered as its own top-level card."""

    try:
        absolute = assert_within_root(context.root, context.root.path / target)
    except ContainmentError:
        return _unresolved_diagnostic(
            evidence, f"delegation target {target!r} escapes the repository root"
        )

    try:
        with bounded_recursion(margin=500):
            payload = json.loads(absolute.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return _unresolved_diagnostic(
            evidence, f"delegation target {target!r} could not be read as UTF-8 JSON"
        )

    if not isinstance(payload, dict):
        return _unresolved_diagnostic(
            evidence, f"delegation target {target!r} did not parse into a document"
        )

    name = payload.get("name")
    if not isinstance(name, str) or not name:
        return _unresolved_diagnostic(
            evidence, f"delegation target {target!r} has no usable name"
        )

    try:
        return _build_node(
            target, "agent-card", NodeType.AGENT, "a2a-agent-card", name, evidence
        )
    except ValueError:
        return _unresolved_diagnostic(
            evidence, f"delegation target {target!r} could not be represented"
        )


def _delegation_nodes_and_edges(
    context: ScanContext,
    card: dict[str, Any],
    agent_node: Node,
    evidence: tuple[Evidence, ...],
) -> tuple[list[Node], list[Edge], list[Diagnostic]]:
    """Delegation edges for one card's declared targets. Resolution is
    direct and non-recursive -- one target lookup per declared entry,
    never following a resolved target's own delegation list -- so a
    mutual or self-delegation cycle cannot hang this adapter
    structurally; bounded transitive traversal through the resulting
    edges is `controlloop.capability.compute`'s job, not this
    adapter's."""

    targets = card.get(_DELEGATION_FIELD)
    if not isinstance(targets, list):
        return [], [], []

    nodes: list[Node] = []
    edges: list[Edge] = []
    diagnostics: list[Diagnostic] = []
    for target in targets:
        if not isinstance(target, str) or not target:
            diagnostics.append(
                _unresolved_diagnostic(
                    evidence, "a delegation target is not a usable string"
                )
            )
            continue

        resolved = (
            _external_delegation_target_node(target, evidence)
            if _REMOTE_TARGET_PATTERN.match(target)
            else _local_delegation_target_node(context, target, evidence)
        )
        if isinstance(resolved, Diagnostic):
            diagnostics.append(resolved)
            continue
        target_node = resolved

        try:
            edge_material = EdgeIdentityMaterial(
                relationship_type=EdgeType.DELEGATES_TO,
                source_id=agent_node.id,
                target_id=target_node.id,
                relationship_discriminator=f"a2a:delegates-to:{target}",
            )
            edge = Edge(
                id=edge_id(edge_material),
                source=agent_node.id,
                target=target_node.id,
                type=EdgeType.DELEGATES_TO,
                status=EdgeStatus.DIRECT,
                security_attributes=SecurityAttributes(),
                confidence=Confidence.HIGH,
                evidence=evidence,
            )
        except ValueError:
            diagnostics.append(
                _unresolved_diagnostic(
                    evidence, f"delegation edge to {target!r} could not be represented"
                )
            )
            continue

        nodes.append(target_node)
        edges.append(edge)

    return nodes, edges, diagnostics


def _discover_file(
    context: ScanContext, relative_path: str
) -> tuple[tuple[Node, ...], tuple[Edge, ...], tuple[Diagnostic, ...]]:
    absolute = context.root.path / relative_path
    evidence = (Evidence(adapter=_NAME, path=relative_path),)

    try:
        with bounded_recursion(margin=500):
            card = json.loads(absolute.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return (
            (),
            (),
            (
                _malformed_diagnostic(
                    evidence, "the file could not be read as UTF-8 JSON"
                ),
            ),
        )

    if not isinstance(card, dict):
        return (
            (),
            (),
            (_malformed_diagnostic(evidence, "the top level is not a JSON object"),),
        )

    version = card.get("protocolVersion", card.get("version"))
    if (
        isinstance(version, str)
        and version
        and not any(version.startswith(supported) for supported in _SUPPORTED_VERSIONS)
    ):
        return (
            (),
            (),
            (
                incomplete_diagnostic(
                    code="INCOMPLETE-UNPARSED-REGION",
                    message=(
                        "A2A Agent Card declares unsupported protocol "
                        f"version {version!r}."
                    ),
                    evidence=evidence,
                ),
            ),
        )

    name = card.get("name")
    if not isinstance(name, str) or not name:
        return (), (), (_malformed_diagnostic(evidence, "the card has no usable name"),)

    try:
        agent_node = _build_node(
            relative_path,
            "agent-card",
            NodeType.AGENT,
            "a2a-agent-card",
            name,
            evidence,
        )
    except ValueError:
        return (
            (),
            (),
            (_malformed_diagnostic(evidence, "the card could not be represented"),),
        )

    identity_nodes = _security_scheme_nodes(card, relative_path, evidence)
    skill_nodes, skill_edges, diagnostics = _skill_nodes_and_edges(
        card, relative_path, agent_node, evidence
    )
    delegation_nodes, delegation_edges, delegation_diagnostics = (
        _delegation_nodes_and_edges(context, card, agent_node, evidence)
    )

    return (
        (agent_node, *identity_nodes, *skill_nodes, *delegation_nodes),
        (*skill_edges, *delegation_edges),
        (*diagnostics, *delegation_diagnostics),
    )


class A2aAgentCardAdapter:
    """Discovers A2A Agent Cards committed to a repository and maps
    skills and security schemes to canonical nodes and edges."""

    name = _NAME
    supported_versions: tuple[str, ...] = _SUPPORTED_VERSIONS

    def detect(self, context: ScanContext) -> DetectionResult:
        return DetectionResult(adapter=self.name, claimed_paths=_claimed_paths(context))

    def discover(self, context: ScanContext) -> DiscoveryResult:
        nodes: list[Node] = []
        edges: list[Edge] = []
        diagnostics: list[Diagnostic] = []
        for relative_path in _claimed_paths(context):
            file_nodes, file_edges, file_diagnostics = _discover_file(
                context, relative_path
            )
            nodes.extend(file_nodes)
            edges.extend(file_edges)
            diagnostics.extend(file_diagnostics)
        return DiscoveryResult(
            nodes=tuple(nodes), edges=tuple(edges), diagnostics=tuple(diagnostics)
        )
