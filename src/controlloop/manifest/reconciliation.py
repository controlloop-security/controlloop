"""Reconciles a `controlloop.yaml` manifest against already-discovered
ACBOM evidence.

`reconcile_manifest` returns only `tuple[Diagnostic, ...]`: it has no
code path that constructs a modified node/edge collection, so "manifest
declarations supplement discovered evidence and never delete a
discovered capability" is a structural property of this
function's return type, not a runtime check.

A contradiction is represented with the existing `Diagnostic` model
(`Confidence.HIGH`, `incomplete=False`, a non-"INCOMPLETE-" code
`MANIFEST-CONTRADICTS-DISCOVERY`) rather than a
`controlloop.findings.models.Finding`. The "unverified" case genuinely
is an unknown and reuses `incomplete_diagnostic` with a
newly registered `INCOMPLETE-UNVERIFIED-DECLARATION` code instead.

Reconciliation matches by `Node.name`, not by content-addressed ID:
node/edge IDs are stable hashes a human cannot write into a YAML file,
so the manifest necessarily references agents and resources by their
declared name, the only human-writable identifier discovery produces.
"""

from __future__ import annotations

from controlloop.acbom import (
    Confidence,
    Diagnostic,
    DiagnosticSeverity,
    Edge,
    EdgeType,
    Evidence,
    Node,
    NodeType,
    incomplete_diagnostic,
)
from controlloop.manifest.models import ManifestDocument

_CONTRADICTION_CODE = "MANIFEST-CONTRADICTS-DISCOVERY"
_UNVERIFIED_CODE = "INCOMPLETE-UNVERIFIED-DECLARATION"
_ADAPTER_NAME = "manifest"


def _nodes_by_name(
    nodes: tuple[Node, ...], node_type: NodeType | None = None
) -> dict[str, list[Node]]:
    index: dict[str, list[Node]] = {}
    for node in nodes:
        if node_type is None or node.type is node_type:
            index.setdefault(node.name, []).append(node)
    return index


def manifest_evidence(manifest_path: str) -> tuple[Evidence, ...]:
    return (Evidence(adapter=_ADAPTER_NAME, path=manifest_path),)


def _contradiction_diagnostic(
    evidence: tuple[Evidence, ...], reason: str
) -> Diagnostic:
    return Diagnostic(
        code=_CONTRADICTION_CODE,
        severity=DiagnosticSeverity.ERROR,
        message=f"Manifest declaration contradicts discovered evidence: {reason}.",
        confidence=Confidence.HIGH,
        incomplete=False,
        evidence=evidence,
    )


def unverified_diagnostic(evidence: tuple[Evidence, ...], reason: str) -> Diagnostic:
    return incomplete_diagnostic(
        code=_UNVERIFIED_CODE,
        message=(
            f"Manifest declaration could not be corroborated by discovery: {reason}."
        ),
        evidence=evidence,
    )


def reconcile_manifest(
    manifest: ManifestDocument,
    nodes: tuple[Node, ...],
    edges: tuple[Edge, ...],
    *,
    manifest_path: str = "controlloop.yaml",
) -> tuple[Diagnostic, ...]:
    """Compares `manifest` against `nodes`/`edges` already discovered
    elsewhere and returns diagnostics for every contradiction and
    unverifiable declaration found. Never modifies or returns
    `nodes`/`edges`."""

    evidence = manifest_evidence(manifest_path)
    agents_by_name = _nodes_by_name(nodes, NodeType.AGENT)
    resources_by_name = _nodes_by_name(nodes, NodeType.RESOURCE)
    all_by_name = _nodes_by_name(nodes)
    nodes_by_id = {node.id: node for node in nodes}
    diagnostics: list[Diagnostic] = []

    for prohibited in manifest.prohibited_capabilities:
        agent_ids = {node.id for node in agents_by_name.get(prohibited.agent, ())}
        target_ids = {node.id for node in all_by_name.get(prohibited.target, ())}
        if not agent_ids or not target_ids:
            continue
        violated = any(
            edge.type is prohibited.edge_type
            and edge.source in agent_ids
            and edge.target in target_ids
            for edge in edges
        )
        if violated:
            diagnostics.append(
                _contradiction_diagnostic(
                    evidence,
                    "a prohibited capability was found in discovered evidence",
                )
            )

    for allowed in manifest.allowed_delegation:
        agent_ids = {node.id for node in agents_by_name.get(allowed.agent, ())}
        if not agent_ids:
            continue
        allowed_target_names = set(allowed.targets)
        violated = any(
            edge.type is EdgeType.DELEGATES_TO
            and edge.source in agent_ids
            and edge.target in nodes_by_id
            and nodes_by_id[edge.target].name not in allowed_target_names
            for edge in edges
        )
        if violated:
            diagnostics.append(
                _contradiction_diagnostic(
                    evidence,
                    "a delegation target outside the declared allowed set was found",
                )
            )

    for declaration in manifest.data_classification:
        if declaration.resource not in resources_by_name:
            diagnostics.append(
                unverified_diagnostic(
                    evidence,
                    "a declared data classification names a resource "
                    "discovery did not find",
                )
            )

    return tuple(diagnostics)
