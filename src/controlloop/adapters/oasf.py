"""OASF ingestion at pinned versions.

**Disclosed low-confidence scope.** MCP, A2A, and OpenAPI are
well-established, thoroughly documented specifications whose wire
formats were verified with high confidence. OASF (the Open Agentic
Schema Framework) is a newer, still-evolving specification; this module
does not have verified, current confidence in its exact wire format the
way it does for the other three. Rather than fabricate field names for a
real spec under genuine uncertainty -- risking a silently wrong parse --
`SUPPORTED_OASF_VERSIONS` starts **empty**. The detection field name
below (`oasf_version`) is an unverified best-effort guess, not a
confirmed schema reference. The version-governance mechanism (one
declared registry of supported versions, and a diagnostic for any other
version) is implemented and tested fully; normalizing a supported record
is a real, tested code path that does not fire on any real input until a
verified version is added to the registry.
"""

from __future__ import annotations

import json

from controlloop.acbom import (
    Confidence,
    Diagnostic,
    Evidence,
    Node,
    NodeType,
    SecurityAttributes,
)
from controlloop.acbom.completeness import incomplete_diagnostic
from controlloop.acbom.identity import NodeIdentityMaterial, SemanticIdentity, node_id
from controlloop.adapters.framework import DetectionResult, DiscoveryResult, ScanContext
from controlloop.bounded_recursion import bounded_recursion

_NAME = "oasf"

#: Declared in one place. Empty until a real OASF version is verified
#: against an authoritative schema reference -- see the module
#: docstring. Populate deliberately, not by guessing.
SUPPORTED_OASF_VERSIONS: tuple[str, ...] = ()

_VERSION_FIELD = "oasf_version"
_KNOWN_TOP_LEVEL_FIELDS = frozenset({_VERSION_FIELD, "name", "description"})
_NAMESPACE = "oasf.record"


def _claimed_paths(context: ScanContext) -> tuple[str, ...]:
    found = set()
    for file in context.repository_files():
        if file.path.suffix.lower() == ".json":
            try:
                with bounded_recursion(margin=500):
                    document = json.loads(file.path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError):
                continue
            if isinstance(document, dict) and _VERSION_FIELD in document:
                found.add(file.relative)
    return tuple(sorted(found))


def _discover_file(
    context: ScanContext, relative_path: str
) -> tuple[tuple[Node, ...], tuple[Diagnostic, ...]]:
    absolute = context.root.path / relative_path
    evidence = (Evidence(adapter=_NAME, path=relative_path),)

    try:
        with bounded_recursion(margin=500):
            record = json.loads(absolute.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return (), (
            incomplete_diagnostic(
                code="INCOMPLETE-UNPARSED-REGION",
                message="OASF record could not be read as UTF-8 JSON.",
                evidence=evidence,
            ),
        )

    if not isinstance(record, dict):
        return (), (
            incomplete_diagnostic(
                code="INCOMPLETE-UNPARSED-REGION",
                message="OASF record's top level is not a JSON object.",
                evidence=evidence,
            ),
        )

    found_version = record.get(_VERSION_FIELD)
    if (
        not isinstance(found_version, str)
        or found_version not in SUPPORTED_OASF_VERSIONS
    ):
        supported = (
            ", ".join(SUPPORTED_OASF_VERSIONS) if SUPPORTED_OASF_VERSIONS else "(none)"
        )
        return (), (
            incomplete_diagnostic(
                code="INCOMPLETE-UNPARSED-REGION",
                message=(
                    f"OASF record version {found_version!r} is not supported "
                    f"(supported: {supported})."
                ),
                evidence=evidence,
            ),
        )

    name = record.get("name")
    if not isinstance(name, str) or not name:
        return (), (
            incomplete_diagnostic(
                code="INCOMPLETE-UNPARSED-REGION",
                message="OASF record has no usable name.",
                evidence=evidence,
            ),
        )

    try:
        identity_material = NodeIdentityMaterial(
            node_type=NodeType.AGENT,
            namespace=_NAMESPACE,
            semantic_identity=SemanticIdentity(
                source_path=relative_path, in_document_key="record"
            ),
        )
        node = Node(
            id=node_id(identity_material),
            type=NodeType.AGENT,
            subtype="oasf-record",
            name=name,
            security_attributes=SecurityAttributes(),
            confidence=Confidence.HIGH,
            evidence=evidence,
        )
    except ValueError:
        return (), (
            incomplete_diagnostic(
                code="INCOMPLETE-UNPARSED-REGION",
                message="OASF record could not be represented.",
                evidence=evidence,
            ),
        )

    diagnostics: list[Diagnostic] = []
    unrecognized = sorted(set(record) - _KNOWN_TOP_LEVEL_FIELDS)
    if unrecognized:
        diagnostics.append(
            incomplete_diagnostic(
                code="INCOMPLETE-UNPARSED-REGION",
                message=(
                    f"OASF record has {len(unrecognized)} unrecognized field(s), "
                    "preserved as unknown rather than discarded."
                ),
                evidence=evidence,
            )
        )

    return (node,), tuple(diagnostics)


class OasfAdapter:
    """Discovers OASF records at pinned, explicitly supported versions.
    See the module docstring: `SUPPORTED_OASF_VERSIONS` is empty until a
    real version is verified."""

    name = _NAME
    supported_versions: tuple[str, ...] = SUPPORTED_OASF_VERSIONS

    def detect(self, context: ScanContext) -> DetectionResult:
        return DetectionResult(adapter=self.name, claimed_paths=_claimed_paths(context))

    def discover(self, context: ScanContext) -> DiscoveryResult:
        nodes: list[Node] = []
        diagnostics: list[Diagnostic] = []
        for relative_path in _claimed_paths(context):
            file_nodes, file_diagnostics = _discover_file(context, relative_path)
            nodes.extend(file_nodes)
            diagnostics.extend(file_diagnostics)
        return DiscoveryResult(nodes=tuple(nodes), diagnostics=tuple(diagnostics))
