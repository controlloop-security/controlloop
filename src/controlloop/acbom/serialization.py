"""Deterministic canonicalization, serialization, and digesting for ACBOMs.

Canonical collection keys are:

- nodes and edges: canonical ``id``;
- evidence: adapter, path, line range, parser, schema ID, and document digest;
- diagnostics: code, severity, message, confidence, incomplete state, and evidence;
- standards identifiers: namespace and identifier;
- security classifications and permission scopes: Unicode code-point order.

JSON object keys, including keys in nested maps, are sorted during serialization.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping, Sequence

from pydantic_core import PydanticSerializationError

from controlloop.acbom.models import (
    ACBOMDocument,
    Diagnostic,
    Edge,
    Evidence,
    Node,
    SecurityAttributes,
    Sha256Digest,
)

type JsonValue = (
    bool | int | float | str | list[JsonValue] | dict[str, JsonValue] | None
)


class CanonicalizationError(ValueError):
    """A safe deterministic error raised for noncanonical input categories."""


class EdgeMergeConflictError(ValueError):
    """Two edges share a canonical ID but disagree on a field this merge
    does not resolve.

    Two edges can only share an ID by agreeing on relationship type,
    source, and target -- that is what the ID is derived from. A
    disagreement on type, status, confidence, or security attributes for
    what is otherwise the same relationship is a genuine adapter
    disagreement, not a duplicate; resolving it automatically would mean
    choosing a security-consequential tie-break policy this module has
    no standing to invent.
    """


def merge_duplicate_edges(edges: Sequence[Edge]) -> tuple[Edge, ...]:
    """Merge edges sharing a canonical ID, unioning their evidence.

    An edge appearing once passes through unchanged. Edges sharing an ID
    are merged into one edge whose evidence is the deduplicated union of
    every source edge's evidence, preserving both (or all) records.
    Raises :class:`EdgeMergeConflictError` if edges sharing an ID
    disagree on ``type``, ``status``, ``confidence``, or
    ``security_attributes``, rather than silently picking a winner.
    """

    groups: dict[str, list[Edge]] = {}
    for edge in edges:
        groups.setdefault(edge.id, []).append(edge)

    merged: list[Edge] = []
    for edge_id, group in groups.items():
        first = group[0]
        for other in group[1:]:
            if (
                other.type,
                other.status,
                other.confidence,
                other.security_attributes,
            ) != (
                first.type,
                first.status,
                first.confidence,
                first.security_attributes,
            ):
                raise EdgeMergeConflictError(
                    f"edges sharing id {edge_id} disagree on type, status, "
                    "confidence, or security attributes"
                )

        if len(group) == 1:
            merged.append(first)
            continue

        combined_evidence = tuple(
            dict.fromkeys(
                evidence for candidate in group for evidence in candidate.evidence
            )
        )
        merged.append(first.model_copy(update={"evidence": combined_evidence}))

    return tuple(merged)


class NodeMergeConflictError(ValueError):
    """Two nodes share a canonical ID but disagree on a field this merge
    does not resolve.

    Two nodes can only share an ID by agreeing on type and identity
    material -- that is what the ID is derived from. A disagreement on
    subtype, name, confidence, or security attributes for what is
    otherwise the same node is a genuine adapter disagreement, not a
    duplicate; resolving it automatically would mean choosing a
    security-consequential tie-break policy this module has no standing
    to invent (the same reasoning as :class:`EdgeMergeConflictError`).
    """


def merge_duplicate_nodes(nodes: Sequence[Node]) -> tuple[Node, ...]:
    """Merge nodes sharing a canonical ID, unioning their provenance data.

    A node appearing once passes through unchanged. Nodes sharing an ID
    are merged into one node whose ``evidence`` and
    ``standards_identifiers`` are each the deduplicated union of every
    source node's -- both are source-contributed reference data, not
    part of the asserted fact. Raises :class:`NodeMergeConflictError` if
    nodes sharing an ID disagree on ``type``, ``subtype``, ``name``,
    ``confidence``, ``security_attributes``, or ``attributes`` -- the
    fields that describe the asserted fact itself -- rather than
    silently picking a winner.
    """

    groups: dict[str, list[Node]] = {}
    for node in nodes:
        groups.setdefault(node.id, []).append(node)

    merged: list[Node] = []
    for node_id, group in groups.items():
        first = group[0]
        for other in group[1:]:
            if (
                other.type,
                other.subtype,
                other.name,
                other.confidence,
                other.security_attributes,
                other.attributes,
            ) != (
                first.type,
                first.subtype,
                first.name,
                first.confidence,
                first.security_attributes,
                first.attributes,
            ):
                raise NodeMergeConflictError(
                    f"nodes sharing id {node_id} disagree on type, subtype, "
                    "name, confidence, security attributes, or attributes"
                )

        if len(group) == 1:
            merged.append(first)
            continue

        combined_evidence = tuple(
            dict.fromkeys(
                evidence for candidate in group for evidence in candidate.evidence
            )
        )
        combined_standards_identifiers = tuple(
            dict.fromkeys(
                identifier
                for candidate in group
                for identifier in candidate.standards_identifiers
            )
        )
        merged.append(
            first.model_copy(
                update={
                    "evidence": combined_evidence,
                    "standards_identifiers": combined_standards_identifiers,
                }
            )
        )

    return tuple(merged)


def _evidence_key(evidence: Evidence) -> tuple[str, str, int, int, str, str, str]:
    return (
        evidence.adapter,
        evidence.path or "",
        evidence.line_start or 0,
        evidence.line_end or 0,
        evidence.parser or "",
        evidence.schema_id or "",
        evidence.document_digest or "",
    )


def _canonicalize_security_attributes(
    attributes: SecurityAttributes,
) -> SecurityAttributes:
    return attributes.model_copy(
        update={
            "data_classifications": tuple(sorted(attributes.data_classifications)),
            "permission_scopes": tuple(sorted(attributes.permission_scopes)),
        }
    )


def _canonicalize_node(node: Node) -> Node:
    return node.model_copy(
        update={
            "security_attributes": _canonicalize_security_attributes(
                node.security_attributes
            ),
            "evidence": tuple(sorted(node.evidence, key=_evidence_key)),
            "standards_identifiers": tuple(
                sorted(
                    node.standards_identifiers,
                    key=lambda identifier: (
                        identifier.namespace,
                        identifier.identifier,
                    ),
                )
            ),
        }
    )


def _canonicalize_edge(edge: Edge) -> Edge:
    return edge.model_copy(
        update={
            "security_attributes": _canonicalize_security_attributes(
                edge.security_attributes
            ),
            "evidence": tuple(sorted(edge.evidence, key=_evidence_key)),
        }
    )


def _diagnostic_key(
    diagnostic: Diagnostic,
) -> tuple[
    str, str, str, str, bool, tuple[tuple[str, str, int, int, str, str, str], ...]
]:
    return (
        diagnostic.code,
        diagnostic.severity.value,
        diagnostic.message,
        diagnostic.confidence.value,
        diagnostic.incomplete,
        tuple(_evidence_key(evidence) for evidence in diagnostic.evidence),
    )


def _canonicalize_diagnostic(diagnostic: Diagnostic) -> Diagnostic:
    return diagnostic.model_copy(
        update={"evidence": tuple(sorted(diagnostic.evidence, key=_evidence_key))}
    )


def canonicalize_document(document: ACBOMDocument) -> ACBOMDocument:
    """Return a new frozen document with every canonical collection sorted."""

    if not isinstance(document, ACBOMDocument):
        raise CanonicalizationError("unsupported canonical document category")

    try:
        nodes = tuple(
            sorted(
                (_canonicalize_node(node) for node in document.nodes),
                key=lambda node: node.id,
            )
        )
        edges = tuple(
            sorted(
                (_canonicalize_edge(edge) for edge in document.edges),
                key=lambda edge: edge.id,
            )
        )
        diagnostics = tuple(
            sorted(
                (
                    _canonicalize_diagnostic(diagnostic)
                    for diagnostic in document.diagnostics
                ),
                key=_diagnostic_key,
            )
        )
    except (AttributeError, TypeError, ValueError):
        raise CanonicalizationError(
            "canonical document contains an unsupported value category"
        ) from None

    return document.model_copy(
        update={
            "nodes": nodes,
            "edges": edges,
            "diagnostics": diagnostics,
        }
    )


def _normalize_json_value(value: object) -> JsonValue:
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalizationError("canonical JSON contains a nonfinite number")
        return value
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise CanonicalizationError("canonical JSON object keys must be strings")
        return {key: _normalize_json_value(value[key]) for key in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [_normalize_json_value(item) for item in value]
    raise CanonicalizationError("canonical JSON contains an unsupported value category")


def canonical_json_bytes(value: object) -> bytes:
    """Serialize supported JSON data to deterministic compact UTF-8 bytes."""

    normalized = _normalize_json_value(value)
    try:
        serialized = json.dumps(
            normalized,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError):
        raise CanonicalizationError(
            "canonical JSON serialization failed for a safe value category"
        ) from None
    return serialized.encode("utf-8")


def _document_data(
    document: ACBOMDocument,
    *,
    exclude_digest: bool,
) -> dict[str, object]:
    canonical = canonicalize_document(document)
    try:
        data = canonical.model_dump(
            mode="json",
            exclude={"digest"} if exclude_digest else None,
            warnings="error",
        )
    except (PydanticSerializationError, TypeError, ValueError):
        raise CanonicalizationError(
            "canonical document contains an unsupported value category"
        ) from None
    _omit_unset_additions(data)
    return data


#: Fields schema 1.2.0 added to `SecurityAttributes`.
_SECURITY_FLAGS_ADDED_IN_1_2_0 = (
    "bypass_mode",
    "wildcard",
    "pinned",
    "untrusted_input",
)


def _omit_unset_additions(data: dict[str, object]) -> None:
    """Drop the 1.2.0 additions from canonical data when they are unset.

    Every other field is dumped unconditionally, `null` included. These
    are not: a document produced before 1.2.0 never had them, and
    dumping them as `null` or `{}` would add bytes its digest was never
    computed over, so an unmodified 1.1.0 document would recompute to a
    different digest. The baseline format's `provenance` field
    (`controlloop.baseline.serialization`) set the precedent. A set flag
    or a non-empty `attributes` map is covered by the digest like any
    other field.
    """

    for collection in ("nodes", "edges"):
        items = data.get(collection)
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            attributes = item.get("security_attributes")
            if isinstance(attributes, dict):
                for flag in _SECURITY_FLAGS_ADDED_IN_1_2_0:
                    if attributes.get(flag) is None:
                        attributes.pop(flag, None)
            if collection == "nodes" and item.get("attributes") == {}:
                item.pop("attributes", None)


def serialize_document(document: ACBOMDocument) -> bytes:
    """Return canonical UTF-8 JSON bytes including the document digest."""

    return canonical_json_bytes(_document_data(document, exclude_digest=False))


def compute_digest(document: ACBOMDocument) -> Sha256Digest:
    """Return the SHA-256 digest of canonical bytes excluding ``digest``."""

    digest_input = canonical_json_bytes(_document_data(document, exclude_digest=True))
    return f"sha256:{hashlib.sha256(digest_input).hexdigest()}"


def with_digest(document: ACBOMDocument) -> ACBOMDocument:
    """Return a new canonical frozen document containing its computed digest."""

    canonical = canonicalize_document(document)
    return canonical.model_copy(update={"digest": compute_digest(canonical)})
