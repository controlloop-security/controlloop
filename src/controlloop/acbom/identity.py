"""Stable, privacy-preserving identifiers for canonical ACBOM components."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Annotated, Any, ClassVar, Self

from pydantic import BaseModel, ConfigDict, StringConstraints, model_validator

from controlloop.acbom.models import (
    EdgeId,
    EdgeType,
    NodeId,
    NodeType,
    RelativePath,
    SafeIdentifier,
)

IDENTITY_VERSION = 1
_EDGE_NAMESPACE = "controlloop.edge"

IdentityString = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=512,
        pattern=r"^[^\x00-\x1f\x7f]*$",
    ),
]

_PROHIBITED_FIELD_CATEGORIES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("private key", ("privatekey",)),
    (
        "environment value",
        (
            "environmentvalue",
            "environmentvariablevalue",
            "envvalue",
            "envvarvalue",
        ),
    ),
    ("source content", ("sourcecontent", "sourcecode", "rawsource")),
    ("credential", ("credential",)),
    ("password", ("password", "passwd")),
    ("secret", ("secret",)),
    ("token", ("token",)),
)
_EXCLUDED_FIELD_CATEGORIES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("presentation", ("display", "label", "description")),
    ("evidence", ("evidence", "confidence", "linenumber", "line")),
    ("timestamp", ("timestamp", "createdat", "updatedat")),
    ("version", ("schemaversion", "generatorversion")),
    ("security attribute", ("securityattribute",)),
)


def _normalized_field_name(field_name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", field_name.casefold())


def _field_category(field_name: object) -> tuple[str, str] | None:
    if not isinstance(field_name, str):
        return ("unsupported", "unsupported")

    normalized = _normalized_field_name(field_name)
    for category, markers in _PROHIBITED_FIELD_CATEGORIES:
        if any(marker in normalized for marker in markers):
            return ("prohibited", category)
    for category, markers in _EXCLUDED_FIELD_CATEGORIES:
        if any(marker in normalized for marker in markers):
            return ("excluded", category)
    return None


class _IdentityModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        strict=True,
    )

    _allowed_fields: ClassVar[frozenset[str]]

    @model_validator(mode="before")
    @classmethod
    def reject_unapproved_fields(cls, value: Any) -> Any:
        if not isinstance(value, Mapping):
            return value

        for field_name in value:
            if field_name in cls._allowed_fields:
                continue
            category = _field_category(field_name)
            if category is None:
                raise ValueError("unsupported identity field category")
            disposition, safe_category = category
            raise ValueError(f"{disposition} identity field category: {safe_category}")
        return value


class SemanticIdentity(_IdentityModel):
    """Allowlisted semantic identity for the canonical ACBOM contract."""

    _allowed_fields = frozenset({"identifier", "source_path", "in_document_key"})

    identifier: IdentityString | None = None
    source_path: RelativePath | None = None
    in_document_key: IdentityString | None = None

    @model_validator(mode="after")
    def validate_identity_shape(self) -> Self:
        uses_identifier = self.identifier is not None
        uses_adapter_fallback = (
            self.source_path is not None and self.in_document_key is not None
        )
        if uses_identifier == uses_adapter_fallback:
            raise ValueError(
                "semantic identity requires exactly one approved identity category"
            )
        if (self.source_path is None) != (self.in_document_key is None):
            raise ValueError(
                "adapter fallback identity requires path and in-document key"
            )
        return self


class NodeIdentityMaterial(_IdentityModel):
    """Typed node identity material accepted by the hashing boundary."""

    _allowed_fields = frozenset({"node_type", "namespace", "semantic_identity"})

    node_type: NodeType
    namespace: SafeIdentifier
    semantic_identity: SemanticIdentity


class EdgeIdentityMaterial(_IdentityModel):
    """Typed edge identity material accepted by the hashing boundary."""

    _allowed_fields = frozenset(
        {
            "relationship_type",
            "source_id",
            "target_id",
            "relationship_discriminator",
        }
    )

    relationship_type: EdgeType
    source_id: NodeId
    target_id: NodeId
    relationship_discriminator: IdentityString


def _canonical_identity_bytes(
    *,
    node_type: str,
    namespace: str,
    semantic_identity: dict[str, object],
) -> bytes:
    payload = {
        "identity_version": IDENTITY_VERSION,
        "namespace": namespace,
        "node_type": node_type,
        "semantic_identity": semantic_identity,
    }
    return json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def node_id(material: NodeIdentityMaterial) -> NodeId:
    """Return the stable canonical ID for validated node identity material."""

    canonical_bytes = _canonical_identity_bytes(
        node_type=material.node_type.value,
        namespace=material.namespace,
        semantic_identity=material.semantic_identity.model_dump(
            mode="json",
            exclude_none=True,
        ),
    )
    digest = hashlib.sha256(canonical_bytes).hexdigest()
    return f"clp:{material.node_type.value}:sha256:{digest}"


def edge_id(material: EdgeIdentityMaterial) -> EdgeId:
    """Return the stable canonical ID for validated edge identity material."""

    canonical_bytes = _canonical_identity_bytes(
        node_type="edge",
        namespace=_EDGE_NAMESPACE,
        semantic_identity={
            "relationship_discriminator": material.relationship_discriminator,
            "relationship_type": material.relationship_type.value,
            "source_id": material.source_id,
            "target_id": material.target_id,
        },
    )
    digest = hashlib.sha256(canonical_bytes).hexdigest()
    return f"clp:edge:sha256:{digest}"


AGENT_HOST_NAMESPACE = "agent-host"
"""Identity namespace for agent host nodes."""


def host_node_id(host: str) -> NodeId:
    """Return the stable ID of the agent host node for `host`.

    A host such as `claude-code` is one node per repository whatever
    files configure it, so its identity is the host key alone: no path,
    no line, no setting.
    """

    return node_id(
        NodeIdentityMaterial(
            node_type=NodeType.AGENT,
            namespace=AGENT_HOST_NAMESPACE,
            semantic_identity=SemanticIdentity(identifier=host),
        )
    )


def authority_component_node_id(
    node_type: NodeType,
    *,
    namespace: str,
    declaring_path: str,
    key_path: str,
) -> NodeId:
    """Return the stable ID of an agent authority component.

    Identity is the repository-relative file that declares the component
    and the structural key path to it inside that file, for example
    `hooks.SessionStart[0].hooks[0]`. Reformatting the file, reordering
    object keys, or moving the declaration to other lines leaves the ID
    unchanged; changing the component's command, pattern, or flags does
    not change it either, so a diff reports the component as changed
    rather than as one removed and one added. No line number or absolute
    path is accepted: `declaring_path` must be a sanitized relative path.
    """

    return node_id(
        NodeIdentityMaterial(
            node_type=node_type,
            namespace=namespace,
            semantic_identity=SemanticIdentity(
                source_path=declaring_path,
                in_document_key=key_path,
            ),
        )
    )
