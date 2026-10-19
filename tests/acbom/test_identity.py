"""Dedicated tests for controlloop.acbom.identity.

`identity.py`'s algorithm is a compatibility surface and must not change
here; these tests prove the existing, already-generic-across-types
algorithm, not a new one.
"""

from __future__ import annotations

import re

import pytest
from pydantic import ValidationError

from controlloop.acbom import (
    EdgeIdentityMaterial,
    EdgeType,
    NodeIdentityMaterial,
    NodeType,
    SemanticIdentity,
    edge_id,
    node_id,
)

_NODE_ID_PATTERN = re.compile(r"^clp:(?P<type>[a-z-]+):sha256:[0-9a-f]{64}$")
_EDGE_ID_PATTERN = re.compile(r"^clp:edge:sha256:[0-9a-f]{64}$")

_AGENT_ID = f"clp:agent:sha256:{'a' * 64}"
_TOOL_ID = f"clp:tool:sha256:{'b' * 64}"

_PROHIBITED_FIELD_SAMPLES = (
    ("credential", "credential"),
    ("password", "password"),
    ("secret", "secret"),
    ("token", "token"),
    ("private_key", "private key"),
    ("environment_value", "environment value"),
    ("source_content", "source content"),
)

_NON_IDENTITY_NODE_FIELDS = (
    ("name", "Renamed after an unrelated change"),
    ("confidence", "high"),
    ("evidence", ({"adapter": "fixture", "path": "src/example.py"},)),
    ("security_attributes", {"trusted": True}),
    ("standards_identifiers", ()),
)

_NON_IDENTITY_EDGE_FIELDS = (
    ("status", "direct"),
    ("confidence", "high"),
    ("evidence", ({"adapter": "fixture", "path": "src/example.py"},)),
    ("security_attributes", {"trusted": True}),
)


def _identifier_material(
    node_type: NodeType,
    identifier: str = "example",
    namespace: str = "controlloop.test",
) -> NodeIdentityMaterial:
    return NodeIdentityMaterial(
        node_type=node_type,
        namespace=namespace,
        semantic_identity=SemanticIdentity(identifier=identifier),
    )


@pytest.mark.parametrize("node_type", tuple(NodeType))
def test_node_id_is_well_formed_for_every_type(node_type: NodeType) -> None:
    identifier_id = node_id(_identifier_material(node_type))
    match = _NODE_ID_PATTERN.fullmatch(identifier_id)
    assert match is not None
    assert match.group("type") == node_type.value

    fallback_material = NodeIdentityMaterial(
        node_type=node_type,
        namespace="controlloop.test",
        semantic_identity=SemanticIdentity(
            source_path="src/example.py", in_document_key="tool.example"
        ),
    )
    fallback_id = node_id(fallback_material)
    assert _NODE_ID_PATTERN.fullmatch(fallback_id) is not None
    assert fallback_id != identifier_id


@pytest.mark.parametrize("node_type", tuple(NodeType))
def test_node_id_is_deterministic_for_every_type(node_type: NodeType) -> None:
    first = node_id(_identifier_material(node_type))
    second = node_id(_identifier_material(node_type))

    assert first == second


@pytest.mark.parametrize("node_type", tuple(NodeType))
def test_node_id_changes_when_identity_material_changes(node_type: NodeType) -> None:
    baseline = node_id(_identifier_material(node_type))

    assert node_id(_identifier_material(node_type, identifier="different")) != baseline
    assert (
        node_id(_identifier_material(node_type, namespace="controlloop.other"))
        != baseline
    )

    other_type = NodeType.TOOL if node_type is not NodeType.TOOL else NodeType.RESOURCE
    assert node_id(_identifier_material(other_type)) != baseline


@pytest.mark.parametrize("node_type", tuple(NodeType))
@pytest.mark.parametrize(("field_name", "value"), _NON_IDENTITY_NODE_FIELDS)
def test_node_identity_material_excludes_non_identity_node_fields(
    node_type: NodeType, field_name: str, value: object
) -> None:
    """Identity cannot be perturbed by fields that change for
    unrelated reasons (a rename, a re-evaluated confidence, new evidence,
    an updated security attribute) -- the structural boundary that makes
    identity survive an unrelated repository change."""
    with pytest.raises(ValidationError):
        NodeIdentityMaterial(
            node_type=node_type,
            namespace="controlloop.test",
            semantic_identity=SemanticIdentity(identifier="example"),
            **{field_name: value},
        )


@pytest.mark.parametrize("edge_type", tuple(EdgeType))
def test_edge_id_is_well_formed_and_deterministic(edge_type: EdgeType) -> None:
    material = EdgeIdentityMaterial(
        relationship_type=edge_type,
        source_id=_AGENT_ID,
        target_id=_TOOL_ID,
        relationship_discriminator="default",
    )

    first = edge_id(material)
    second = edge_id(material)

    assert _EDGE_ID_PATTERN.fullmatch(first) is not None
    assert first == second


@pytest.mark.parametrize("edge_type", tuple(EdgeType))
def test_edge_id_changes_when_identity_material_changes(edge_type: EdgeType) -> None:
    baseline = edge_id(
        EdgeIdentityMaterial(
            relationship_type=edge_type,
            source_id=_AGENT_ID,
            target_id=_TOOL_ID,
            relationship_discriminator="default",
        )
    )

    changed_source = edge_id(
        EdgeIdentityMaterial(
            relationship_type=edge_type,
            source_id=_TOOL_ID,
            target_id=_TOOL_ID,
            relationship_discriminator="default",
        )
    )
    changed_discriminator = edge_id(
        EdgeIdentityMaterial(
            relationship_type=edge_type,
            source_id=_AGENT_ID,
            target_id=_TOOL_ID,
            relationship_discriminator="other",
        )
    )

    assert changed_source != baseline
    assert changed_discriminator != baseline


def test_edge_id_does_not_depend_on_discovery_order() -> None:
    """Edge identity depends only on endpoints and type,
    never on when or where among other edges it was discovered."""
    material = EdgeIdentityMaterial(
        relationship_type=EdgeType.INVOKES,
        source_id=_AGENT_ID,
        target_id=_TOOL_ID,
        relationship_discriminator="default",
    )

    discovered_first = edge_id(material)

    for other_type in EdgeType:
        edge_id(
            EdgeIdentityMaterial(
                relationship_type=other_type,
                source_id=_TOOL_ID,
                target_id=_AGENT_ID,
                relationship_discriminator="unrelated",
            )
        )

    discovered_last = edge_id(material)

    assert discovered_first == discovered_last


@pytest.mark.parametrize(("field_name", "value"), _NON_IDENTITY_EDGE_FIELDS)
def test_edge_identity_material_excludes_non_identity_edge_fields(
    field_name: str, value: object
) -> None:
    """Edge counterpart: status/confidence/evidence/security
    attributes all change for unrelated reasons and cannot enter identity
    material."""
    with pytest.raises(ValidationError):
        EdgeIdentityMaterial(
            relationship_type=EdgeType.INVOKES,
            source_id=_AGENT_ID,
            target_id=_TOOL_ID,
            relationship_discriminator="default",
            **{field_name: value},
        )


@pytest.mark.parametrize(("field_name", "expected_category"), _PROHIBITED_FIELD_SAMPLES)
def test_prohibited_semantic_identity_fields_never_leak_the_planted_value(
    field_name: str, expected_category: str
) -> None:
    """A fixture containing a credential-shaped value is rejected,
    and the raw value is never present in the resulting error."""
    planted_secret = "synthetic-secret-shaped-value-abc123"

    with pytest.raises(ValidationError) as excinfo:
        SemanticIdentity(identifier="example", **{field_name: planted_secret})

    message = str(excinfo.value)
    assert f"prohibited identity field category: {expected_category}" in message
    assert planted_secret not in message


def test_prohibited_field_rejected_at_the_node_identity_material_boundary_too() -> None:
    """The same rejection applies one level up, not only on SemanticIdentity."""
    planted_secret = "synthetic-secret-shaped-value-abc123"

    with pytest.raises(ValidationError) as excinfo:
        NodeIdentityMaterial(
            node_type=NodeType.AGENT,
            namespace="controlloop.test",
            semantic_identity=SemanticIdentity(identifier="example"),
            **{"credential": planted_secret},
        )

    message = str(excinfo.value)
    assert "prohibited identity field category: credential" in message
    assert planted_secret not in message


def test_excluded_but_not_secret_field_is_rejected_with_its_own_category() -> None:
    with pytest.raises(
        ValidationError, match="excluded identity field category: presentation"
    ):
        SemanticIdentity(identifier="example", **{"display": "Human label"})


def test_unsupported_field_is_rejected_without_a_named_category() -> None:
    with pytest.raises(ValidationError, match="unsupported identity field category"):
        SemanticIdentity(
            identifier="example", **{"totally_unrecognized_field": "value"}
        )


def test_semantic_identity_requires_exactly_one_category() -> None:
    with pytest.raises(ValidationError, match="exactly one approved identity category"):
        SemanticIdentity()
    with pytest.raises(ValidationError, match="exactly one approved identity category"):
        SemanticIdentity(identifier="x", source_path="a.py", in_document_key="k")
    with pytest.raises(ValidationError, match="exactly one approved identity category"):
        SemanticIdentity(source_path="a.py")


def test_semantic_identity_rejects_partial_adapter_fallback_with_identifier() -> None:
    with pytest.raises(
        ValidationError,
        match="adapter fallback identity requires path and in-document key",
    ):
        SemanticIdentity(identifier="x", source_path="a.py")


def test_non_string_field_name_is_rejected_as_unsupported() -> None:
    with pytest.raises(ValidationError, match="unsupported identity field category"):
        SemanticIdentity.model_validate({"identifier": "x", 123: "y"})


def test_revalidating_an_existing_instance_still_succeeds() -> None:
    original = SemanticIdentity(identifier="x")

    revalidated = SemanticIdentity.model_validate(original)

    assert revalidated == original
