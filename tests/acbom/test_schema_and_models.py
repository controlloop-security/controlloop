"""Contract tests shared by ACBOM schema 1.0.0 and canonical models."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import cast

import pytest
from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
from jsonschema.exceptions import (  # type: ignore[import-untyped]
    ValidationError as JsonSchemaValidationError,
)
from pydantic import ValidationError as PydanticValidationError

from controlloop.acbom import CURRENT_SCHEMA_VERSION, ACBOMDocument, EdgeType, NodeType

type JsonObject = dict[str, object]

_CLI_ROOT = Path(__file__).resolve().parents[2]
_SCHEMA_PATH = _CLI_ROOT / "src/controlloop/schemas/acbom/1.2.0/acbom.schema.json"
_FIXTURE_PATH = _CLI_ROOT / "tests/fixtures/acbom/minimal-input.json"


def _load_object(path: Path) -> JsonObject:
    return cast(JsonObject, json.loads(path.read_text(encoding="utf-8")))


_SCHEMA = _load_object(_SCHEMA_PATH)
_VALIDATOR = Draft202012Validator(_SCHEMA)


def _fixture() -> JsonObject:
    return deepcopy(_load_object(_FIXTURE_PATH))


def _objects(document: JsonObject, key: str) -> list[JsonObject]:
    return cast(list[JsonObject], document[key])


def _object(document: JsonObject, key: str) -> JsonObject:
    return cast(JsonObject, document[key])


def _validate_model(document: JsonObject) -> ACBOMDocument:
    return ACBOMDocument.model_validate_json(json.dumps(document))


def _assert_both_reject(document: JsonObject) -> None:
    with pytest.raises(JsonSchemaValidationError):
        _VALIDATOR.validate(document)
    with pytest.raises(PydanticValidationError):
        _validate_model(document)


def _assert_model_only_rejects(document: JsonObject, message: str) -> None:
    """Assert graph semantics that draft 2020-12 cannot express structurally."""
    _VALIDATOR.validate(document)
    with pytest.raises(PydanticValidationError, match=message):
        _validate_model(document)


def test_published_schema_is_valid_draft_2020_12() -> None:
    Draft202012Validator.check_schema(_SCHEMA)


def test_minimal_fixture_validates_through_schema_and_models() -> None:
    document = _fixture()

    _VALIDATOR.validate(document)
    model = _validate_model(document)

    assert model.schema_version == CURRENT_SCHEMA_VERSION
    assert len(model.nodes) == 2
    assert len(model.edges) == 1


def test_schema_and_model_declare_the_same_node_types() -> None:
    definitions = _object(_SCHEMA, "$defs")
    node_type = _object(definitions, "nodeType")

    assert set(cast(list[str], node_type["enum"])) == {
        member.value for member in NodeType
    }


@pytest.mark.parametrize("node_type", tuple(NodeType))
def test_every_node_type_validates(node_type: NodeType) -> None:
    document = _fixture()
    node = _objects(document, "nodes")[0]
    node["id"] = f"clp:{node_type.value}:sha256:{'a' * 64}"
    node["type"] = node_type.value
    document["nodes"] = [node]
    document["edges"] = []

    _VALIDATOR.validate(document)
    assert _validate_model(document).nodes[0].type is node_type


def test_schema_and_model_declare_the_same_edge_types() -> None:
    definitions = _object(_SCHEMA, "$defs")
    edge_type = _object(definitions, "edgeType")

    assert set(cast(list[str], edge_type["enum"])) == {
        member.value for member in EdgeType
    }


@pytest.mark.parametrize("edge_type", tuple(EdgeType))
def test_every_edge_type_validates(edge_type: EdgeType) -> None:
    document = _fixture()
    _objects(document, "edges")[0]["type"] = edge_type.value

    _VALIDATOR.validate(document)
    assert _validate_model(document).edges[0].type is edge_type


@pytest.mark.parametrize("nested", [False, True], ids=["envelope", "node"])
def test_unknown_fields_are_rejected(nested: bool) -> None:
    document = _fixture()
    target = _objects(document, "nodes")[0] if nested else document
    target["unexpected_field"] = True

    _assert_both_reject(document)


@pytest.mark.parametrize(
    ("category", "value"),
    [
        ("node", f"clp:agent:sha256:{'A' * 64}"),
        ("edge", "clp:edge:sha256:not-a-digest"),
        ("root_digest", f"sha256:{'D' * 64}"),
        ("document_digest", "sha256:short"),
    ],
)
def test_invalid_ids_and_digests_are_rejected(category: str, value: str) -> None:
    document = _fixture()
    if category == "node":
        _objects(document, "nodes")[0]["id"] = value
    elif category == "edge":
        _objects(document, "edges")[0]["id"] = value
    elif category == "root_digest":
        _object(document, "repository")["root_digest"] = value
    else:
        document["digest"] = value

    _assert_both_reject(document)


def test_duplicate_node_ids_are_rejected_by_graph_model() -> None:
    document = _fixture()
    duplicate = deepcopy(_objects(document, "nodes")[0])
    duplicate["name"] = "Duplicate logical node"
    _objects(document, "nodes").append(duplicate)

    _assert_model_only_rejects(document, "node IDs must be unique")


def test_duplicate_edge_ids_are_rejected_by_graph_model() -> None:
    document = _fixture()
    duplicate = deepcopy(_objects(document, "edges")[0])
    duplicate["type"] = EdgeType.READS.value
    _objects(document, "edges").append(duplicate)

    _assert_model_only_rejects(document, "edge IDs must be unique")


def test_dangling_edges_are_rejected_by_graph_model() -> None:
    document = _fixture()
    _objects(document, "edges")[0]["target"] = f"clp:resource:sha256:{'f' * 64}"

    _assert_model_only_rejects(
        document,
        "edge endpoints must reference document node IDs",
    )


def test_reversed_line_ranges_are_rejected_by_evidence_model() -> None:
    document = _fixture()
    evidence = _objects(_objects(document, "nodes")[0], "evidence")[0]
    evidence["line_start"] = 20
    evidence["line_end"] = 10

    _assert_model_only_rejects(
        document,
        "evidence line end must not precede line start",
    )


@pytest.mark.parametrize(
    "evidence",
    [
        {"adapter": "fixture"},
        {
            "adapter": "fixture",
            "document_digest": f"sha256:{'d' * 64}",
            "line_start": 1,
        },
        {"adapter": "fixture", "path": "input.json", "line_end": 2},
    ],
    ids=["no-location", "line-without-path", "end-without-start"],
)
def test_incomplete_evidence_locations_are_rejected(evidence: JsonObject) -> None:
    document = _fixture()
    _objects(document, "nodes")[0]["evidence"] = [evidence]

    _assert_both_reject(document)


def test_unsanitized_relative_paths_are_rejected() -> None:
    document = _fixture()
    evidence = _objects(_objects(document, "nodes")[0], "evidence")[0]
    evidence["path"] = "../outside.json"

    _assert_both_reject(document)


@pytest.mark.parametrize(
    ("category", "length"),
    [("node_name", 257), ("evidence_path", 513), ("diagnostic_message", 1025)],
)
def test_excessive_strings_are_rejected(category: str, length: int) -> None:
    document = _fixture()
    if category == "node_name":
        _objects(document, "nodes")[0]["name"] = "n" * length
    elif category == "evidence_path":
        evidence = _objects(_objects(document, "nodes")[0], "evidence")[0]
        evidence["path"] = "p" * length
    else:
        document["diagnostics"] = [
            {
                "code": "INPUT-LIMIT",
                "severity": "warning",
                "message": "m" * length,
                "confidence": "high",
                "incomplete": True,
                "evidence": [{"adapter": "fixture", "path": "input.json"}],
            }
        ]

    _assert_both_reject(document)


@pytest.mark.parametrize(
    ("category", "limit"),
    [("evidence", 32), ("data_classifications", 64), ("permission_scopes", 128)],
)
def test_excessive_collections_are_rejected(category: str, limit: int) -> None:
    document = _fixture()
    node = _objects(document, "nodes")[0]
    if category == "evidence":
        node["evidence"] = [
            {"adapter": "fixture", "path": f"evidence/{index}.json"}
            for index in range(limit + 1)
        ]
    else:
        security_attributes = _object(node, "security_attributes")
        security_attributes[category] = [
            f"classification-{index}" for index in range(limit + 1)
        ]

    _assert_both_reject(document)


@pytest.mark.parametrize(
    "category",
    ["data_classifications", "permission_scopes"],
)
def test_duplicate_security_attribute_collections_are_rejected(
    category: str,
) -> None:
    document = _fixture()
    security_attributes = _object(
        _objects(document, "nodes")[0],
        "security_attributes",
    )
    security_attributes[category] = ["restricted", "restricted"]

    _assert_both_reject(document)


@pytest.mark.parametrize(
    "field_name",
    [
        "content",
        "raw_source",
        "source_content",
        "prompt",
        "credential",
        "environment_value",
    ],
)
def test_prohibited_raw_content_field_names_are_rejected(field_name: str) -> None:
    document = _fixture()
    evidence = _objects(_objects(document, "nodes")[0], "evidence")[0]
    evidence[field_name] = "synthetic-prohibited-value"

    _assert_both_reject(document)


def test_evidence_content_field_never_leaks_a_planted_secret() -> None:
    """Tied to a canary-style planted secret value, matching the pattern
    already used in test_identity.py and test_redaction.py: a field shaped
    like it might carry file content is rejected outright, and the planted
    value never survives into the resulting error."""
    planted_secret = "synthetic-secret-shaped-value-abc123"
    document = _fixture()
    evidence = _objects(_objects(document, "nodes")[0], "evidence")[0]
    evidence["content"] = planted_secret

    with pytest.raises(PydanticValidationError) as excinfo:
        _validate_model(document)

    assert planted_secret not in str(excinfo.value)


def test_evidence_requires_adapter_confidence_and_location() -> None:
    """Every node/edge carries an adapter identifier, a confidence, and
    either a sanitized source location or a document digest -- confidence
    lives on the node/edge itself, not on evidence."""
    document = _fixture()
    node = _objects(document, "nodes")[0]
    evidence = _objects(node, "evidence")[0]

    missing_adapter = deepcopy(document)
    del _objects(_objects(missing_adapter, "nodes")[0], "evidence")[0]["adapter"]
    _assert_both_reject(missing_adapter)

    missing_confidence = deepcopy(document)
    del _objects(missing_confidence, "nodes")[0]["confidence"]
    _assert_both_reject(missing_confidence)

    assert "path" in evidence or "document_digest" in evidence


@pytest.mark.parametrize("owner", ["node", "edge"])
def test_missing_evidence_is_rejected_rather_than_emitted(owner: str) -> None:
    """A node or edge with no evidence is rejected rather than emitted."""
    document = _fixture()
    target = (
        _objects(document, "nodes")[0]
        if owner == "node"
        else _objects(document, "edges")[0]
    )
    target["evidence"] = []

    _assert_both_reject(document)


@pytest.mark.parametrize("owner", ["node", "edge"])
def test_confidence_must_be_an_enumerated_value_not_a_number(owner: str) -> None:
    """Confidence is drawn from a defined enumeration, not a free-form
    number."""
    document = _fixture()
    target = (
        _objects(document, "nodes")[0]
        if owner == "node"
        else _objects(document, "edges")[0]
    )
    target["confidence"] = 0.95

    _assert_both_reject(document)
