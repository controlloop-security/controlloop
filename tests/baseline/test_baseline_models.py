"""Contract tests shared by baseline schema 1.0.0 and `BaselineDocument`.

Mirrors `tests/acbom/test_schema_and_models.py`'s schema/model
parity style for the ACBOM, applied to the baseline artifact.
"""

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

from controlloop.baseline import BaselineDocument, load_baseline_document

type JsonObject = dict[str, object]

_CLI_ROOT = Path(__file__).resolve().parents[2]
_SCHEMA_PATH = _CLI_ROOT / "src/controlloop/schemas/baseline/1.0.0/baseline.schema.json"
_FIXTURE_PATH = _CLI_ROOT / "tests/fixtures/baseline/minimal-baseline.json"


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


def _validate_model(document: JsonObject) -> BaselineDocument:
    return BaselineDocument.model_validate_json(json.dumps(document))


def _assert_both_reject(document: JsonObject) -> None:
    with pytest.raises(JsonSchemaValidationError):
        _VALIDATOR.validate(document)
    with pytest.raises(PydanticValidationError):
        _validate_model(document)


def _assert_model_only_rejects(document: JsonObject, message: str) -> None:
    """Assert a fact-level rule that Draft 2020-12 cannot express
    structurally (mirrors the ACBOM contract test's own helper of the
    same name for graph-integrity rules)."""
    _VALIDATOR.validate(document)
    with pytest.raises(PydanticValidationError, match=message):
        _validate_model(document)


def test_published_schema_is_valid_draft_2020_12() -> None:
    Draft202012Validator.check_schema(_SCHEMA)


def test_minimal_fixture_validates_through_schema_and_models() -> None:
    document = _fixture()

    _VALIDATOR.validate(document)
    model = _validate_model(document)

    assert model.schema_version == "1.0.0"
    assert model.acbom_schema_version == "1.0.0"
    assert len(model.effective_authority) == 1


def test_fixture_digest_is_real_and_integrity_verified() -> None:
    """Unlike the ACBOM's own minimal fixture (whose `digest` is a
    placeholder never checked by anything today), this fixture's digest must
    be a real, recomputable digest: `load_baseline_document` verifies it, so
    a placeholder digest here would make every other test in this suite
    start from a document that cannot actually be loaded."""
    raw = _FIXTURE_PATH.read_bytes()

    document = load_baseline_document(raw)

    assert document.acbom_digest == _fixture()["acbom_digest"]


@pytest.mark.parametrize(
    "nested", [False, True], ids=["envelope", "effective_authority_entry"]
)
def test_unknown_fields_are_rejected(nested: bool) -> None:
    document = _fixture()
    target = _objects(document, "effective_authority")[0] if nested else document
    target["unexpected_field"] = True

    _assert_both_reject(document)


@pytest.mark.parametrize(
    ("category", "value"),
    [
        ("acbom_digest", f"sha256:{'A' * 64}"),
        ("digest", "sha256:short"),
        ("root_digest", f"sha256:{'D' * 64}"),
        ("agent_id", "not-a-node-id"),
    ],
)
def test_invalid_digests_and_ids_are_rejected(category: str, value: str) -> None:
    document = _fixture()
    if category == "root_digest":
        _object(document, "repository")["root_digest"] = value
    elif category == "agent_id":
        _objects(document, "effective_authority")[0]["agent_id"] = value
    else:
        document[category] = value

    _assert_both_reject(document)


@pytest.mark.parametrize("action", ["reads", "writes", "invokes"])
def test_resource_action_types_validate(action: str) -> None:
    """The three action types a baseline can record."""
    document = _fixture()
    _objects(document, "effective_authority")[0]["action"] = action

    _VALIDATOR.validate(document)
    model = _validate_model(document)

    assert str(model.effective_authority[0].action) == action


@pytest.mark.parametrize(
    "action",
    [
        "delegates-to",
        "authenticates-as",
        "permitted-by",
        "constrained-by",
        "receives-from",
    ],
)
def test_structural_edge_types_are_rejected_as_actions(action: str) -> None:
    """Only reads/writes/invokes represent an action a baseline can
    assert; structural edge types are rejected by both."""
    document = _fixture()
    _objects(document, "effective_authority")[0]["action"] = action

    _assert_both_reject(document)


def test_permitting_identity_is_optional() -> None:
    """Inherited from the effective-authority model: an unknown permitting
    identity is represented as an absent field, never fabricated."""
    document = _fixture()
    del _objects(document, "effective_authority")[0]["permitting_identity_id"]

    _VALIDATOR.validate(document)
    model = _validate_model(document)

    assert model.effective_authority[0].permitting_identity_id is None


def test_duplicate_effective_authority_entries_are_rejected_by_model() -> None:
    """A baseline records an already-deduplicated fact set; a duplicate
    `(agent_id, action, resource_id, permitting_identity_id)` tuple is a
    model-level rule Draft 2020-12 cannot express structurally."""
    document = _fixture()
    duplicate = deepcopy(_objects(document, "effective_authority")[0])
    _objects(document, "effective_authority").append(duplicate)

    _assert_model_only_rejects(document, "must be unique")


def test_missing_required_top_level_field_is_rejected() -> None:
    document = _fixture()
    del document["acbom_schema_version"]

    _assert_both_reject(document)


def test_empty_effective_authority_is_accepted() -> None:
    """A baseline with no direct effective authority yet (a fresh
    repository with no discovered authority) is a valid, honest
    baseline -- not a malformed one."""
    document = _fixture()
    document["effective_authority"] = []

    _VALIDATOR.validate(document)
    model = _validate_model(document)

    assert model.effective_authority == ()


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
    """The baseline contains no source, secret, or environment values.
    Inherited from reusing `Evidence`/`EffectiveAuthorityEntry` (already
    `extra="forbid"`), asserted directly here too rather than only by
    reference, mirroring
    `test_prohibited_raw_content_field_names_are_rejected` in
    `tests/acbom/test_schema_and_models.py`."""
    document = _fixture()
    evidence = _objects(_objects(document, "effective_authority")[0], "evidence")[0]
    evidence[field_name] = "synthetic-prohibited-value"

    _assert_both_reject(document)


def test_canary_planted_secret_never_leaks_through_a_rejection_error() -> None:
    """The canary: a planted secret-shaped value attached under a prohibited
    field name is rejected outright, and the raw planted value never appears
    in the resulting error text -- mirrors
    `test_evidence_content_field_never_leaks_a_planted_secret` in
    `tests/acbom/test_schema_and_models.py`."""
    planted_secret = "ghp_" + "a" * 36  # synthetic GitHub-token-shaped canary
    document = _fixture()
    evidence = _objects(_objects(document, "effective_authority")[0], "evidence")[0]
    evidence["content"] = planted_secret

    with pytest.raises(PydanticValidationError) as excinfo:
        _validate_model(document)

    assert planted_secret not in str(excinfo.value)


def test_effective_authority_at_max_length_is_accepted() -> None:
    """Boundary: exactly `max_length` distinct entries validate."""
    document = _fixture()
    template = _objects(document, "effective_authority")[0]
    entries = []
    for index in range(50):
        entry = deepcopy(template)
        entry["resource_id"] = f"clp:tool:sha256:{index:064x}"
        entries.append(entry)
    document["effective_authority"] = entries

    _VALIDATOR.validate(document)
    model = _validate_model(document)

    assert len(model.effective_authority) == 50


def test_excessive_effective_authority_collection_is_rejected_by_schema() -> None:
    """The schema-level half of the `max_length=10_000` boundary (the
    bounded-collection discipline): asserted at the schema layer only here,
    since constructing and fully validating 10,001 real nested
    `EffectiveAuthorityEntry` models in-process is unnecessarily expensive
    for a boundary the JSON Schema `maxItems` keyword already enforces
    structurally and identically to the model's `Field(max_length=...)`."""
    document = _fixture()
    template = _objects(document, "effective_authority")[0]
    document["effective_authority"] = [template] * 10_001

    with pytest.raises(JsonSchemaValidationError):
        _VALIDATOR.validate(document)
