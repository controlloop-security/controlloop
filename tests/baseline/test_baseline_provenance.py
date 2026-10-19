"""Tests for approval provenance.

Mirrors `tests/baseline/test_baseline_models.py`'s schema/model parity style
(against the new 1.1.0 schema) and
`tests/baseline/test_baseline_integrity.py`'s golden-digest and
tamper-detection style, extended with `controlloop.baseline.provenance`'s
reporting behavior. Every test here uses only in-process fixtures and the
committed fixture files under `tests/fixtures/baseline/` -- nothing in this
module opens a socket or otherwise depends on the network (offline evidence
for provenance's own core path).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import cast

import pytest
from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
from jsonschema.exceptions import (  # type: ignore[import-untyped]
    ValidationError as JsonSchemaValidationError,
)
from pydantic import ValidationError as PydanticValidationError

from controlloop.acbom import Confidence, EdgeType, Evidence, Generator, Repository
from controlloop.baseline import (
    ApprovalProvenance,
    ApproverSource,
    BaselineDocument,
    BaselineIntegrityError,
    ProvenanceStatus,
    describe_provenance,
    format_provenance_lines,
    load_baseline_document,
    with_baseline_digest,
)
from controlloop.baseline.serialization import compute_baseline_digest
from controlloop.capability.models import EffectiveAuthorityEntry
from controlloop.exit_codes import ExitCode

type JsonObject = dict[str, object]

_CLI_ROOT = Path(__file__).resolve().parents[2]
_SCHEMA_PATH = _CLI_ROOT / "src/controlloop/schemas/baseline/1.1.0/baseline.schema.json"
_FIXTURES = _CLI_ROOT / "tests/fixtures/baseline"
_MINIMAL_FIXTURE_PATH = _FIXTURES / "minimal-baseline.json"
_WITH_PROVENANCE_PATH = _FIXTURES / "baseline-with-provenance.json"
_WITH_MALFORMED_PROVENANCE_PATH = _FIXTURES / "baseline-with-malformed-provenance.json"

# Regenerate by hashing the schema file after a deliberate, version-bumped
# change: `hashlib.sha256(_SCHEMA_PATH.read_bytes()).hexdigest()`. Moved by
# the fix that made `permitting_identity_id` nullable, and again by the fix
# that gave every remaining optional field in this schema -- `Evidence`'s
# six and `ApprovalProvenance`'s four, plus `provenance` itself -- the same
# null branch. Both are corrective PATCHes under
# docs/reference/schema-versioning.md: they relax the packaged file to
# describe behavior that never changed, so no document valid before is
# invalid after, and no `schema_version` bump is warranted.
_GOLDEN_SCHEMA_DIGEST_FOR_1_1_0 = (
    "ee5aaad231087b4bbfab31307a44baf3f117d6dfb904fcce596e08d80e4e5315"
)

_AGENT_ID = f"clp:agent:sha256:{'a' * 64}"
_RESOURCE_ID = f"clp:tool:sha256:{'b' * 64}"
_PLACEHOLDER_DIGEST = f"sha256:{'0' * 64}"
_ACBOM_DIGEST = f"sha256:{'e' * 64}"


def _load_object(path: Path) -> JsonObject:
    return cast(JsonObject, json.loads(path.read_text(encoding="utf-8")))


def _document(*, provenance: ApprovalProvenance | None) -> BaselineDocument:
    entry = EffectiveAuthorityEntry(
        schema_version="1.0.0",
        agent_id=_AGENT_ID,
        action=EdgeType.INVOKES,
        resource_id=_RESOURCE_ID,
        confidence=Confidence.HIGH,
        evidence=(Evidence(adapter="mcp", path="a.json"),),
    )
    return BaselineDocument(
        schema_version="1.1.0",
        generator=Generator(name="controlloop", version="0.1.0"),
        repository=Repository(commit="abc123", root_digest=f"sha256:{'f' * 64}"),
        acbom_schema_version="1.0.0",
        acbom_digest=_ACBOM_DIGEST,
        effective_authority=(entry,),
        provenance=provenance,
        digest=_PLACEHOLDER_DIGEST,
    )


class TestSchemaParity:
    """Mirrors `test_baseline_models.py`'s schema/model parity style,
    applied to the new 1.1.0 schema and its `approvalProvenance` addition
    (including the schema version bump)."""

    def test_published_schema_is_valid_draft_2020_12(self) -> None:
        schema = _load_object(_SCHEMA_PATH)
        Draft202012Validator.check_schema(schema)

    def test_packaged_schema_matches_its_golden_digest(self) -> None:
        """A breaking schema change without a version increment fails CI
        -- mirrors `test_packaged_schema_matches_its_golden_digest` in
        `test_baseline_integrity.py`."""
        actual_digest = hashlib.sha256(_SCHEMA_PATH.read_bytes()).hexdigest()

        assert actual_digest == _GOLDEN_SCHEMA_DIGEST_FOR_1_1_0, (
            "the packaged baseline 1.1.0 schema file changed without "
            "updating the golden digest -- see "
            "docs/reference/schema-versioning.md and "
            "docs/reference/baseline-artifact-format.md before updating "
            "this constant"
        )

    def test_fixture_with_provenance_validates_through_schema_and_model(self) -> None:
        document = _load_object(_WITH_PROVENANCE_PATH)
        schema = _load_object(_SCHEMA_PATH)

        Draft202012Validator(schema).validate(document)
        model = BaselineDocument.model_validate_json(json.dumps(document))

        assert model.schema_version == "1.1.0"
        assert model.provenance is not None
        assert model.provenance.approver == "reviewer@example.test"

    def test_fixture_with_malformed_provenance_validates_through_schema_and_model(
        self,
    ) -> None:
        """Malformed provenance is structurally valid at the schema/model
        layer -- only `describe_provenance` classifies it as unattributed,
        never a structural validator."""
        document = _load_object(_WITH_MALFORMED_PROVENANCE_PATH)
        schema = _load_object(_SCHEMA_PATH)

        Draft202012Validator(schema).validate(document)
        model = BaselineDocument.model_validate_json(json.dumps(document))

        assert model.provenance is not None
        assert model.provenance.approver_source is None
        assert model.provenance.approved_commit is None

    def test_unknown_field_inside_provenance_is_rejected(self) -> None:
        document = _load_object(_WITH_PROVENANCE_PATH)
        provenance = cast(JsonObject, document["provenance"])
        provenance["unexpected_field"] = True
        schema = _load_object(_SCHEMA_PATH)

        with pytest.raises(JsonSchemaValidationError):
            Draft202012Validator(schema).validate(document)
        with pytest.raises(PydanticValidationError):
            BaselineDocument.model_validate_json(json.dumps(document))


class TestNullablePermittingIdentityParity:
    """The packaged 1.1.0 schema once required
    `effective_authority[].permitting_identity_id` to be a pattern-matched
    string, while `controlloop.capability.models.EffectiveAuthorityEntry`
    types it `NodeId | None` and `compute_effective_authority` deliberately
    emits `None` for an action edge with no matching identity -- "An action
    edge with no matching identity still produces an entry, at
    `Confidence.UNKNOWN`, rather than being dropped".

    That is not a hypothetical: the reference agent's
    `scenarios/order-support-agent` has `invokes` edges and no
    `authenticates-as` edge, so its real, CLI-accepted baseline carries
    `"permitting_identity_id": null` and the packaged schema meant to
    describe it rejected the document.

    Widening the packaged file to `anyOf: [nodeId, null]` matches the
    already-correct definition of the identically-named field in
    `src/controlloop/schemas/report/1.1.0/report.schema.json`. Under
    `docs/reference/schema-versioning.md` this is a corrective PATCH, not
    a MINOR or MAJOR change: it relaxes what the packaged file accepts so
    it finally describes behavior that never changed, no document valid
    before this is invalid after it, and no `schema_version` bump is
    warranted. Only the golden digest above moves.
    """

    @staticmethod
    def _with_permitting_identity(value: object) -> JsonObject:
        document = _load_object(_WITH_PROVENANCE_PATH)
        entries = cast(list[JsonObject], document["effective_authority"])
        entries[0]["permitting_identity_id"] = value
        return document

    def _assert_both_accept(self, value: object) -> None:
        document = self._with_permitting_identity(value)

        Draft202012Validator(_load_object(_SCHEMA_PATH)).validate(document)
        model = BaselineDocument.model_validate_json(json.dumps(document))

        assert model.effective_authority[0].permitting_identity_id == value

    def _assert_both_reject(self, value: object) -> None:
        document = self._with_permitting_identity(value)

        with pytest.raises(JsonSchemaValidationError):
            Draft202012Validator(_load_object(_SCHEMA_PATH)).validate(document)
        with pytest.raises(PydanticValidationError):
            BaselineDocument.model_validate_json(json.dumps(document))

    def test_null_permitting_identity_is_accepted_by_schema_and_model(self) -> None:
        """The exact document from the original report. Fails against the
        pre-fix schema with `None is not of type 'string'`."""
        self._assert_both_accept(None)

    def test_well_formed_permitting_identity_is_still_accepted(self) -> None:
        self._assert_both_accept(f"clp:identity:sha256:{'c' * 64}")

    @pytest.mark.parametrize(
        "value",
        [
            "",
            "not-an-id",
            f"clp:widget:sha256:{'c' * 64}",
            f"clp:identity:sha256:{'c' * 63}",
            f"clp:identity:sha256:{'C' * 64}",
        ],
    )
    def test_malformed_permitting_identity_is_still_rejected_by_both(
        self, value: str
    ) -> None:
        """Relaxing the field to accept `null` must not relax it to
        accept a malformed identity ID."""
        self._assert_both_reject(value)

    def test_packaged_definition_declares_null_explicitly(self) -> None:
        """Guards the shape of the fix itself, so a future edit cannot
        silently drop the null branch and reintroduce the defect."""
        schema = _load_object(_SCHEMA_PATH)
        defs = cast(JsonObject, schema["$defs"])
        entry = cast(JsonObject, defs["effectiveAuthorityEntry"])
        properties = cast(JsonObject, entry["properties"])
        field = cast(JsonObject, properties["permitting_identity_id"])

        assert {"type": "null"} in cast(list[JsonObject], field["anyOf"])

    @pytest.mark.parametrize("field_name", ["agent_id", "resource_id"])
    def test_sibling_identifier_fields_are_still_not_nullable(
        self, field_name: str
    ) -> None:
        """Boundary case: only `permitting_identity_id` is nullable. The
        required node references either side of it must keep rejecting
        `null`, or the fix has over-relaxed the entry."""
        document = _load_object(_WITH_PROVENANCE_PATH)
        entries = cast(list[JsonObject], document["effective_authority"])
        entries[0][field_name] = None

        with pytest.raises(JsonSchemaValidationError):
            Draft202012Validator(_load_object(_SCHEMA_PATH)).validate(document)
        with pytest.raises(PydanticValidationError):
            BaselineDocument.model_validate_json(json.dumps(document))


class TestApprovalProvenanceModel:
    """Every field is optional and independently settable."""

    def test_all_fields_optional_and_default_to_none(self) -> None:
        provenance = ApprovalProvenance()

        assert provenance.approver is None
        assert provenance.approver_source is None
        assert provenance.approved_at is None
        assert provenance.approved_commit is None

    def test_partial_provenance_is_accepted(self) -> None:
        """Malformed/incomplete provenance is a legitimate, loadable value
        at the model layer."""
        provenance = ApprovalProvenance(approver="reviewer@example.test")

        assert provenance.approver == "reviewer@example.test"
        assert provenance.approved_at is None

    def test_arbitrary_approver_source_text_is_accepted_by_the_model(self) -> None:
        """Deliberately not a closed enum at the model level (see
        `ApprovalProvenance.approver_source`'s docstring) -- an unrecognized
        value is a `describe_provenance`-level "unattributed"
        classification, not a parse-time rejection."""
        provenance = ApprovalProvenance(approver_source="maybe")

        assert provenance.approver_source == "maybe"

    def test_field_over_max_length_is_rejected(self) -> None:
        """Boundary: this one case is a legitimate whole-document
        rejection (a `SafeText` bound violation), unlike an ordinary
        semantically-malformed value -- `SafeText` caps every field at
        1024 characters regardless of which provenance field it is."""
        with pytest.raises(PydanticValidationError):
            ApprovalProvenance(approver="x" * 1025)

    def test_field_at_max_length_is_accepted(self) -> None:
        provenance = ApprovalProvenance(approver="x" * 1024)

        assert provenance.approver is not None
        assert len(provenance.approver) == 1024

    def test_control_character_is_rejected(self) -> None:
        with pytest.raises(PydanticValidationError):
            ApprovalProvenance(approver="reviewer\x00example")

    def test_unknown_field_is_rejected(self) -> None:
        with pytest.raises(PydanticValidationError):
            ApprovalProvenance.model_validate({"unexpected_field": "x"})


class TestApprovalProvenancePrivacy:
    """Privacy canary -- mirrors
    `test_canary_planted_secret_never_leaks_through_a_rejection_error` in
    `test_baseline_models.py`."""

    def test_canary_planted_secret_never_leaks_through_a_rejection_error(self) -> None:
        planted_secret = "ghp_" + "a" * 1040  # exceeds SafeText's max_length

        with pytest.raises(PydanticValidationError) as excinfo:
            ApprovalProvenance(approver=planted_secret)

        assert planted_secret not in str(excinfo.value)


class TestDescribeProvenance:
    """Classification of attributed vs. unattributed provenance."""

    def test_missing_provenance_is_unattributed(self) -> None:
        document = load_baseline_document(_MINIMAL_FIXTURE_PATH.read_bytes())

        assert document.provenance is None
        summary = describe_provenance(document)

        assert summary.status is ProvenanceStatus.UNATTRIBUTED
        assert summary.issues
        assert summary.approver is None

    def test_complete_supplied_provenance_is_attributed(self) -> None:
        document = load_baseline_document(_WITH_PROVENANCE_PATH.read_bytes())

        summary = describe_provenance(document)

        assert summary.status is ProvenanceStatus.ATTRIBUTED
        assert summary.issues == ()
        assert summary.approver == "reviewer@example.test"
        assert summary.approver_source == ApproverSource.SUPPLIED.value

    def test_complete_inferred_provenance_is_still_attributed(self) -> None:
        """An inferred-but-fully-labeled entry is honestly attributed -- it
        must be labeled as inferred, not treated as unattributed."""
        document = _document(
            provenance=ApprovalProvenance(
                approver="git-log-heuristic",
                approver_source=ApproverSource.INFERRED.value,
                approved_at="2026-08-19T00:00:00Z",
                approved_commit="abc123",
            )
        )

        summary = describe_provenance(document)

        assert summary.status is ProvenanceStatus.ATTRIBUTED
        assert summary.approver_source == ApproverSource.INFERRED.value

    def test_malformed_provenance_is_unattributed_but_preserves_present_facts(
        self,
    ) -> None:
        document = load_baseline_document(_WITH_MALFORMED_PROVENANCE_PATH.read_bytes())

        summary = describe_provenance(document)

        assert summary.status is ProvenanceStatus.UNATTRIBUTED
        # The approver value that *was* present is never discarded just
        # because the whole is incomplete.
        assert summary.approver == "reviewer@example.test"
        assert any("approver source" in issue for issue in summary.issues)
        assert any("timestamp" in issue for issue in summary.issues)
        assert any("commit" in issue for issue in summary.issues)

    def test_unparseable_timestamp_alone_is_flagged(self) -> None:
        document = _document(
            provenance=ApprovalProvenance(
                approver="reviewer@example.test",
                approver_source=ApproverSource.SUPPLIED.value,
                approved_at="definitely not a timestamp",
                approved_commit="abc123",
            )
        )

        summary = describe_provenance(document)

        assert summary.status is ProvenanceStatus.UNATTRIBUTED
        assert any("timestamp" in issue for issue in summary.issues)

    def test_unrecognized_approver_source_is_flagged(self) -> None:
        document = _document(
            provenance=ApprovalProvenance(
                approver="reviewer@example.test",
                approver_source="maybe",
                approved_at="2026-08-19T00:00:00Z",
                approved_commit="abc123",
            )
        )

        summary = describe_provenance(document)

        assert summary.status is ProvenanceStatus.UNATTRIBUTED
        assert any("not a recognized value" in issue for issue in summary.issues)

    def test_describe_provenance_never_raises_on_a_malformed_document(self) -> None:
        """The central guarantee, asserted directly: classification never
        raises, no matter how incomplete the provenance is."""
        document = _document(provenance=ApprovalProvenance())

        summary = describe_provenance(document)

        assert summary.status is ProvenanceStatus.UNATTRIBUTED
        assert len(summary.issues) == 4

    def test_determinism_across_repeated_calls(self) -> None:
        document = load_baseline_document(_WITH_PROVENANCE_PATH.read_bytes())

        first = describe_provenance(document)
        second = describe_provenance(document)

        assert first == second


class TestFormatProvenanceLines:
    """CLI-voice rendering, never disclosed to any command yet (this module
    has no CLI caller today -- see its own module docstring)."""

    def test_attributed_supplied_line_names_approver_and_qualifies_supplied(
        self,
    ) -> None:
        document = load_baseline_document(_WITH_PROVENANCE_PATH.read_bytes())

        lines = format_provenance_lines(document)

        assert len(lines) == 1
        assert "reviewer@example.test" in lines[0]
        assert "(supplied)" in lines[0]
        assert "(inferred)" not in lines[0]
        assert "abc123" in lines[0]

    def test_attributed_inferred_line_says_inferred_never_supplied(self) -> None:
        """The literal assertion: an inferred approver identity is never
        rendered as if it were directly supplied."""
        document = _document(
            provenance=ApprovalProvenance(
                approver="git-log-heuristic",
                approver_source=ApproverSource.INFERRED.value,
                approved_at="2026-08-19T00:00:00Z",
                approved_commit="abc123",
            )
        )

        lines = format_provenance_lines(document)

        assert "(inferred)" in lines[0]
        assert "(supplied)" not in lines[0]

    def test_missing_provenance_line_says_unattributed(self) -> None:
        document = load_baseline_document(_MINIMAL_FIXTURE_PATH.read_bytes())

        lines = format_provenance_lines(document)

        assert len(lines) == 1
        assert "UNATTRIBUTED" in lines[0]
        assert lines[0].startswith("!")

    def test_malformed_provenance_line_says_unattributed(self) -> None:
        document = load_baseline_document(_WITH_MALFORMED_PROVENANCE_PATH.read_bytes())

        lines = format_provenance_lines(document)

        assert "UNATTRIBUTED" in lines[0]

    def test_determinism_across_repeated_calls(self) -> None:
        document = load_baseline_document(_WITH_PROVENANCE_PATH.read_bytes())

        first = format_provenance_lines(document)
        second = format_provenance_lines(document)

        assert first == second


class TestDigestCoverage:
    """Provenance is covered by the canonical digest so it cannot be altered
    without detection."""

    def test_digest_differs_when_provenance_differs(self) -> None:
        without = _document(provenance=None)
        with_provenance = _document(
            provenance=ApprovalProvenance(approver="reviewer@example.test")
        )

        assert compute_baseline_digest(without) != compute_baseline_digest(
            with_provenance
        )

    def test_digest_is_stable_for_the_same_provenance(self) -> None:
        first = _document(
            provenance=ApprovalProvenance(
                approver="reviewer@example.test",
                approver_source=ApproverSource.SUPPLIED.value,
                approved_at="2026-08-19T00:00:00Z",
                approved_commit="abc123",
            )
        )
        second = _document(
            provenance=ApprovalProvenance(
                approver="reviewer@example.test",
                approver_source=ApproverSource.SUPPLIED.value,
                approved_at="2026-08-19T00:00:00Z",
                approved_commit="abc123",
            )
        )

        assert compute_baseline_digest(first) == compute_baseline_digest(second)

    def test_missing_provenance_still_matches_the_pre_existing_committed_digest(
        self,
    ) -> None:
        """The backward-compatibility property provenance depends on:
        recomputing the digest for a real document that predates the 1.1.0
        bump (no `provenance` field at all) under today's model still
        reproduces the exact digest committed for it under 1.0.0 -- see
        `controlloop.baseline.serialization._document_data`'s docstring for
        why this needs a targeted exclusion, not merely `provenance: null`
        serialization."""
        document = load_baseline_document(_MINIMAL_FIXTURE_PATH.read_bytes())

        assert compute_baseline_digest(document) == document.digest

    def test_tampered_provenance_approver_is_detected(self) -> None:
        """Mirrors `TestLoadBaselineDocumentTampered` in
        `test_baseline_integrity.py`, extended to a provenance field."""
        signed = with_baseline_digest(
            _document(
                provenance=ApprovalProvenance(
                    approver="reviewer@example.test",
                    approver_source=ApproverSource.SUPPLIED.value,
                    approved_at="2026-08-19T00:00:00Z",
                    approved_commit="abc123",
                )
            )
        )
        raw = json.loads(signed.model_dump_json())
        raw["provenance"]["approver"] = "attacker@example.test"

        with pytest.raises(BaselineIntegrityError) as excinfo:
            load_baseline_document(json.dumps(raw))

        assert excinfo.value.exit_code is ExitCode.INVALID_INPUT

    def test_tampered_approver_source_from_inferred_to_supplied_is_detected(
        self,
    ) -> None:
        """A tampered document cannot silently upgrade an honestly
        `"inferred"` approval into an apparently `"supplied"` one -- digest
        coverage protects the inferred/supplied distinction."""
        signed = with_baseline_digest(
            _document(
                provenance=ApprovalProvenance(
                    approver="git-log-heuristic",
                    approver_source=ApproverSource.INFERRED.value,
                    approved_at="2026-08-19T00:00:00Z",
                    approved_commit="abc123",
                )
            )
        )
        raw = json.loads(signed.model_dump_json())
        raw["provenance"]["approver_source"] = ApproverSource.SUPPLIED.value

        with pytest.raises(BaselineIntegrityError) as excinfo:
            load_baseline_document(json.dumps(raw))

        assert excinfo.value.exit_code is ExitCode.INVALID_INPUT

    def test_removing_provenance_entirely_is_detected(self) -> None:
        signed = with_baseline_digest(
            _document(provenance=ApprovalProvenance(approver="reviewer@example.test"))
        )
        raw = json.loads(signed.model_dump_json())
        del raw["provenance"]

        with pytest.raises(BaselineIntegrityError) as excinfo:
            load_baseline_document(json.dumps(raw))

        assert excinfo.value.exit_code is ExitCode.INVALID_INPUT


class TestOptionalFieldsAcceptExplicitNull:
    """The packaged schema once rejected documents its own model produces by
    default.

    `Evidence` and `ApprovalProvenance` type their optional fields
    `X | None = None`, and `model_dump_json()` -- the ordinary way to
    serialize a Pydantic model -- writes them as explicit nulls. The
    packaged schema had no null branch for any of them, so a plain round
    trip through the model failed validation against the very schema
    meant to describe it.

    This is the same defect already fixed for `permitting_identity_id`. That
    fix's investigation could not see the rest of it, because a JSON Schema
    validator reports the best-matching error and stopped at the first
    field.

    A document that omits an optional field instead of nulling it was
    always valid and still is -- this only widens what is accepted.
    """

    @staticmethod
    def _document(**provenance_fields: object) -> JsonObject:
        document = _document(provenance=ApprovalProvenance(**provenance_fields))  # type: ignore[arg-type]
        return cast(JsonObject, json.loads(document.model_dump_json()))

    def test_plain_model_dump_json_validates(self) -> None:
        """The exact repro: serialize the ordinary way, nulls and all, and
        validate against the packaged schema."""
        document = self._document(approver="reviewer@example.test")

        Draft202012Validator(_load_object(_SCHEMA_PATH)).validate(document)

    def test_a_document_with_no_provenance_at_all_validates(self) -> None:
        document = cast(
            JsonObject, json.loads(_document(provenance=None).model_dump_json())
        )

        assert document["provenance"] is None
        Draft202012Validator(_load_object(_SCHEMA_PATH)).validate(document)

    @pytest.mark.parametrize(
        "field", ["line_start", "line_end", "parser", "schema_id", "document_digest"]
    )
    def test_each_optional_evidence_field_accepts_null(self, field: str) -> None:
        document = self._document(approver="reviewer@example.test")
        entries = cast(list[JsonObject], document["effective_authority"])
        evidence = cast(list[JsonObject], entries[0]["evidence"])
        evidence[0][field] = None

        Draft202012Validator(_load_object(_SCHEMA_PATH)).validate(document)
        BaselineDocument.model_validate_json(json.dumps(document))

    def test_path_may_be_null_only_when_a_document_digest_carries_it(self) -> None:
        """`path` is conditionally required: `Evidence` rejects a value
        with neither a path nor a document digest. Making the field
        nullable must not lose that, so the schema's own `anyOf` was
        rewritten to require the field *present and non-null* rather
        than merely present -- a key set to `null` satisfies `required`
        but not the model."""
        document = self._document(approver="reviewer@example.test")
        entries = cast(list[JsonObject], document["effective_authority"])
        evidence = cast(list[JsonObject], entries[0]["evidence"])
        evidence[0]["path"] = None
        evidence[0]["document_digest"] = f"sha256:{'a' * 64}"

        Draft202012Validator(_load_object(_SCHEMA_PATH)).validate(document)
        BaselineDocument.model_validate_json(json.dumps(document))

    def test_null_path_without_a_document_digest_is_rejected_by_both(self) -> None:
        document = self._document(approver="reviewer@example.test")
        entries = cast(list[JsonObject], document["effective_authority"])
        evidence = cast(list[JsonObject], entries[0]["evidence"])
        evidence[0]["path"] = None

        with pytest.raises(JsonSchemaValidationError):
            Draft202012Validator(_load_object(_SCHEMA_PATH)).validate(document)
        with pytest.raises(PydanticValidationError):
            BaselineDocument.model_validate_json(json.dumps(document))

    def test_a_line_start_with_a_null_path_is_rejected_by_both(self) -> None:
        """The `if/then` constraints had the same present-but-null hole."""
        document = self._document(approver="reviewer@example.test")
        entries = cast(list[JsonObject], document["effective_authority"])
        evidence = cast(list[JsonObject], entries[0]["evidence"])
        evidence[0]["path"] = None
        evidence[0]["document_digest"] = f"sha256:{'a' * 64}"
        evidence[0]["line_start"] = 3

        with pytest.raises(JsonSchemaValidationError):
            Draft202012Validator(_load_object(_SCHEMA_PATH)).validate(document)
        with pytest.raises(PydanticValidationError):
            BaselineDocument.model_validate_json(json.dumps(document))

    @pytest.mark.parametrize(
        "field", ["approver", "approver_source", "approved_at", "approved_commit"]
    )
    def test_each_optional_provenance_field_accepts_null(self, field: str) -> None:
        document = self._document(approver="reviewer@example.test")
        cast(JsonObject, document["provenance"])[field] = None

        Draft202012Validator(_load_object(_SCHEMA_PATH)).validate(document)
        BaselineDocument.model_validate_json(json.dumps(document))

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("line_start", 0),
            ("line_start", "3"),
            ("path", "/etc/passwd"),
            ("path", "../escape.json"),
            ("adapter", None),
        ],
    )
    def test_malformed_evidence_is_still_rejected_by_both(
        self, field: str, value: object
    ) -> None:
        """Widening to accept null must not widen to accept anything
        else -- including nulling `adapter`, which is required."""
        document = self._document(approver="reviewer@example.test")
        entries = cast(list[JsonObject], document["effective_authority"])
        evidence = cast(list[JsonObject], entries[0]["evidence"])
        evidence[0][field] = value

        with pytest.raises(JsonSchemaValidationError):
            Draft202012Validator(_load_object(_SCHEMA_PATH)).validate(document)
        with pytest.raises(PydanticValidationError):
            BaselineDocument.model_validate_json(json.dumps(document))

    @pytest.mark.parametrize("field", ["schema_version", "digest", "acbom_digest"])
    def test_required_top_level_fields_are_still_not_nullable(self, field: str) -> None:
        document = self._document(approver="reviewer@example.test")
        document[field] = None

        with pytest.raises(JsonSchemaValidationError):
            Draft202012Validator(_load_object(_SCHEMA_PATH)).validate(document)
        with pytest.raises(PydanticValidationError):
            BaselineDocument.model_validate_json(json.dumps(document))
