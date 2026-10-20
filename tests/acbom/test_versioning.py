"""Tests for controlloop.acbom.versioning.

The compatibility policy itself is documented in
docs/reference/schema-versioning.md.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from controlloop.acbom import (
    CURRENT_SCHEMA_VERSION,
    ACBOMDocument,
    ACBOMIntegrityError,
    IncompatibleSchemaVersionError,
    canonicalize_document,
    check_schema_version_compatible,
    compute_digest,
    load_acbom_document,
)
from controlloop.exit_codes import ExitCode

_CLI_ROOT = Path(__file__).resolve().parents[2]
_SCHEMA_PATH = _CLI_ROOT / "src/controlloop/schemas/acbom/1.2.0/acbom.schema.json"
_FIXTURE_PATH = _CLI_ROOT / "tests/fixtures/acbom/minimal-input.json"
_FROZEN_1_0_0_SCHEMA_PATH = (
    _CLI_ROOT / "src/controlloop/schemas/acbom/1.0.0/acbom.schema.json"
)
_FROZEN_1_1_0_SCHEMA_PATH = (
    _CLI_ROOT / "src/controlloop/schemas/acbom/1.1.0/acbom.schema.json"
)

# Regenerate by hashing the schema file after a deliberate, version-bumped
# change: `hashlib.sha256(_SCHEMA_PATH.read_bytes()).hexdigest()`. The bump
# from 1.0.0 to 1.1.0 added one new, optional, defaulted,
# backward-compatible field, `schema_url`; the 1.0.0 file itself is kept
# unmodified at `src/controlloop/schemas/acbom/1.0.0/`, the same two-version
# precedent `schemas/baseline/` and `schemas/evidence/` already established.
# The bump from 1.1.0 to 1.2.0 added the agent authority contract; the 1.1.0
# file is now frozen too, held to its digest below.
_GOLDEN_SCHEMA_DIGEST_FOR_1_2_0 = (
    "3e3350149b1867c0d287918465956b0a7e07efb5cd8150a6fc052b9993eb94c0"
)
_FROZEN_SCHEMA_DIGEST_FOR_1_1_0 = (
    "8e3c8e2cc122a7baf1057e3e2d299aa779665e7fb72ec2de4d17c3705844abcb"
)


def test_schema_version_and_generator_version_are_always_present() -> None:
    """Every ACBOM records its schema version and the scanner version that
    produced it."""
    document = ACBOMDocument.model_validate_json(_FIXTURE_PATH.read_text())

    assert document.schema_version == CURRENT_SCHEMA_VERSION
    assert document.generator.name
    assert document.generator.version


def test_schema_version_is_a_required_field() -> None:
    fixture = json.loads(_FIXTURE_PATH.read_text())
    del fixture["schema_version"]

    with pytest.raises(Exception, match="schema_version"):
        ACBOMDocument.model_validate_json(json.dumps(fixture))


class TestCheckSchemaVersionCompatible:
    def test_identical_version_is_compatible(self) -> None:
        check_schema_version_compatible("1.0.0", reader_version="1.0.0")

    def test_older_minor_within_the_same_major_is_compatible(self) -> None:
        """Reading a compatible older version succeeds."""
        check_schema_version_compatible("1.0.0", reader_version="1.4.0")

    @pytest.mark.parametrize(
        ("document_version", "reader_version"),
        [
            ("2.0.0", "1.4.0"),
            ("0.9.0", "1.4.0"),
        ],
        ids=["newer-major", "older-major"],
    )
    def test_different_major_is_incompatible(
        self, document_version: str, reader_version: str
    ) -> None:
        """Reading a newer major version returns exit 2 with a clear message
        rather than partially parsing. A different (older) major is rejected
        the same way."""
        with pytest.raises(IncompatibleSchemaVersionError) as excinfo:
            check_schema_version_compatible(
                document_version, reader_version=reader_version
            )

        assert excinfo.value.exit_code is ExitCode.INVALID_INPUT
        assert document_version in str(excinfo.value)
        assert reader_version in str(excinfo.value)

    def test_newer_minor_within_the_same_major_is_incompatible(self) -> None:
        """A newer minor may carry an additive field this reader does
        not know about, and extra="forbid" would reject it uncleanly --
        so it is rejected here, cleanly, first."""
        with pytest.raises(IncompatibleSchemaVersionError) as excinfo:
            check_schema_version_compatible("1.5.0", reader_version="1.4.0")

        assert excinfo.value.exit_code is ExitCode.INVALID_INPUT

    def test_malformed_version_is_rejected_not_crashed_on(self) -> None:
        with pytest.raises(IncompatibleSchemaVersionError):
            check_schema_version_compatible("not-a-version", reader_version="1.0.0")


def _with_true_digest(data: dict[str, object]) -> str:
    """`data` as JSON with its `digest` set to the real canonical digest
    of its content. `minimal-input.json` carries a placeholder digest
    because it is canonicalization input, not a generated document."""

    document = ACBOMDocument.model_validate_json(json.dumps(data))
    return json.dumps(
        {**data, "digest": compute_digest(canonicalize_document(document))}
    )


class TestLoadAcbomDocument:
    def test_reads_a_real_fixture_at_the_current_version(self) -> None:
        raw = _with_true_digest(json.loads(_FIXTURE_PATH.read_text()))

        document = load_acbom_document(raw)

        assert document.schema_version == CURRENT_SCHEMA_VERSION

    def test_version_drift_fixture_reads_an_older_real_document(self) -> None:
        """The version-drift fixture: a genuine 1.0.0 document (no
        `schema_url`, the field 1.1.0 added) read by this reader's own
        current (1.1.0-plus) compatibility policy, proving the
        older-version-succeeds path holds for actual document content, not
        only the version-string comparison in isolation."""
        older = json.loads(_FIXTURE_PATH.read_text())
        older["schema_version"] = "1.0.0"
        del older["schema_url"]
        raw = _with_true_digest(older)

        document = load_acbom_document(raw)

        assert document.schema_version == "1.0.0"
        assert document.schema_url is None

    def test_incompatible_major_never_completes_a_full_parse(self) -> None:
        """Rejected before any full parse is attempted."""
        raw = _FIXTURE_PATH.read_text()
        # Corrupt the document's actual content so any full parse attempt
        # would raise a *different* error than IncompatibleSchemaVersionError
        # if the version gate were skipped.
        broken = json.loads(raw)
        del broken["nodes"]
        broken_raw = json.dumps(broken)

        with pytest.raises(IncompatibleSchemaVersionError):
            load_acbom_document(broken_raw, reader_version="2.0.0")

    def test_missing_schema_version_is_rejected(self) -> None:
        fixture = json.loads(_FIXTURE_PATH.read_text())
        del fixture["schema_version"]

        with pytest.raises(IncompatibleSchemaVersionError):
            load_acbom_document(json.dumps(fixture))


class TestLoadAcbomDocumentIntegrity:
    """An ACBOM is only ever returned when it is well formed and its
    declared digest matches its content."""

    def test_an_edited_document_is_rejected(self) -> None:
        data = json.loads(_with_true_digest(json.loads(_FIXTURE_PATH.read_text())))
        data["nodes"][0]["name"] = "renamed-after-generation"

        with pytest.raises(ACBOMIntegrityError, match="digest does not match"):
            load_acbom_document(json.dumps(data))

    def test_a_placeholder_digest_is_rejected(self) -> None:
        with pytest.raises(ACBOMIntegrityError, match="digest does not match"):
            load_acbom_document(_FIXTURE_PATH.read_text())

    def test_an_unedited_document_round_trips(self) -> None:
        raw = _with_true_digest(json.loads(_FIXTURE_PATH.read_text()))

        assert load_acbom_document(raw).digest == json.loads(raw)["digest"]

    def test_a_schema_violation_is_one_line_naming_the_location(self) -> None:
        data = json.loads(_FIXTURE_PATH.read_text())
        data["nodes"][0]["type"] = "banana"

        with pytest.raises(ACBOMIntegrityError) as excinfo:
            load_acbom_document(json.dumps(data))

        message = str(excinfo.value)
        assert "nodes.0.type" in message
        assert "\n" not in message
        assert "errors.pydantic.dev" not in message
        assert excinfo.value.exit_code is ExitCode.INVALID_INPUT

    def test_several_schema_violations_are_counted(self) -> None:
        data = json.loads(_FIXTURE_PATH.read_text())
        data["nodes"][0]["type"] = "banana"
        data["nodes"][0]["confidence"] = "certain"

        with pytest.raises(ACBOMIntegrityError, match=r"and 1 more error\)"):
            load_acbom_document(json.dumps(data))

    @pytest.mark.parametrize("raw", ["{", "not json", b"\xff\xfe"])
    def test_invalid_json_is_an_integrity_error(self, raw: str | bytes) -> None:
        with pytest.raises(ACBOMIntegrityError, match="not valid JSON"):
            load_acbom_document(raw)


def test_packaged_schema_matches_its_golden_digest() -> None:
    """A breaking schema change without a version increment fails CI. This
    schema file's content is tied to a committed digest for its declared
    version; any edit to the file changes the digest, and this test then
    requires a deliberate update -- which itself requires deciding whether
    the change is a MAJOR/MINOR/PATCH bump per
    docs/reference/schema-versioning.md, not a silent drift.
    """
    actual_digest = hashlib.sha256(_SCHEMA_PATH.read_bytes()).hexdigest()

    assert actual_digest == _GOLDEN_SCHEMA_DIGEST_FOR_1_2_0, (
        "the packaged schema file changed without updating the golden "
        "digest -- see docs/reference/schema-versioning.md before "
        "updating this constant"
    )


def test_frozen_1_0_0_schema_file_is_never_edited() -> None:
    """A published schema version is never modified in place. The 1.0.0 file
    predates `schema_url` (the 1.1.0 addition) and must stay exactly that
    way."""

    schema = json.loads(_FROZEN_1_0_0_SCHEMA_PATH.read_text(encoding="utf-8"))

    assert (
        schema["$id"] == "https://schemas.controlloop.ai/acbom/1.0.0/acbom.schema.json"
    )
    assert "schema_url" not in schema["properties"]


def test_frozen_1_1_0_schema_file_is_never_edited() -> None:
    """1.1.0 is a published version and is frozen from the moment 1.2.0
    became current."""

    actual_digest = hashlib.sha256(_FROZEN_1_1_0_SCHEMA_PATH.read_bytes()).hexdigest()

    assert actual_digest == _FROZEN_SCHEMA_DIGEST_FOR_1_1_0
