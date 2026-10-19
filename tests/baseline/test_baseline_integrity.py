"""Tests for `controlloop.baseline.integrity`.

Mirrors `tests/acbom/test_versioning.py`'s version-drift and golden-digest
style, extended with the tamper/truncation detection this module adds on top
of what the ACBOM's own `load_acbom_document` does.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from controlloop.baseline import (
    BaselineIntegrityError,
    load_baseline_document,
)
from controlloop.exit_codes import ExitCode

_CLI_ROOT = Path(__file__).resolve().parents[2]
_SCHEMA_PATH = _CLI_ROOT / "src/controlloop/schemas/baseline/1.0.0/baseline.schema.json"
_FIXTURE_PATH = _CLI_ROOT / "tests/fixtures/baseline/minimal-baseline.json"

# Regenerate by hashing the schema file after a deliberate, version-bumped
# change: `hashlib.sha256(_SCHEMA_PATH.read_bytes()).hexdigest()`.
_GOLDEN_SCHEMA_DIGEST_FOR_1_0_0 = (
    "6be9b28500b7f05c932007574c67d907c2cb15b15b2865d65ccc84bf52d20b24"
)


def _assert_integrity_error(
    callable_under_test: object, *args: object, **kwargs: object
) -> None:
    with pytest.raises(BaselineIntegrityError) as excinfo:
        callable_under_test(*args, **kwargs)  # type: ignore[operator]

    assert excinfo.value.exit_code is ExitCode.INVALID_INPUT


class TestLoadBaselineDocumentPositive:
    def test_reads_the_real_fixture_with_the_default_reader_version(self) -> None:
        """This fixture predates the 1.1.0 minor bump (it carries no
        `provenance` field at all) but must still be readable by the
        default, current reader version with no explicit `reader_version`
        argument -- the ordinary, no-flag call every real caller makes.
        Asserted against the fixture's own literal `"1.0.0"` rather than
        `CURRENT_BASELINE_SCHEMA_VERSION` (now `"1.1.0"`) precisely because
        this test's point is that the two may differ."""
        raw = _FIXTURE_PATH.read_bytes()

        document = load_baseline_document(raw)

        assert document.schema_version == "1.0.0"

    def test_accepts_str_input_as_well_as_bytes(self) -> None:
        """Asserted against the fixture's own literal `"1.0.0"`, not
        `CURRENT_BASELINE_SCHEMA_VERSION` (now `"1.1.0"`) -- see
        `test_reads_the_real_fixture_with_the_default_reader_version`."""
        raw_text = _FIXTURE_PATH.read_text(encoding="utf-8")

        document = load_baseline_document(raw_text)

        assert document.schema_version == "1.0.0"

    def test_version_drift_fixture_reads_an_older_real_document(self) -> None:
        """The version-drift case: a newer-minor-compatible reader still
        reads a real, older document -- mirrors
        `test_version_drift_fixture_reads_an_older_real_document` in
        `tests/acbom/test_versioning.py`."""
        raw = _FIXTURE_PATH.read_bytes()

        document = load_baseline_document(raw, reader_version="1.9.0")

        assert document.schema_version == "1.0.0"


class TestLoadBaselineDocumentTruncated:
    """A truncated document is rejected."""

    def test_truncated_json_is_rejected(self) -> None:
        raw = _FIXTURE_PATH.read_bytes()
        truncated = raw[: len(raw) // 2]

        _assert_integrity_error(load_baseline_document, truncated)

    def test_empty_input_is_rejected(self) -> None:
        _assert_integrity_error(load_baseline_document, b"")

    def test_garbage_non_json_input_is_rejected(self) -> None:
        _assert_integrity_error(load_baseline_document, b"not json at all {{{")


class TestLoadBaselineDocumentMalformed:
    """A malformed document is rejected."""

    def test_missing_schema_version_is_rejected(self) -> None:
        fixture = json.loads(_FIXTURE_PATH.read_text())
        del fixture["schema_version"]

        _assert_integrity_error(load_baseline_document, json.dumps(fixture))

    def test_non_object_json_is_rejected(self) -> None:
        _assert_integrity_error(load_baseline_document, json.dumps([1, 2, 3]))

    def test_missing_required_field_is_rejected(self) -> None:
        fixture = json.loads(_FIXTURE_PATH.read_text())
        del fixture["acbom_digest"]

        _assert_integrity_error(load_baseline_document, json.dumps(fixture))

    def test_invalid_digest_format_is_rejected(self) -> None:
        fixture = json.loads(_FIXTURE_PATH.read_text())
        fixture["digest"] = "not-a-sha256-digest"

        _assert_integrity_error(load_baseline_document, json.dumps(fixture))

    def test_different_major_version_is_rejected_before_any_full_parse(self) -> None:
        """Rejected before any full parse is attempted. Corrupt the
        document's actual content too, so a full parse attempt would raise a
        *different* error than `BaselineIntegrityError`'s version-gate
        message if the version gate were skipped -- mirrors
        `test_incompatible_major_never_completes_a_full_parse` in
        `tests/acbom/test_versioning.py`."""
        fixture = json.loads(_FIXTURE_PATH.read_text())
        fixture["schema_version"] = "2.0.0"
        del fixture["effective_authority"]

        with pytest.raises(BaselineIntegrityError) as excinfo:
            load_baseline_document(json.dumps(fixture))

        assert excinfo.value.exit_code is ExitCode.INVALID_INPUT
        assert "2.0.0" in str(excinfo.value)

    def test_newer_minor_within_the_same_major_is_rejected(self) -> None:
        """A newer minor may carry an additive field this reader does
        not know about, and `extra="forbid"` would reject it uncleanly
        -- so it is rejected here, cleanly, first (before this reader's
        own field set is even consulted, since the version gate runs
        against the raw envelope before any full parse is attempted)."""
        fixture = json.loads(_FIXTURE_PATH.read_text())
        fixture["schema_version"] = "1.5.0"

        _assert_integrity_error(
            load_baseline_document, json.dumps(fixture), reader_version="1.4.0"
        )


class TestLoadBaselineDocumentTampered:
    """The tamper case: structurally valid, but the declared digest does not
    match a fresh recomputation."""

    def test_tampered_commit_is_detected(self) -> None:
        fixture = json.loads(_FIXTURE_PATH.read_text())
        fixture["repository"]["commit"] = "tampered-commit-value"

        _assert_integrity_error(load_baseline_document, json.dumps(fixture))

    def test_tampered_effective_authority_resource_is_detected(self) -> None:
        fixture = json.loads(_FIXTURE_PATH.read_text())
        fixture["effective_authority"][0]["resource_id"] = f"clp:tool:sha256:{'9' * 64}"

        _assert_integrity_error(load_baseline_document, json.dumps(fixture))

    def test_tampered_digest_itself_is_detected(self) -> None:
        fixture = json.loads(_FIXTURE_PATH.read_text())
        fixture["digest"] = f"sha256:{'1' * 64}"

        _assert_integrity_error(load_baseline_document, json.dumps(fixture))

    def test_tampered_acbom_digest_is_detected(self) -> None:
        """The recorded ACBOM digest is itself covered by the baseline's own
        integrity digest -- tampering with which ACBOM digest a baseline
        claims to describe is exactly the kind of tamper this control exists
        to catch."""
        fixture = json.loads(_FIXTURE_PATH.read_text())
        fixture["acbom_digest"] = f"sha256:{'9' * 64}"

        _assert_integrity_error(load_baseline_document, json.dumps(fixture))


def test_packaged_schema_matches_its_golden_digest() -> None:
    """A breaking schema change without a version increment fails CI --
    mirrors `test_packaged_schema_matches_its_golden_digest` in
    `tests/acbom/test_versioning.py`."""
    actual_digest = hashlib.sha256(_SCHEMA_PATH.read_bytes()).hexdigest()

    assert actual_digest == _GOLDEN_SCHEMA_DIGEST_FOR_1_0_0, (
        "the packaged baseline schema file changed without updating the "
        "golden digest -- see docs/reference/schema-versioning.md and "
        "docs/reference/baseline-artifact-format.md before updating this "
        "constant"
    )
