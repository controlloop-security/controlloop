"""Tests for the packaged `ScanReport` JSON Schema.

Mirrors
`tests/acbom/test_versioning.py::test_packaged_schema_matches_its_golden_digest`
exactly: this schema file's content is tied to a committed digest for its
declared version; any edit to the file changes the digest, and this test
then requires a deliberate update -- which itself requires deciding whether
the change is a MAJOR/MINOR/PATCH bump, not a silent drift.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import cast

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
from test_report import _report

from controlloop.reporting.report import CURRENT_REPORT_SCHEMA_VERSION

_CLI_ROOT = Path(__file__).resolve().parents[2]
_SCHEMA_PATH = _CLI_ROOT / "src/controlloop/schemas/report/1.2.0/report.schema.json"

# Regenerate by hashing the schema file after a deliberate, version-bumped
# change: `hashlib.sha256(_SCHEMA_PATH.read_bytes()).hexdigest()`.
# 1.1.0 (from 1.0.0) changed `suppressions`'s element type from a plain,
# always-empty `tuple[str, ...]` placeholder to a real
# `tuple[SuppressionRecord, ...]`; see `controlloop.reporting.report`'s own
# "Why the schema version is 1.1.0, not 1.0.0" for why this is treated as
# MINOR rather than MAJOR. The 1.0.0 file itself is kept unmodified at
# `src/controlloop/schemas/report/1.0.0/`, the same two-version precedent
# `schemas/evidence/`/`schemas/baseline/` already established -- the
# schemas.controlloop.dev -> .ai domain migration applies only to this, the
# current version; 1.0.0 stays frozen at its original domain. 1.2.0 (from
# 1.1.0) added an optional `authority_delta`, left out when empty; 1.1.0
# stays frozen beside it.
_GOLDEN_SCHEMA_DIGEST_FOR_1_2_0 = (
    "679da2f55bdf460a94dd5f95b22b01d7ba59d1817ca40e9fbbe8d849a215920b"
)


def test_packaged_schema_matches_its_golden_digest() -> None:
    actual_digest = hashlib.sha256(_SCHEMA_PATH.read_bytes()).hexdigest()

    assert actual_digest == _GOLDEN_SCHEMA_DIGEST_FOR_1_2_0, (
        "the packaged report schema file changed without updating the "
        "golden digest -- decide whether this is a MAJOR/MINOR/PATCH "
        "bump before updating this constant"
    )


def test_schema_declares_the_current_report_schema_version_in_its_id() -> None:
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))

    assert CURRENT_REPORT_SCHEMA_VERSION in cast(str, schema["$id"])


def test_a_real_report_validates_against_the_packaged_schema() -> None:
    """Validated in CI -- run here, in this repository's own test suite,
    against a real generated `ScanReport` instance, not only against the
    project's own Pydantic tooling."""

    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)

    report = _report()
    document = json.loads(report.model_dump_json())

    validator.validate(document)


def test_a_report_with_every_optional_field_none_or_empty_still_validates() -> None:
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)

    report = _report(
        blast_radius=None, material_changes=None, findings=None, diagnostics=()
    )
    document = json.loads(report.model_dump_json())

    validator.validate(document)


def test_schema_rejects_an_undeclared_property() -> None:
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)

    report = _report()
    document = json.loads(report.model_dump_json())
    document["unexpected_field"] = "should not be allowed"

    errors = list(validator.iter_errors(document))
    assert errors
