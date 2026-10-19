"""Tests for the packaged `EvidenceArtifact` JSON Schema.

Mirrors `tests/reporting/test_report_schema.py` and, before that,
`tests/acbom/test_versioning.py::test_packaged_schema_matches_its_golden_digest`
exactly: this schema file's content is tied to a committed digest for its
declared version; any edit to the file changes the digest, and this test
then requires a deliberate update.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import cast

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
from test_evidence import _artifact

from controlloop.reporting.evidence import (
    CURRENT_EVIDENCE_SCHEMA_VERSION,
    EvidenceArtifact,
)

_CLI_ROOT = Path(__file__).resolve().parents[2]
_SCHEMA_PATH = _CLI_ROOT / "src/controlloop/schemas/evidence/1.5.0/evidence.schema.json"

# Regenerate by hashing the schema file after a deliberate, version-bumped
# change: `hashlib.sha256(_SCHEMA_PATH.read_bytes()).hexdigest()`.
# 1.1.0 (from 1.0.0) added two new, defaulted, backward-compatible fields,
# `completeness_enforcement`/`completeness_enforcement_source`. 1.2.0 (from
# 1.1.0) changed `suppressions`'s element type from a plain, always-empty
# `tuple[str, ...]` placeholder to a real `tuple[SuppressionRecord, ...]`;
# see `controlloop.reporting.evidence`'s own "Why the schema version is
# 1.2.0, not 1.1.0" for why this is treated as MINOR rather than MAJOR.
# Every prior version's own file is kept unmodified at its own
# `src/controlloop/schemas/evidence/<version>/` directory, the same
# precedent `schemas/baseline/` already established -- the
# schemas.controlloop.dev -> .ai domain migration applies only to this, the
# current version; 1.0.0 and 1.1.0 stay frozen at their original domain.
# 1.4.0 (from 1.3.0) added an optional `authority_delta`, left out when
# empty. 1.5.0 (from 1.4.0) added sanction judgments in the optional `team`
# block.
_GOLDEN_SCHEMA_DIGEST_FOR_1_5_0 = (
    "b9d3d63100afd195df889e65864ca17db50516f0e02a4603900f1fc13e702e54"
)


def test_packaged_schema_matches_its_golden_digest() -> None:
    actual_digest = hashlib.sha256(_SCHEMA_PATH.read_bytes()).hexdigest()

    assert actual_digest == _GOLDEN_SCHEMA_DIGEST_FOR_1_5_0, (
        "the packaged evidence schema file changed without updating the "
        "golden digest -- decide whether this is a MAJOR/MINOR/PATCH "
        "bump before updating this constant"
    )


def test_the_packaged_schema_still_matches_the_model_it_describes() -> None:
    """The guard the digest test alone does not provide.

    A golden digest catches an *edit* to the packaged file. It cannot
    catch the opposite failure: the model changing while the file stays
    frozen, which leaves a schema that describes a shape the code no
    longer produces.

    That failure had already happened once. Making `Finding.affected_agent`
    and `Finding.capability_path` optional meant a repository-scoped finding
    -- a hardcoded secret in a shared file, with no single affected agent --
    became a legal `EvidenceArtifact`. The packaged 1.2.0 schema was never
    regenerated, so it still required both fields, and a real artifact
    containing such a finding would have failed validation against the
    schema this repository ships for it. Nothing caught it because
    `test_a_real_artifact_validates_against_the_packaged_schema` uses an
    agent-scoped finding, where the stale requirement never bites.

    1.3.0 is generated from the current model, which corrects that as a
    side effect. This test is what stops it recurring: it regenerates from
    the model and compares, so the next model change that is not
    accompanied by a schema regeneration fails here rather than in a
    customer's validator.
    """

    packaged = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    generated = EvidenceArtifact.model_json_schema()

    assert packaged["$defs"] == generated["$defs"]
    assert packaged["properties"] == generated["properties"]
    assert packaged["required"] == generated["required"]


def test_a_repository_scoped_finding_validates() -> None:
    """The case the stale 1.2.0 schema would have rejected. See the test
    above for the history."""

    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)

    artifact = _artifact()
    assert artifact.findings is not None
    finding = artifact.findings[0].model_copy(
        update={"affected_agent": None, "capability_path": None}
    )
    document = json.loads(
        artifact.model_copy(update={"findings": (finding,)}).model_dump_json()
    )

    validator.validate(document)


def test_schema_declares_the_current_evidence_schema_version_in_its_id() -> None:
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))

    assert CURRENT_EVIDENCE_SCHEMA_VERSION in cast(str, schema["$id"])


def test_a_real_artifact_validates_against_the_packaged_schema() -> None:
    """Validated in CI -- run here, in this repository's own test suite,
    against a real generated `EvidenceArtifact` instance, not only against
    the project's own Pydantic tooling."""

    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)

    artifact = _artifact()
    document = json.loads(artifact.model_dump_json())

    validator.validate(document)


def test_an_artifact_with_no_baseline_still_validates() -> None:
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)

    artifact = _artifact(
        baseline_digest=None,
        baseline_provenance=None,
        effective_authority_diff=None,
        findings=None,
    )
    document = json.loads(artifact.model_dump_json())

    validator.validate(document)


def test_schema_rejects_an_undeclared_property() -> None:
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)

    artifact = _artifact()
    document = json.loads(artifact.model_dump_json())
    document["unexpected_field"] = "should not be allowed"

    errors = list(validator.iter_errors(document))
    assert errors
