"""Tests for controlloop.reporting.evidence."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError
from test_terminal import _finding

from controlloop.acbom import (
    Confidence,
    Diagnostic,
    DiagnosticSeverity,
    EdgeType,
    Evidence,
    Generator,
)
from controlloop.baseline.models import ApprovalProvenance
from controlloop.capability.models import EffectiveAuthorityEntry
from controlloop.config import ConfigSource
from controlloop.diff.models import ChangeKind, EffectiveAuthorityChange
from controlloop.policy.thresholds import CompletenessEnforcement
from controlloop.reporting.evidence import (
    CURRENT_EVIDENCE_SCHEMA_VERSION,
    EvidenceArtifact,
    EvidenceVersions,
)
from controlloop.reporting.terminal import Verdict

_EVIDENCE = (Evidence(adapter="mcp", path="agent.json"),)
_AGENT_ID = f"clp:agent:sha256:{'a' * 64}"
_RESOURCE_ID = f"clp:resource:sha256:{'c' * 64}"


def _evidence_versions(**overrides: object) -> EvidenceVersions:
    payload: dict[str, object] = {
        "scanner": Generator(name="controlloop", version="0.1.0"),
        "acbom_schema_version": "1.0.0",
        "evidence_schema_version": CURRENT_EVIDENCE_SCHEMA_VERSION,
    }
    payload.update(overrides)
    return EvidenceVersions.model_validate(payload)


def _authority_entry(**overrides: object) -> EffectiveAuthorityEntry:
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "agent_id": _AGENT_ID,
        "action": EdgeType.WRITES,
        "resource_id": _RESOURCE_ID,
        "confidence": Confidence.HIGH,
        "evidence": _EVIDENCE,
    }
    payload.update(overrides)
    return EffectiveAuthorityEntry.model_validate(payload)


def _authority_change(**overrides: object) -> EffectiveAuthorityChange:
    payload: dict[str, object] = {
        "kind": ChangeKind.ADDED,
        "agent_id": _AGENT_ID,
        "action": EdgeType.WRITES,
        "resource_id": _RESOURCE_ID,
        "before": None,
        "after": _authority_entry(),
    }
    payload.update(overrides)
    return EffectiveAuthorityChange.model_validate(payload)


def _diagnostic(**overrides: object) -> Diagnostic:
    payload: dict[str, object] = {
        "code": "INCOMPLETE-BOUND-EXCEEDED",
        "severity": DiagnosticSeverity.WARNING,
        "message": "a bound was exceeded during transitive traversal",
        "confidence": Confidence.UNKNOWN,
        "incomplete": True,
        "evidence": _EVIDENCE,
    }
    payload.update(overrides)
    return Diagnostic.model_validate(payload)


def _provenance(**overrides: object) -> ApprovalProvenance:
    payload: dict[str, object] = {
        "approver": "reviewer@example.com",
        "approver_source": "supplied",
        "approved_at": "2026-08-01T00:00:00Z",
        "approved_commit": "abc1234",
    }
    payload.update(overrides)
    return ApprovalProvenance.model_validate(payload)


def _artifact(**overrides: object) -> EvidenceArtifact:
    payload: dict[str, object] = {
        "schema_version": CURRENT_EVIDENCE_SCHEMA_VERSION,
        "acbom_digest": f"sha256:{'0' * 64}",
        "baseline_digest": f"sha256:{'1' * 64}",
        "baseline_provenance": _provenance(),
        "effective_authority_diff": (_authority_change(),),
        "findings": (_finding(),),
        "completeness": (),
        "verdict": Verdict.REVIEW_REQUIRED,
        "versions": _evidence_versions(),
    }
    payload.update(overrides)
    return EvidenceArtifact.model_validate(payload)


class TestFieldPresence:
    """The artifact contains ACBOM digest, baseline digest and
    provenance, effective authority diff, findings, suppressions,
    completeness state, verdict, and all component versions."""

    def test_every_req1_field_is_present_on_a_real_artifact(self) -> None:
        artifact = _artifact()

        assert artifact.acbom_digest.startswith("sha256:")
        assert artifact.baseline_digest is not None
        assert artifact.baseline_provenance is not None
        assert artifact.effective_authority_diff is not None
        assert artifact.findings is not None
        assert artifact.suppressions == ()
        assert artifact.completeness == ()
        assert artifact.completeness_enforcement is CompletenessEnforcement.WARN
        assert artifact.completeness_enforcement_source is ConfigSource.DEFAULT
        assert artifact.verdict is Verdict.REVIEW_REQUIRED
        assert artifact.versions.scanner.name == "controlloop"

    def test_completeness_carries_real_diagnostics_when_present(self) -> None:
        artifact = _artifact(completeness=(_diagnostic(),))

        assert len(artifact.completeness) == 1
        assert artifact.completeness[0].code == "INCOMPLETE-BOUND-EXCEEDED"

    def test_no_baseline_means_no_digest_provenance_or_diff(self) -> None:
        artifact = _artifact(
            baseline_digest=None,
            baseline_provenance=None,
            effective_authority_diff=None,
        )

        assert artifact.baseline_digest is None
        assert artifact.baseline_provenance is None
        assert artifact.effective_authority_diff is None

    def test_baseline_without_provenance_is_a_valid_state(self) -> None:
        """A real baseline can legitimately have no provenance --
        distinct from having no baseline at all."""

        artifact = _artifact(baseline_provenance=None)

        assert artifact.baseline_digest is not None
        assert artifact.baseline_provenance is None
        assert artifact.effective_authority_diff is not None


class TestCompletenessEnforcementField:
    """`completeness_enforcement`/
    `completeness_enforcement_source` state the active setting on the
    gate result. Defaults on a bare `_artifact()` (no override supplied)
    prove the MINOR-bump backward-compatibility claim in this module's
    own docstring -- a document built without these keys at all still
    resolves them."""

    def test_defaults_when_not_supplied(self) -> None:
        artifact = _artifact()

        assert artifact.completeness_enforcement is CompletenessEnforcement.WARN
        assert artifact.completeness_enforcement_source is ConfigSource.DEFAULT

    def test_explicit_enforce_value_round_trips(self) -> None:
        artifact = _artifact(
            completeness_enforcement=CompletenessEnforcement.ENFORCE,
            completeness_enforcement_source=ConfigSource.REPOSITORY_FILE,
        )

        assert artifact.completeness_enforcement is CompletenessEnforcement.ENFORCE
        assert artifact.completeness_enforcement_source is ConfigSource.REPOSITORY_FILE


class TestDiffRequiresABaseline:
    """The cross-field invariant: `baseline_digest` and
    `effective_authority_diff` are both `None` or both present."""

    def test_digest_without_diff_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="baseline_digest"):
            _artifact(effective_authority_diff=None)

    def test_diff_without_digest_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="baseline_digest"):
            _artifact(baseline_digest=None)


class TestNotEvaluatedVersusConfirmedZero:
    def test_findings_none_differs_from_a_real_empty_tuple(self) -> None:
        not_evaluated = _artifact(findings=None)
        evaluated_empty = _artifact(findings=())

        assert not_evaluated.findings is None
        assert evaluated_empty.findings == ()


class TestDeterminism:
    """Identical input produces byte-identical JSON."""

    def test_identical_input_produces_identical_json(self) -> None:
        first = _artifact().model_dump_json()
        second = _artifact().model_dump_json()

        assert first == second

    def test_top_level_key_order_matches_field_declaration_order(self) -> None:
        artifact = _artifact()
        raw = json.loads(artifact.model_dump_json())

        assert list(raw.keys()) == [
            "schema_version",
            "acbom_digest",
            "baseline_digest",
            "baseline_provenance",
            "effective_authority_diff",
            "findings",
            "completeness",
            "completeness_enforcement",
            "completeness_enforcement_source",
            "suppressions",
            # Declared between `suppressions` and `verdict` because it belongs
            # with the other *inputs* to the verdict, not after the verdict it
            # helped produce.
            "team",
            "verdict",
            "versions",
        ]


class TestPrivacy:
    """The artifact never contains source content or secret
    values. This model reads no raw content of its own -- see
    `test_redaction.py`'s structural canary."""

    def test_round_trip_preserves_only_declared_fields(self) -> None:
        artifact = _artifact()
        raw = json.loads(artifact.model_dump_json())

        assert set(raw.keys()) == {
            "schema_version",
            "acbom_digest",
            "baseline_digest",
            "baseline_provenance",
            "effective_authority_diff",
            "findings",
            "completeness",
            "completeness_enforcement",
            "completeness_enforcement_source",
            "suppressions",
            "team",
            "verdict",
            "versions",
        }
