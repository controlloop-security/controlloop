"""Tests for controlloop.reporting.report."""

from __future__ import annotations

import json

from test_terminal import _blast_radius, _finding, _material_change, _material_summary

from controlloop.acbom import (
    Confidence,
    Diagnostic,
    DiagnosticSeverity,
    Evidence,
    Generator,
)
from controlloop.policy.suppressions import SuppressionRecord, SuppressionStatus
from controlloop.reporting.report import (
    CURRENT_REPORT_SCHEMA_VERSION,
    ReportVersions,
    ScanReport,
)
from controlloop.reporting.terminal import Verdict

_SUPPRESSION_TARGET = "clp:finding:sha256:" + "a" * 64


def _suppression_record(**overrides: object) -> SuppressionRecord:
    payload: dict[str, object] = {
        "rule_id": "policy.undeclared-tools",
        "target": _SUPPRESSION_TARGET,
        "reason": "reviewed and accepted by security team",
        "expires_at": "2099-01-01",
        "status": SuppressionStatus.ACTIVE,
    }
    payload.update(overrides)
    return SuppressionRecord.model_validate(payload)


_EVIDENCE = (Evidence(adapter="mcp", path="agent.json"),)


def _versions(**overrides: object) -> ReportVersions:
    payload: dict[str, object] = {
        "scanner": Generator(name="controlloop", version="0.1.0"),
        "acbom_schema_version": "1.0.0",
        "report_schema_version": CURRENT_REPORT_SCHEMA_VERSION,
    }
    payload.update(overrides)
    return ReportVersions.model_validate(payload)


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


def _report(**overrides: object) -> ScanReport:
    payload: dict[str, object] = {
        "schema_version": CURRENT_REPORT_SCHEMA_VERSION,
        "verdict": Verdict.REVIEW_REQUIRED,
        "blast_radius": _blast_radius(),
        "material_changes": _material_summary(_material_change()),
        "findings": (_finding(),),
        "diagnostics": (),
        "versions": _versions(),
    }
    payload.update(overrides)
    return ScanReport.model_validate(payload)


class TestFieldPresence:
    """The report contains verdict, blast-radius statement,
    material changes, findings, completeness state, suppressions,
    versions, and diagnostics."""

    def test_every_req2_field_is_present_on_a_real_report(self) -> None:
        report = _report()

        assert report.verdict is Verdict.REVIEW_REQUIRED
        assert report.blast_radius is not None
        assert report.material_changes is not None
        assert report.findings is not None
        assert report.diagnostics == ()
        assert report.suppressions == ()
        assert report.versions.scanner.name == "controlloop"
        assert report.incomplete is False

    def test_incomplete_is_true_whenever_diagnostics_are_present(self) -> None:
        report = _report(diagnostics=(_diagnostic(),))

        assert report.incomplete is True

    def test_suppressions_default_empty_when_none_declared(self) -> None:
        report = _report()

        assert report.suppressions == ()

    def test_suppressions_field_carries_real_suppression_records(self) -> None:
        record = _suppression_record()
        report = _report(suppressions=(record,))

        assert report.suppressions == (record,)
        assert report.suppressions[0].status is SuppressionStatus.ACTIVE


class TestNotEvaluatedVersusConfirmedZero:
    """The same "Unknown, never omitted" distinction
    `controlloop.reporting.terminal` already draws, applied to the
    JSON envelope's own optional fields."""

    def test_material_changes_none_differs_from_a_real_empty_summary(self) -> None:
        not_evaluated = _report(material_changes=None)
        evaluated_empty = _report(material_changes=_material_summary())

        assert not_evaluated.material_changes is None
        assert evaluated_empty.material_changes is not None
        assert evaluated_empty.material_changes.is_empty

    def test_findings_none_differs_from_a_real_empty_tuple(self) -> None:
        not_evaluated = _report(findings=None)
        evaluated_empty = _report(findings=())

        assert not_evaluated.findings is None
        assert evaluated_empty.findings == ()


class TestDeterminism:
    """Identical input produces byte-identical JSON,
    with canonical (class-declaration-order) key ordering."""

    def test_identical_input_produces_identical_json(self) -> None:
        first = _report().model_dump_json()
        second = _report().model_dump_json()

        assert first == second

    def test_top_level_key_order_matches_field_declaration_order(self) -> None:
        report = _report()
        raw = json.loads(report.model_dump_json())

        assert list(raw.keys()) == [
            "schema_version",
            "verdict",
            "blast_radius",
            "material_changes",
            "findings",
            "diagnostics",
            "suppressions",
            "versions",
        ]


class TestPrivacy:
    """The report never contains source content or secret
    values. This model reads no raw content of its own -- see
    `test_redaction.py`'s structural canary -- so this asserts the
    positive case: ordinary sanitized field values round-trip intact
    with nothing extraneous injected."""

    def test_round_trip_preserves_only_declared_fields(self) -> None:
        report = _report()
        raw = json.loads(report.model_dump_json())

        assert set(raw.keys()) == {
            "schema_version",
            "verdict",
            "blast_radius",
            "material_changes",
            "findings",
            "diagnostics",
            "suppressions",
            "versions",
        }
