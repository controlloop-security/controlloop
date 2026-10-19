"""Tests for controlloop.policy.rules.hardcoded_secrets."""

from __future__ import annotations

from _helpers import acbom, context, one_evidence

from controlloop.acbom.models import Confidence, Diagnostic, DiagnosticSeverity
from controlloop.findings.models import FindingSeverity
from controlloop.policy.engine import evaluate as engine_evaluate
from controlloop.policy.rules.hardcoded_secrets import RULE, RULE_ID, evaluate, findings


def _detection_diagnostic(
    *,
    code: str = "SECRET-CREDENTIAL-SHAPE-DETECTED",
    confidence: Confidence = Confidence.HIGH,
    path: str = "config.py",
    line_start: int = 3,
    message: str = (
        "Content matching the 'aws-access-key-id' credential shape was detected."
    ),
) -> Diagnostic:
    return Diagnostic(
        code=code,
        severity=DiagnosticSeverity.ERROR,
        message=message,
        confidence=confidence,
        incomplete=False,
        evidence=one_evidence(path=path, line_start=line_start),
    )


def _bound_exceeded_diagnostic() -> Diagnostic:
    from controlloop.acbom.models import Evidence

    return Diagnostic(
        code="INCOMPLETE-BOUND-EXCEEDED",
        severity=DiagnosticSeverity.WARNING,
        message="secret-shaped-content scanning stopped after the configured bound",
        confidence=Confidence.UNKNOWN,
        incomplete=True,
        evidence=(Evidence(adapter="secret-scan", path="<secret-scan-evaluation>"),),
    )


def _unrelated_diagnostic() -> Diagnostic:
    return Diagnostic(
        code="INCOMPLETE-DYNAMIC-REGISTRATION",
        severity=DiagnosticSeverity.WARNING,
        message="a tool is registered dynamically",
        confidence=Confidence.UNKNOWN,
        incomplete=True,
        evidence=one_evidence(path="server.py", line_start=1),
    )


class TestPositive:
    def test_a_detection_diagnostic_produces_an_observation(self) -> None:
        diagnostic = _detection_diagnostic()
        result = evaluate(context(acbom=acbom(diagnostics=(diagnostic,))))

        assert len(result) == 1
        assert result[0].rule_id == RULE_ID
        assert result[0].message == diagnostic.message
        assert result[0].evidence == diagnostic.evidence

    def test_multiple_detections_produce_multiple_observations(self) -> None:
        first = _detection_diagnostic(path="a.py", line_start=1)
        second = _detection_diagnostic(
            code="SECRET-HIGH-ENTROPY-VALUE-DETECTED",
            path="b.py",
            line_start=2,
            message=(
                "A high-entropy value assigned to a credential-like variable "
                "was detected."
            ),
        )
        result = evaluate(context(acbom=acbom(diagnostics=(first, second))))

        assert len(result) == 2

    def test_findings_produces_a_repository_scoped_finding(self) -> None:
        diagnostic = _detection_diagnostic()
        (finding,) = findings(context(acbom=acbom(diagnostics=(diagnostic,))))

        assert finding.rule_id == RULE_ID
        assert finding.affected_agent is None
        assert finding.capability_path is None
        assert finding.evidence == diagnostic.evidence

    def test_severity_scales_with_detection_confidence(self) -> None:
        high = _detection_diagnostic(confidence=Confidence.HIGH)
        medium = _detection_diagnostic(confidence=Confidence.MEDIUM, path="b.py")
        low = _detection_diagnostic(confidence=Confidence.LOW, path="c.py")

        (high_finding,) = findings(context(acbom=acbom(diagnostics=(high,))))
        (medium_finding,) = findings(context(acbom=acbom(diagnostics=(medium,))))
        (low_finding,) = findings(context(acbom=acbom(diagnostics=(low,))))

        assert high_finding.severity is FindingSeverity.CRITICAL
        assert medium_finding.severity is FindingSeverity.HIGH
        assert low_finding.severity is FindingSeverity.MEDIUM

    def test_every_finding_validates_and_is_engine_safe(self) -> None:
        """Structural proof this rule module never imports a forbidden
        name -- the same runtime check every rule in ALL_RULES passes,
        exercised directly here rather than only through the registry
        test."""

        diagnostic = _detection_diagnostic()
        result = engine_evaluate(
            (RULE,), context(acbom=acbom(diagnostics=(diagnostic,)))
        )
        assert len(result.observations) == 1


class TestNegative:
    def test_no_detection_diagnostics_produces_nothing(self) -> None:
        assert evaluate(context()) == ()
        assert findings(context()) == ()


class TestMalformed:
    def test_unrelated_diagnostic_codes_are_ignored(self) -> None:
        result = evaluate(context(acbom=acbom(diagnostics=(_unrelated_diagnostic(),))))
        assert result == ()

    def test_unrelated_and_relevant_diagnostics_together(self) -> None:
        detection = _detection_diagnostic()
        unrelated = _unrelated_diagnostic()
        result = evaluate(context(acbom=acbom(diagnostics=(detection, unrelated))))
        assert len(result) == 1
        assert result[0].message == detection.message


class TestBoundary:
    def test_bound_exceeded_diagnostic_surfaces_as_an_advisory_observation(
        self,
    ) -> None:
        detection = _detection_diagnostic()
        bound = _bound_exceeded_diagnostic()
        result = evaluate(context(acbom=acbom(diagnostics=(detection, bound))))

        assert len(result) == 2
        messages = {observation.message for observation in result}
        assert any("stopped before covering" in message for message in messages)

    def test_bound_exceeded_diagnostic_from_a_different_adapter_is_ignored(
        self,
    ) -> None:
        from controlloop.acbom.models import Evidence

        other_bound = Diagnostic(
            code="INCOMPLETE-BOUND-EXCEEDED",
            severity=DiagnosticSeverity.WARNING,
            message="a different pass hit its own bound",
            confidence=Confidence.UNKNOWN,
            incomplete=True,
            evidence=(
                Evidence(adapter="policy.engine", path="<policy-engine-evaluation>"),
            ),
        )
        result = evaluate(context(acbom=acbom(diagnostics=(other_bound,))))
        assert result == ()


class TestDeterminism:
    def test_repeated_evaluation_is_identical(self) -> None:
        diagnostic = _detection_diagnostic()
        built_context = context(acbom=acbom(diagnostics=(diagnostic,)))

        first = evaluate(built_context)
        second = evaluate(built_context)
        assert first == second

        first_findings = findings(built_context)
        second_findings = findings(built_context)
        assert first_findings == second_findings

    def test_observation_order_is_independent_of_diagnostic_order(self) -> None:
        first = _detection_diagnostic(path="a.py", line_start=1)
        second = _detection_diagnostic(path="b.py", line_start=2)

        forward = evaluate(context(acbom=acbom(diagnostics=(first, second))))
        backward = evaluate(context(acbom=acbom(diagnostics=(second, first))))

        assert forward == backward
