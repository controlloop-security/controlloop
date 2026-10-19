"""Tests for controlloop.policy.models -- data-shape validation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from controlloop.acbom.models import (
    Confidence,
    Diagnostic,
    DiagnosticSeverity,
    Evidence,
)
from controlloop.policy.models import (
    EvaluationBounds,
    EvaluationResult,
    RuleObservation,
)

_EVIDENCE = (Evidence(adapter="fixture", path="a.json"),)


def _diagnostic(*, incomplete: bool) -> Diagnostic:
    return Diagnostic(
        code="INCOMPLETE-BOUND-EXCEEDED" if incomplete else "ORDINARY-INFO",
        severity=DiagnosticSeverity.WARNING,
        message="a diagnostic",
        confidence=Confidence.UNKNOWN if incomplete else Confidence.HIGH,
        incomplete=incomplete,
        evidence=_EVIDENCE,
    )


class TestRuleObservation:
    def test_constructs_with_required_fields(self) -> None:
        observation = RuleObservation(
            rule_id="fixture.rule",
            message="something worth reporting",
            evidence=_EVIDENCE,
        )

        assert observation.rule_id == "fixture.rule"
        assert observation.evidence == _EVIDENCE

    def test_rejects_unknown_extra_field(self) -> None:
        with pytest.raises(ValidationError):
            RuleObservation.model_validate(
                {
                    "rule_id": "fixture.rule",
                    "message": "x",
                    "evidence": [{"adapter": "fixture", "path": "a.json"}],
                    "severity": "should not be accepted",
                }
            )

    def test_rejects_empty_evidence(self) -> None:
        with pytest.raises(ValidationError):
            RuleObservation(rule_id="fixture.rule", message="x", evidence=())

    def test_is_frozen(self) -> None:
        observation = RuleObservation(
            rule_id="fixture.rule", message="x", evidence=_EVIDENCE
        )
        with pytest.raises(ValidationError):
            observation.message = "changed"


class TestEvaluationBounds:
    def test_defaults_are_positive(self) -> None:
        bounds = EvaluationBounds()

        assert bounds.max_rules > 0
        assert bounds.max_observations > 0

    @pytest.mark.parametrize("max_rules", [0, -1])
    def test_rejects_non_positive_max_rules(self, max_rules: int) -> None:
        with pytest.raises(ValueError, match="max_rules must be a positive integer"):
            EvaluationBounds(max_rules=max_rules)

    @pytest.mark.parametrize("max_observations", [0, -1])
    def test_rejects_non_positive_max_observations(self, max_observations: int) -> None:
        with pytest.raises(
            ValueError, match="max_observations must be a positive integer"
        ):
            EvaluationBounds(max_observations=max_observations)


class TestEvaluationResult:
    def test_is_incomplete_false_with_no_diagnostics(self) -> None:
        result = EvaluationResult(observations=(), diagnostics=())

        assert result.is_incomplete is False

    def test_is_incomplete_false_when_no_diagnostic_is_incomplete(self) -> None:
        result = EvaluationResult(
            observations=(), diagnostics=(_diagnostic(incomplete=False),)
        )

        assert result.is_incomplete is False

    def test_is_incomplete_true_when_any_diagnostic_is_incomplete(self) -> None:
        result = EvaluationResult(
            observations=(),
            diagnostics=(_diagnostic(incomplete=False), _diagnostic(incomplete=True)),
        )

        assert result.is_incomplete is True
