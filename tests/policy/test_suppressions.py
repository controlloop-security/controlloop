"""Tests for controlloop.policy.suppressions.

Mirrors `test_policy_thresholds.py`'s own `_finding`/`_capability_path`
helper pattern, with `_capability_path`/`_finding` parameterized over
which tool/edge pair to use so the "cannot broaden beyond its declared
scope" fixture has two genuinely different findings to distinguish
between, not just two copies of the same one.
"""

from __future__ import annotations

from datetime import date
from typing import ClassVar

import pytest
from pydantic import ValidationError

from controlloop.acbom.models import Confidence, EdgeType, Evidence, NodeType
from controlloop.capability.models import CapabilityPath, PathHop
from controlloop.findings.models import (
    CURRENT_FINDING_SCHEMA_VERSION,
    Finding,
    FindingChangeState,
    FindingSeverity,
)
from controlloop.manifest.models import Suppression
from controlloop.policy.rules.capability_ceiling import RULE_ID as CEILING_RULE_ID
from controlloop.policy.suppressions import (
    SuppressionOutcome,
    SuppressionRecord,
    SuppressionStatus,
    apply_suppressions,
)

_AGENT_ID = f"clp:agent:sha256:{'a' * 64}"
_TOOL_A_ID = f"clp:tool:sha256:{'b' * 64}"
_TOOL_B_ID = f"clp:tool:sha256:{'c' * 64}"
_EDGE_A_ID = f"clp:edge:sha256:{'d' * 64}"
_EDGE_B_ID = f"clp:edge:sha256:{'e' * 64}"
_EVIDENCE = (Evidence(adapter="mcp", path="agent.json", line_start=3, line_end=4),)

_REFERENCE_DATE = date(2026, 8, 21)


def _capability_path(*, tool_id: str, edge_id: str) -> CapabilityPath:
    return CapabilityPath(
        schema_version="1.0.0",
        agent_id=_AGENT_ID,
        target_id=tool_id,
        target_type=NodeType.TOOL,
        hops=(
            PathHop(
                edge_id=edge_id,
                edge_type=EdgeType.INVOKES,
                source_id=_AGENT_ID,
                target_id=tool_id,
                evidence=_EVIDENCE,
            ),
        ),
        confidence=Confidence.HIGH,
    )


def _finding(
    *,
    rule_id: str = "policy.undeclared-tools",
    tool_id: str = _TOOL_A_ID,
    edge_id: str = _EDGE_A_ID,
    severity: FindingSeverity = FindingSeverity.HIGH,
    confidence: Confidence = Confidence.HIGH,
) -> Finding:
    """Deliberately never given an explicit `id=` -- `Finding.id` must be
    computed for real via `controlloop.findings.identity.finding_id` so
    every test below exercises the exact same stable-identity scheme
    `apply_suppressions` matches against in production, not a
    hand-typed stand-in digest."""

    from controlloop.findings.identity import finding_id

    capability_path = _capability_path(tool_id=tool_id, edge_id=edge_id)
    return Finding(
        schema_version=CURRENT_FINDING_SCHEMA_VERSION,
        id=finding_id(
            rule_id=rule_id, affected_agent=_AGENT_ID, capability_path=capability_path
        ),
        rule_id=rule_id,
        rule_version="1.0.0",
        message="a tool is reachable",
        severity=severity,
        confidence=confidence,
        affected_agent=_AGENT_ID,
        evidence=_EVIDENCE,
        capability_path=capability_path,
        change_state=FindingChangeState.ADDED,
        remediation="declare the tool in controlloop.yaml",
        documentation_url="https://docs.controlloop.dev/rules/undeclared-tools",
    )


def _suppression(
    *,
    rule_id: str = "policy.undeclared-tools",
    target: str,
    reason: str = "reviewed and accepted",
    expires_at: str = "2099-01-01",
) -> Suppression:
    return Suppression(
        rule_id=rule_id, target=target, reason=reason, expires_at=expires_at
    )


class TestApplySuppressionsPositive:
    def test_active_suppression_removes_its_exact_target_finding(self) -> None:
        finding = _finding()
        suppression = _suppression(target=finding.id)

        outcome: SuppressionOutcome = apply_suppressions(
            (finding,), (suppression,), reference_date=_REFERENCE_DATE
        )

        assert outcome.effective_findings == ()
        assert outcome.records == (
            SuppressionRecord(
                rule_id=suppression.rule_id,
                target=suppression.target,
                reason=suppression.reason,
                expires_at=suppression.expires_at,
                status=SuppressionStatus.ACTIVE,
            ),
        )

    def test_no_declared_suppressions_leaves_findings_untouched(self) -> None:
        finding = _finding()

        outcome = apply_suppressions((finding,), (), reference_date=_REFERENCE_DATE)

        assert outcome.effective_findings == (finding,)
        assert outcome.records == ()


class TestApplySuppressionsSimilarNegative:
    def test_suppression_for_a_different_target_does_not_suppress(self) -> None:
        """Same rule, same agent, genuinely different capability path
        (and therefore a genuinely different `Finding.id`) -- the
        suppression names one finding's real ID, not the other's."""

        finding_a = _finding(tool_id=_TOOL_A_ID, edge_id=_EDGE_A_ID)
        finding_b = _finding(tool_id=_TOOL_B_ID, edge_id=_EDGE_B_ID)
        suppression = _suppression(target=finding_a.id)

        outcome = apply_suppressions(
            (finding_a, finding_b), (suppression,), reference_date=_REFERENCE_DATE
        )

        assert outcome.effective_findings == (finding_b,)
        assert outcome.records[0].status is SuppressionStatus.ACTIVE

    def test_suppression_for_a_different_rule_on_the_same_target_is_stale(
        self,
    ) -> None:
        """`target` alone is not sufficient to match -- `rule_id` must
        also agree, even when `target` happens to equal a real finding's
        `id` under a different rule."""

        finding = _finding(rule_id="policy.undeclared-tools")
        suppression = _suppression(rule_id="policy.broad-permission", target=finding.id)

        outcome = apply_suppressions(
            (finding,), (suppression,), reference_date=_REFERENCE_DATE
        )

        assert outcome.effective_findings == (finding,)
        assert outcome.records[0].status is SuppressionStatus.STALE


class TestCannotBroadenBeyondDeclaredScope:
    """A suppression cannot broaden beyond its declared scope, asserted by
    a fixture attempting a wildcard match on unrelated findings."""

    def test_exact_match_never_broadens_to_a_second_unrelated_finding(self) -> None:
        finding_a = _finding(tool_id=_TOOL_A_ID, edge_id=_EDGE_A_ID)
        finding_b = _finding(tool_id=_TOOL_B_ID, edge_id=_EDGE_B_ID)
        assert finding_a.id != finding_b.id  # sanity: genuinely different findings

        suppression = _suppression(target=finding_a.id)

        outcome = apply_suppressions(
            (finding_a, finding_b), (suppression,), reference_date=_REFERENCE_DATE
        )

        # Only the exact named finding is suppressed; the second,
        # unrelated finding sharing the same rule_id is untouched.
        assert finding_b in outcome.effective_findings
        assert finding_a not in outcome.effective_findings
        assert len(outcome.effective_findings) == 1

    def test_a_wildcard_shaped_target_is_rejected_at_construction(self) -> None:
        """`SuppressionTarget`'s own pattern permits no wildcard,
        glob, or prefix syntax at all -- attempting one is not a
        "broadened match," it is a structurally invalid `Suppression`
        that never parses in the first place (see also
        `TestSuppressionModelRequiredFields`)."""

        with pytest.raises(ValidationError):
            Suppression(
                rule_id="policy.undeclared-tools",
                target="clp:finding:sha256:*",
                reason="attempted wildcard broadening",
                expires_at="2099-01-01",
            )

    def test_matching_uses_exact_equality_never_substring_containment(self) -> None:
        """A target that is a real finding ID *plus* extra trailing
        content must not match via substring/prefix containment --
        confirms the matching mechanism itself, not merely the schema
        constraint above, is exact-equality-only."""

        finding = _finding()
        # Shape-valid (64 hex chars) but a different digest that merely
        # shares a prefix with the real finding id.
        near_miss_target = finding.id[:-1] + ("0" if finding.id[-1] != "0" else "1")
        suppression = _suppression(target=near_miss_target)

        outcome = apply_suppressions(
            (finding,), (suppression,), reference_date=_REFERENCE_DATE
        )

        assert outcome.effective_findings == (finding,)
        assert outcome.records[0].status is SuppressionStatus.STALE


class TestCannotSuppressCeilingBreaches:
    """Suppressions cannot suppress ceiling breaches unless the ceiling
    itself is amended."""

    def test_a_suppression_targeting_the_ceiling_rule_never_suppresses(self) -> None:
        finding = _finding(rule_id=CEILING_RULE_ID, severity=FindingSeverity.CRITICAL)
        suppression = _suppression(
            rule_id=CEILING_RULE_ID,
            target=finding.id,
            reason="attempting to suppress a ceiling breach",
        )

        outcome = apply_suppressions(
            (finding,), (suppression,), reference_date=_REFERENCE_DATE
        )

        assert outcome.effective_findings == (finding,)
        assert outcome.records[0].status is SuppressionStatus.CEILING_PROTECTED

    def test_ceiling_protection_wins_even_when_the_suppression_is_also_expired(
        self,
    ) -> None:
        """Ceiling protection is reported even ahead of expiry -- a
        repository owner should never be told a ceiling-targeting
        suppression merely "expired" (implying it would work again if
        renewed); it never works, regardless of date."""

        finding = _finding(rule_id=CEILING_RULE_ID)
        suppression = _suppression(
            rule_id=CEILING_RULE_ID, target=finding.id, expires_at="2020-01-01"
        )

        outcome = apply_suppressions(
            (finding,), (suppression,), reference_date=_REFERENCE_DATE
        )

        assert outcome.records[0].status is SuppressionStatus.CEILING_PROTECTED


class TestExpired:
    """An expired suppression has no effect and is reported as expired."""

    def test_expiry_before_the_reference_date_has_no_effect(self) -> None:
        finding = _finding()
        suppression = _suppression(target=finding.id, expires_at="2020-01-01")

        outcome = apply_suppressions(
            (finding,), (suppression,), reference_date=_REFERENCE_DATE
        )

        assert outcome.effective_findings == (finding,)
        assert outcome.records[0].status is SuppressionStatus.EXPIRED

    def test_expiry_exactly_on_the_reference_date_is_still_active(self) -> None:
        """Boundary: "expires on this date" is valid through the end of
        that date."""

        finding = _finding()
        suppression = _suppression(
            target=finding.id, expires_at=_REFERENCE_DATE.isoformat()
        )

        outcome = apply_suppressions(
            (finding,), (suppression,), reference_date=_REFERENCE_DATE
        )

        assert outcome.effective_findings == ()
        assert outcome.records[0].status is SuppressionStatus.ACTIVE

    def test_expiry_one_day_after_the_reference_date_is_still_active(self) -> None:
        finding = _finding()
        tomorrow = date(2026, 8, 22)
        suppression = _suppression(target=finding.id, expires_at=tomorrow.isoformat())

        outcome = apply_suppressions(
            (finding,), (suppression,), reference_date=_REFERENCE_DATE
        )

        assert outcome.records[0].status is SuppressionStatus.ACTIVE

    def test_expiry_one_day_before_the_reference_date_is_expired(self) -> None:
        finding = _finding()
        yesterday = date(2026, 8, 20)
        suppression = _suppression(target=finding.id, expires_at=yesterday.isoformat())

        outcome = apply_suppressions(
            (finding,), (suppression,), reference_date=_REFERENCE_DATE
        )

        assert outcome.records[0].status is SuppressionStatus.EXPIRED


class TestStale:
    """A suppression that matches nothing is reported as stale, so
    suppressions do not accumulate invisibly."""

    def test_a_suppression_matching_no_finding_is_stale(self) -> None:
        suppression = _suppression(target=f"clp:finding:sha256:{'0' * 64}")

        outcome = apply_suppressions((), (suppression,), reference_date=_REFERENCE_DATE)

        assert outcome.effective_findings == ()
        assert outcome.records[0].status is SuppressionStatus.STALE

    def test_stale_suppression_is_still_a_visible_record(self) -> None:
        """Stale is reported, never silently dropped from the records
        tuple."""

        suppression = _suppression(target=f"clp:finding:sha256:{'1' * 64}")

        outcome = apply_suppressions((), (suppression,), reference_date=_REFERENCE_DATE)

        assert len(outcome.records) == 1


class TestVisibility:
    """Active suppressions are listed in every scan and gate result,
    never hidden -- extended to every declared suppression's
    own status, not only ACTIVE ones (see this module's own reasoning
    in `controlloop.policy.suppressions`'s docstring)."""

    def test_every_declared_suppression_produces_exactly_one_record(self) -> None:
        finding = _finding()
        active = _suppression(target=finding.id)
        expired = _suppression(
            rule_id="policy.broad-permission",
            target=f"clp:finding:sha256:{'2' * 64}",
            expires_at="2020-01-01",
        )
        stale = _suppression(
            rule_id="policy.missing-action-logging",
            target=f"clp:finding:sha256:{'3' * 64}",
        )

        outcome = apply_suppressions(
            (finding,), (active, expired, stale), reference_date=_REFERENCE_DATE
        )

        assert len(outcome.records) == 3
        statuses = {record.status for record in outcome.records}
        assert statuses == {
            SuppressionStatus.ACTIVE,
            SuppressionStatus.EXPIRED,
            SuppressionStatus.STALE,
        }


class TestDeterminism:
    def test_records_are_sorted_regardless_of_input_order(self) -> None:
        first = _suppression(
            rule_id="policy.undeclared-tools",
            target=f"clp:finding:sha256:{'a' * 64}",
        )
        second = _suppression(
            rule_id="policy.broad-permission",
            target=f"clp:finding:sha256:{'b' * 64}",
        )

        forward = apply_suppressions(
            (), (first, second), reference_date=_REFERENCE_DATE
        )
        reversed_order = apply_suppressions(
            (), (second, first), reference_date=_REFERENCE_DATE
        )

        assert forward.records == reversed_order.records
        assert [record.rule_id for record in forward.records] == sorted(
            [record.rule_id for record in forward.records]
        )

    def test_identical_input_produces_identical_output(self) -> None:
        finding = _finding()
        suppression = _suppression(target=finding.id)

        first = apply_suppressions(
            (finding,), (suppression,), reference_date=_REFERENCE_DATE
        )
        second = apply_suppressions(
            (finding,), (suppression,), reference_date=_REFERENCE_DATE
        )

        assert first == second


class TestSuppressionModelRequiredFields:
    """A suppression requires a rule identifier, a scoped target, a
    written reason, and an expiry date; any missing field returns exit
    2. Structural proof at the model level -- exit-2 behavior via the
    real manifest-loading CLI path is covered separately in
    `test_cli.py`."""

    _VALID: ClassVar[dict[str, str]] = {
        "rule_id": "policy.undeclared-tools",
        "target": f"clp:finding:sha256:{'a' * 64}",
        "reason": "reviewed",
        "expires_at": "2099-01-01",
    }

    @pytest.mark.parametrize("missing_field", sorted(_VALID))
    def test_each_required_field_is_mandatory(self, missing_field: str) -> None:
        payload = {k: v for k, v in self._VALID.items() if k != missing_field}

        with pytest.raises(ValidationError):
            Suppression(**payload)

    def test_malformed_expiry_shape_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Suppression(**{**self._VALID, "expires_at": "not-a-date"})

    def test_malformed_expiry_calendar_date_is_rejected(self) -> None:
        """Shape-valid (`YYYY-MM-DD`) but not a real calendar date."""

        with pytest.raises(ValidationError):
            Suppression(**{**self._VALID, "expires_at": "2026-02-30"})

    def test_malformed_target_shape_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Suppression(**{**self._VALID, "target": "not-a-finding-id"})

    def test_all_valid_fields_construct_successfully(self) -> None:
        suppression = Suppression(**self._VALID)

        assert suppression.rule_id == "policy.undeclared-tools"
