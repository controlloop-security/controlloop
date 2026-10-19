"""Tests for organization exceptions as a gate input.

The exception rules have four clauses and each gets its own coverage: exceptions apply
only to their exact fingerprint, only within their scope, expire by
timestamp *at evaluation time*, and an expired one visibly re-blocks with
its expiry date.

The expiry tests inject the evaluation instant rather than reading a
clock, which is the whole reason `apply_exceptions` takes one.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from factories import EDGE_B_ID, TOOL_B_ID, make_finding
from pydantic import ValidationError

from controlloop.team.exceptions import (
    ActiveException,
    ExceptionState,
    apply_exceptions,
)

_NOW = datetime(2026, 9, 2, 12, 0, 0, tzinfo=UTC)
_FUTURE = _NOW + timedelta(days=30)
_PAST = _NOW - timedelta(days=1)


class TestApplied:
    def test_an_unexpired_exception_removes_its_exact_finding(self) -> None:
        finding = make_finding()
        exception = ActiveException(finding_fingerprint=finding.id, expires_at=_FUTURE)

        outcome = apply_exceptions((finding,), (exception,), evaluated_at=_NOW)

        assert outcome.effective_findings == ()
        assert outcome.records[0].state is ExceptionState.APPLIED

    def test_other_findings_are_untouched(self) -> None:
        excepted = make_finding(rule_id="a.rule")
        other = make_finding(rule_id="b.rule", tool_id=TOOL_B_ID, edge_id=EDGE_B_ID)
        exception = ActiveException(finding_fingerprint=excepted.id, expires_at=_FUTURE)

        outcome = apply_exceptions((excepted, other), (exception,), evaluated_at=_NOW)

        assert outcome.effective_findings == (other,)

    def test_no_exceptions_returns_the_findings_unchanged(self) -> None:
        findings = (make_finding(),)

        outcome = apply_exceptions(findings, (), evaluated_at=_NOW)

        assert outcome.effective_findings is findings
        assert outcome.records == ()


class TestExactMatching:
    """Exceptions apply only to their exact finding fingerprint and scope."""

    def test_a_different_finding_is_not_covered(self) -> None:
        """The failure this prevents: one accepted risk silently covering
        a second, different one that appeared later under the same rule."""

        excepted = make_finding(rule_id="a.rule")
        other = make_finding(rule_id="a.rule", tool_id=TOOL_B_ID, edge_id=EDGE_B_ID)
        assert excepted.id != other.id

        outcome = apply_exceptions(
            (other,),
            (ActiveException(finding_fingerprint=excepted.id, expires_at=_FUTURE),),
            evaluated_at=_NOW,
        )

        assert outcome.effective_findings == (other,)
        assert outcome.records[0].state is ExceptionState.UNMATCHED

    def test_a_prefix_of_a_fingerprint_does_not_match(self) -> None:
        finding = make_finding()

        outcome = apply_exceptions(
            (finding,),
            (ActiveException(finding_fingerprint=finding.id[:20], expires_at=_FUTURE),),
            evaluated_at=_NOW,
        )

        assert outcome.effective_findings == (finding,)

    def test_an_unmatched_exception_is_still_recorded(self) -> None:
        """Evidence shows the full published set, not only the part that
        bit."""

        outcome = apply_exceptions(
            (make_finding(),),
            (ActiveException(finding_fingerprint="clp:absent", expires_at=_FUTURE),),
            evaluated_at=_NOW,
        )

        assert len(outcome.records) == 1
        assert outcome.records[0].state is ExceptionState.UNMATCHED


class TestExpiry:
    """Expiry is evaluated at gate time, and an expired exception visibly
    re-blocks."""

    def test_an_expired_exception_does_not_apply(self) -> None:
        finding = make_finding()

        outcome = apply_exceptions(
            (finding,),
            (ActiveException(finding_fingerprint=finding.id, expires_at=_PAST),),
            evaluated_at=_NOW,
        )

        assert outcome.effective_findings == (finding,)
        assert outcome.records[0].state is ExceptionState.EXPIRED

    def test_expiry_exactly_at_the_evaluation_instant_is_expired(self) -> None:
        """The boundary is inclusive: an exception that expires *at* this
        instant has expired. Anything else means an approval that is
        simultaneously live and lapsed depending on rounding."""

        finding = make_finding()

        outcome = apply_exceptions(
            (finding,),
            (ActiveException(finding_fingerprint=finding.id, expires_at=_NOW),),
            evaluated_at=_NOW,
        )

        assert outcome.records[0].state is ExceptionState.EXPIRED

    def test_one_second_before_expiry_still_applies(self) -> None:
        finding = make_finding()

        outcome = apply_exceptions(
            (finding,),
            (
                ActiveException(
                    finding_fingerprint=finding.id,
                    expires_at=_NOW + timedelta(seconds=1),
                ),
            ),
            evaluated_at=_NOW,
        )

        assert outcome.records[0].state is ExceptionState.APPLIED

    def test_the_expiry_date_is_carried_for_rendering(self) -> None:
        """An expired exception visibly re-blocks with the expiry date in
        the output -- the record carries the date the CLI renders."""

        finding = make_finding()

        outcome = apply_exceptions(
            (finding,),
            (ActiveException(finding_fingerprint=finding.id, expires_at=_PAST),),
            evaluated_at=_NOW,
        )

        assert outcome.expired()[0].expires_at == _PAST

    def test_expired_reports_only_expired_records(self) -> None:
        first = make_finding(rule_id="a.rule")
        second = make_finding(rule_id="b.rule", tool_id=TOOL_B_ID, edge_id=EDGE_B_ID)

        outcome = apply_exceptions(
            (first, second),
            (
                ActiveException(finding_fingerprint=first.id, expires_at=_PAST),
                ActiveException(finding_fingerprint=second.id, expires_at=_FUTURE),
            ),
            evaluated_at=_NOW,
        )

        assert len(outcome.expired()) == 1
        assert outcome.expired()[0].finding_fingerprint == first.id

    def test_the_same_inputs_at_a_later_instant_can_change_the_outcome(
        self,
    ) -> None:
        """Determinism means "same inputs, same result", and the
        evaluation instant is one of the inputs. This is the test that
        says so out loud."""

        finding = make_finding()
        exception = ActiveException(
            finding_fingerprint=finding.id, expires_at=_NOW + timedelta(hours=1)
        )

        before = apply_exceptions((finding,), (exception,), evaluated_at=_NOW)
        after = apply_exceptions(
            (finding,), (exception,), evaluated_at=_NOW + timedelta(hours=2)
        )

        assert before.records[0].state is ExceptionState.APPLIED
        assert after.records[0].state is ExceptionState.EXPIRED


class TestDeterminism:
    """Deterministic output, for this half of the pipeline."""

    def test_records_are_sorted_regardless_of_input_order(self) -> None:
        first = make_finding(rule_id="a.rule")
        second = make_finding(rule_id="b.rule", tool_id=TOOL_B_ID, edge_id=EDGE_B_ID)
        one = ActiveException(finding_fingerprint=first.id, expires_at=_FUTURE)
        two = ActiveException(finding_fingerprint=second.id, expires_at=_FUTURE)

        forward = apply_exceptions((first, second), (one, two), evaluated_at=_NOW)
        backward = apply_exceptions((first, second), (two, one), evaluated_at=_NOW)

        assert forward.records == backward.records

    def test_the_narrowed_findings_keep_their_original_order(self) -> None:
        first = make_finding(rule_id="a.rule")
        second = make_finding(rule_id="b.rule", tool_id=TOOL_B_ID, edge_id=EDGE_B_ID)

        outcome = apply_exceptions((first, second), (), evaluated_at=_NOW)

        assert outcome.effective_findings == (first, second)


class TestRecordModel:
    def test_a_record_is_frozen(self) -> None:
        outcome = apply_exceptions(
            (make_finding(),),
            (ActiveException(finding_fingerprint="x", expires_at=_FUTURE),),
            evaluated_at=_NOW,
        )

        with pytest.raises(ValidationError):
            outcome.records[0].state = ExceptionState.APPLIED

    def test_a_record_carries_no_owner_or_reason(self) -> None:
        """The contract deliberately omits who approved what -- a CI log is
        not the place for it -- so there is nothing of that kind here to
        leak."""

        outcome = apply_exceptions(
            (make_finding(),),
            (ActiveException(finding_fingerprint="x", expires_at=_FUTURE),),
            evaluated_at=_NOW,
        )

        assert set(outcome.records[0].model_dump()) == {
            "finding_fingerprint",
            "expires_at",
            "state",
        }
