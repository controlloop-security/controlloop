"""Tests for controlloop.diff.report."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from controlloop.diff import (
    CURRENT_DIFF_REPORT_SCHEMA_VERSION,
    CURRENT_DIFF_SCHEMA_VERSION,
    BaselineOrigin,
    ComparisonScope,
    DiffReport,
    DiffResult,
)


def _empty_result() -> DiffResult:
    return DiffResult(
        schema_version=CURRENT_DIFF_SCHEMA_VERSION,
        node_changes=(),
        edge_changes=(),
        effective_authority_changes=(),
    )


class TestBaselineOrigin:
    def test_has_exactly_the_five_documented_sources(self) -> None:
        assert {member.value for member in BaselineOrigin} == {
            "two_acboms",
            "explicit_baseline_file",
            "committed_baseline",
            "merge_base",
            "explicit_revision",
        }


class TestComparisonScope:
    def test_has_exactly_the_two_documented_states(self) -> None:
        assert {member.value for member in ComparisonScope} == {
            "full",
            "effective_authority_only",
        }


class TestDiffReport:
    def test_constructs_with_a_full_scope(self) -> None:
        report = DiffReport(
            schema_version=CURRENT_DIFF_REPORT_SCHEMA_VERSION,
            baseline_origin=BaselineOrigin.TWO_ACBOMS,
            baseline_description="baseline.json vs current.json",
            comparison_scope=ComparisonScope.FULL,
            result=_empty_result(),
        )

        assert report.baseline_origin is BaselineOrigin.TWO_ACBOMS
        assert report.comparison_scope is ComparisonScope.FULL
        assert report.result.is_empty is True

    def test_constructs_with_an_effective_authority_only_scope(self) -> None:
        """A committed/explicit `BaselineDocument` carries no
        nodes/edges, so this scope is a legitimate, expected state --
        never an error."""

        report = DiffReport(
            schema_version=CURRENT_DIFF_REPORT_SCHEMA_VERSION,
            baseline_origin=BaselineOrigin.COMMITTED_BASELINE,
            baseline_description=".controlloop/baseline.json",
            comparison_scope=ComparisonScope.EFFECTIVE_AUTHORITY_ONLY,
            result=_empty_result(),
        )

        assert report.comparison_scope is ComparisonScope.EFFECTIVE_AUTHORITY_ONLY

    def test_is_frozen_and_forbids_extra_fields(self) -> None:
        report = DiffReport(
            schema_version=CURRENT_DIFF_REPORT_SCHEMA_VERSION,
            baseline_origin=BaselineOrigin.MERGE_BASE,
            baseline_description="merge-base abc123 against origin/main",
            comparison_scope=ComparisonScope.FULL,
            result=_empty_result(),
        )

        with pytest.raises(ValidationError):
            report.comparison_scope = ComparisonScope.EFFECTIVE_AUTHORITY_ONLY

        with pytest.raises(ValidationError):
            DiffReport.model_validate(
                {
                    "schema_version": CURRENT_DIFF_REPORT_SCHEMA_VERSION,
                    "baseline_origin": BaselineOrigin.MERGE_BASE,
                    "baseline_description": "x",
                    "comparison_scope": ComparisonScope.FULL,
                    "result": _empty_result(),
                    "extra_field": "not allowed",
                }
            )

    def test_round_trips_through_json(self) -> None:
        report = DiffReport(
            schema_version=CURRENT_DIFF_REPORT_SCHEMA_VERSION,
            baseline_origin=BaselineOrigin.EXPLICIT_REVISION,
            baseline_description="revision deadbeef",
            comparison_scope=ComparisonScope.FULL,
            result=_empty_result(),
        )

        restored = DiffReport.model_validate_json(report.model_dump_json())

        assert restored == report
