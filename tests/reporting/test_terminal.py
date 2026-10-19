"""Tests for controlloop.reporting.terminal."""

from __future__ import annotations

from controlloop.acbom import Confidence, EdgeType, Evidence, NodeType
from controlloop.capability.blast_radius import BlastRadiusStatement
from controlloop.capability.models import CapabilityPath, PathHop
from controlloop.capability.taxonomy import MaterialCapabilityClass
from controlloop.diff.material_summary import (
    CURRENT_MATERIAL_CHANGE_SUMMARY_SCHEMA_VERSION,
    MaterialChange,
    MaterialChangeKind,
    MaterialChangeSummary,
)
from controlloop.findings.models import (
    CURRENT_FINDING_SCHEMA_VERSION,
    Finding,
    FindingChangeState,
    FindingSeverity,
)
from controlloop.reporting.terminal import (
    Verdict,
    render_terminal_report,
    render_verdict,
)

_AGENT_ID = f"clp:agent:sha256:{'a' * 64}"
_TOOL_ID = f"clp:tool:sha256:{'b' * 64}"
_RESOURCE_ID = f"clp:resource:sha256:{'c' * 64}"
_EDGE_ID = f"clp:edge:sha256:{'d' * 64}"
_FINDING_ID = f"clp:finding:sha256:{'e' * 64}"

_EVIDENCE = (Evidence(adapter="mcp", path="agent.json"),)


def _blast_radius(**overrides: object) -> BlastRadiusStatement:
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "material_class": MaterialCapabilityClass.DESTRUCTIVE_ACTION,
        "agent_id": _AGENT_ID,
        "agent_name": "refund-agent",
        "action": EdgeType.WRITES,
        "target_id": _RESOURCE_ID,
        "target_name": "billing-db",
        "transitive": False,
        "incomplete": False,
    }
    payload.update(overrides)
    return BlastRadiusStatement.model_validate(payload)


def _hop() -> PathHop:
    return PathHop(
        edge_id=_EDGE_ID,
        edge_type=EdgeType.INVOKES,
        source_id=_AGENT_ID,
        target_id=_TOOL_ID,
        evidence=_EVIDENCE,
    )


def _capability_path() -> CapabilityPath:
    return CapabilityPath(
        schema_version="1.0.0",
        agent_id=_AGENT_ID,
        target_id=_TOOL_ID,
        target_type=NodeType.TOOL,
        hops=(_hop(),),
        confidence=Confidence.HIGH,
    )


def _material_change(**overrides: object) -> MaterialChange:
    payload: dict[str, object] = {
        "kind": MaterialChangeKind.GAINED,
        "material_class": MaterialCapabilityClass.WRITE_ACCESS,
        "agent_id": _AGENT_ID,
        "agent_name": "refund-agent",
        "action": EdgeType.WRITES,
        "target_id": _RESOURCE_ID,
        "target_name": "billing-db",
        "transitive": False,
    }
    payload.update(overrides)
    return MaterialChange.model_validate(payload)


def _material_summary(*changes: MaterialChange) -> MaterialChangeSummary:
    return MaterialChangeSummary(
        schema_version=CURRENT_MATERIAL_CHANGE_SUMMARY_SCHEMA_VERSION,
        changes=changes,
    )


def _finding(**overrides: object) -> Finding:
    payload: dict[str, object] = {
        "schema_version": CURRENT_FINDING_SCHEMA_VERSION,
        "id": _FINDING_ID,
        "rule_id": "policy.undeclared-tools",
        "rule_version": "1.0.0",
        "message": "undeclared tool reachable",
        "severity": FindingSeverity.HIGH,
        "confidence": Confidence.HIGH,
        "affected_agent": _AGENT_ID,
        "evidence": _EVIDENCE,
        "capability_path": _capability_path(),
        "change_state": FindingChangeState.ADDED,
        "remediation": "declare the tool in controlloop.yaml",
        "documentation_url": "https://docs.controlloop.ai/rules/undeclared-tools",
    }
    payload.update(overrides)
    return Finding.model_validate(payload)


class TestOrdering:
    """Blast-radius statement, then verdict, then material changes, then
    findings, in that exact order, every section always present."""

    def test_all_four_sections_appear_in_order(self) -> None:
        report = render_terminal_report(
            blast_radius=_blast_radius(),
            verdict=Verdict.REVIEW_REQUIRED,
            material_changes=_material_summary(_material_change()),
            findings=(_finding(),),
        )

        blast_index = report.index("billing-db")
        verdict_index = report.index("REVIEW REQUIRED")
        material_index = report.index("• GAINED")
        finding_index = report.index("undeclared tool reachable")

        assert blast_index < verdict_index < material_index < finding_index

    def test_every_section_present_even_when_all_optional_data_is_none(self) -> None:
        report = render_terminal_report(
            blast_radius=None,
            verdict=Verdict.NOT_EVALUATED,
            material_changes=None,
            findings=None,
        )

        assert "no material capability is reachable" in report
        assert "NOT EVALUATED" in report
        assert "material change: not evaluated" in report
        assert "findings: not evaluated" in report

    def test_evaluated_but_empty_differs_from_not_evaluated(self) -> None:
        report = render_terminal_report(
            blast_radius=_blast_radius(),
            verdict=Verdict.PASSED,
            material_changes=_material_summary(),
            findings=(),
        )

        assert "no material capability change" in report
        assert "material change: not evaluated" not in report
        assert "no findings" in report
        assert "findings: not evaluated" not in report


class TestNoMeaningByColorAlone:
    """Every state carries a text or symbol marker; color is additive
    decoration only, applied to exactly one sanctioned case."""

    def test_verdict_text_is_identical_with_and_without_color(self) -> None:
        colored = render_verdict(Verdict.DEPLOYMENT_BLOCKED, color_enabled=True)
        plain = render_verdict(Verdict.DEPLOYMENT_BLOCKED, color_enabled=False)

        assert colored.replace("\x1b[31m", "").replace("\x1b[0m", "") == plain
        assert plain == "✕ DEPLOYMENT BLOCKED"

    def test_only_deployment_blocked_ever_gains_ansi_codes(self) -> None:
        for verdict in Verdict:
            rendered = render_verdict(verdict, color_enabled=True)
            if verdict is Verdict.DEPLOYMENT_BLOCKED:
                assert "\x1b[31m" in rendered
            else:
                assert "\x1b[" not in rendered

    def test_every_verdict_has_a_distinct_glyph_and_label(self) -> None:
        rendered = {verdict: render_verdict(verdict) for verdict in Verdict}

        assert len(set(rendered.values())) == len(Verdict)
        for text in rendered.values():
            assert text[0] in {"✓", "!", "✕", "•"}


class TestWidthAdaptation:
    """Rendering adapts to terminal width."""

    def test_a_long_finding_message_wraps_within_a_narrow_width(self) -> None:
        finding = _finding(
            message=(
                "a very long undeclared tool reachability message that "
                "definitely exceeds a narrow terminal width on its own"
            )
        )

        report = render_terminal_report(
            blast_radius=None,
            verdict=Verdict.NOT_EVALUATED,
            material_changes=None,
            findings=(finding,),
            width=30,
        )

        for line in report.split("\n"):
            assert len(line) <= 30

    def test_a_wide_width_does_not_wrap_a_short_line(self) -> None:
        report = render_terminal_report(
            blast_radius=None,
            verdict=Verdict.PASSED,
            material_changes=None,
            findings=None,
            width=200,
        )

        assert "✓ PASSED" in report.split("\n")

    def test_width_below_the_floor_still_produces_valid_output(self) -> None:
        report = render_terminal_report(
            blast_radius=None,
            verdict=Verdict.PASSED,
            material_changes=None,
            findings=None,
            width=1,
        )

        assert "PASSED" in report


class TestDeterminism:
    """Identical input produces identical output."""

    def test_render_terminal_report_is_deterministic(self) -> None:
        kwargs = {
            "blast_radius": _blast_radius(),
            "verdict": Verdict.REVIEW_REQUIRED,
            "material_changes": _material_summary(_material_change()),
            "findings": (_finding(),),
            "color_enabled": True,
            "width": 60,
        }

        first = render_terminal_report(**kwargs)  # type: ignore[arg-type]
        second = render_terminal_report(**kwargs)  # type: ignore[arg-type]

        assert first == second

    def test_render_verdict_is_deterministic(self) -> None:
        assert render_verdict(Verdict.DEPLOYMENT_BLOCKED, color_enabled=True) == (
            render_verdict(Verdict.DEPLOYMENT_BLOCKED, color_enabled=True)
        )


class TestBoundary:
    def test_empty_string_line_survives_wrapping(self) -> None:
        report = render_terminal_report(
            blast_radius=None,
            verdict=Verdict.PASSED,
            material_changes=None,
            findings=None,
            width=10,
        )

        # The blank separator lines between sections must still exist.
        assert "\n\n" in report

    def test_multiple_findings_are_each_fully_rendered(self) -> None:
        first = _finding(message="first finding")
        second = _finding(id=f"clp:finding:sha256:{'f' * 64}", message="second finding")

        report = render_terminal_report(
            blast_radius=None,
            verdict=Verdict.REVIEW_REQUIRED,
            material_changes=None,
            findings=(first, second),
        )

        assert "first finding" in report
        assert "second finding" in report


class TestReductionOnlyChangeSet:
    """A change set that only removes authority is described in its own
    words, rather than as generic change lines that never say the direction
    was safe.

    `describe_capability_reduction` existed, was tested, and was exported --
    and no user-facing command could reach it. These tests exist so it
    cannot become unreachable again."""

    def _lost(self, material_class: MaterialCapabilityClass) -> MaterialChange:
        return MaterialChange(
            kind=MaterialChangeKind.LOST,
            material_class=material_class,
            agent_id="clp:agent:sha256:" + "a" * 64,
            agent_name="triage-agent",
            action=EdgeType.INVOKES,
            target_id="clp:tool:sha256:" + "b" * 64,
            target_name="Purge ticket history",
            transitive=False,
            path=(),
        )

    def _summary(self, *changes: MaterialChange) -> MaterialChangeSummary:
        return MaterialChangeSummary(
            schema_version=CURRENT_MATERIAL_CHANGE_SUMMARY_SCHEMA_VERSION,
            changes=tuple(changes),
        )

    def test_a_reduction_only_change_set_names_each_material_class(self) -> None:
        summary = self._summary(
            self._lost(MaterialCapabilityClass.DESTRUCTIVE_ACTION),
            self._lost(MaterialCapabilityClass.WRITE_ACCESS),
        )

        rendered = render_terminal_report(
            blast_radius=None,
            verdict=Verdict.PASSED,
            material_changes=summary,
            findings=(),
        )

        assert "• REDUCED" in rendered
        assert "destructive-action" in rendered
        assert "write-access" in rendered

    def test_a_reduction_only_change_set_says_nothing_was_gained(self) -> None:
        """The signal a reduction-only change deserves: a pass that is
        visible rather than merely the absence of a warning."""

        summary = self._summary(self._lost(MaterialCapabilityClass.DESTRUCTIVE_ACTION))

        rendered = render_terminal_report(
            blast_radius=None,
            verdict=Verdict.PASSED,
            material_changes=summary,
            findings=(),
        )

        assert "no new authority gained" in rendered

    def test_a_mixed_change_set_still_uses_the_generic_summary(self) -> None:
        """Only a pure reduction gets the reduction voice. A change set
        that also *gains* authority must not be described as safe."""

        gained = MaterialChange(
            kind=MaterialChangeKind.GAINED,
            material_class=MaterialCapabilityClass.EXTERNAL_COMMUNICATION,
            agent_id="clp:agent:sha256:" + "a" * 64,
            agent_name="triage-agent",
            action=EdgeType.INVOKES,
            target_id="clp:tool:sha256:" + "c" * 64,
            target_name="Send mail",
            transitive=False,
            path=(),
        )
        summary = self._summary(
            self._lost(MaterialCapabilityClass.DESTRUCTIVE_ACTION), gained
        )

        rendered = render_terminal_report(
            blast_radius=None,
            verdict=Verdict.PASSED,
            material_changes=summary,
            findings=(),
        )

        assert "no new authority gained" not in rendered

    def test_no_changes_at_all_still_reports_no_material_change(self) -> None:
        rendered = render_terminal_report(
            blast_radius=None,
            verdict=Verdict.PASSED,
            material_changes=self._summary(),
            findings=(),
        )

        assert "no material capability change" in rendered
