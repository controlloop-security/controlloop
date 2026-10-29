"""Tests for controlloop.findings.rendering: findings serialize identically
in human, JSON, and SARIF output."""

from __future__ import annotations

import json

import pytest

from controlloop.acbom.models import Confidence, EdgeType, Evidence, NodeType
from controlloop.capability.models import CapabilityPath, PathHop
from controlloop.findings.models import (
    CURRENT_FINDING_SCHEMA_VERSION,
    Finding,
    FindingChangeState,
    FindingSeverity,
)
from controlloop.findings.rendering import finding_to_sarif_result, render_finding_text

_AGENT_ID = f"clp:agent:sha256:{'a' * 64}"
_TOOL_ID = f"clp:tool:sha256:{'b' * 64}"
_EDGE_ID = f"clp:edge:sha256:{'c' * 64}"
_FINDING_ID = f"clp:finding:sha256:{'d' * 64}"


def _path() -> CapabilityPath:
    hop = PathHop(
        edge_id=_EDGE_ID,
        edge_type=EdgeType.INVOKES,
        source_id=_AGENT_ID,
        target_id=_TOOL_ID,
        evidence=(Evidence(adapter="mcp", path="hop.json"),),
    )
    return CapabilityPath(
        schema_version="1.0.0",
        agent_id=_AGENT_ID,
        target_id=_TOOL_ID,
        target_type=NodeType.TOOL,
        hops=(hop,),
        confidence=Confidence.HIGH,
    )


def _finding(*, evidence: tuple[Evidence, ...], severity: FindingSeverity) -> Finding:
    return Finding(
        schema_version=CURRENT_FINDING_SCHEMA_VERSION,
        id=_FINDING_ID,
        rule_id="policy.undeclared-tools",
        rule_version="1.0.0",
        message="undeclared tool reachable",
        severity=severity,
        confidence=Confidence.HIGH,
        affected_agent=_AGENT_ID,
        evidence=evidence,
        capability_path=_path(),
        change_state=FindingChangeState.ADDED,
        remediation="declare the tool in controlloop.yaml",
        documentation_url="https://docs.controlloop.ai/rules/undeclared-tools",
    )


_LOCATED_EVIDENCE = (
    Evidence(adapter="mcp", path="agent.json", line_start=3, line_end=4),
)
_UNLOCATED_EVIDENCE = (Evidence(adapter="mcp", document_digest=f"sha256:{'0' * 64}"),)


class TestRenderFindingText:
    def test_summary_line_carries_severity_rule_id_and_message(self) -> None:
        finding = _finding(evidence=_LOCATED_EVIDENCE, severity=FindingSeverity.HIGH)

        text = render_finding_text(finding)

        assert "HIGH" in text
        assert finding.rule_id in text
        assert finding.message in text

    def test_evidence_with_a_path_renders_one_location_line(self) -> None:
        finding = _finding(evidence=_LOCATED_EVIDENCE, severity=FindingSeverity.HIGH)

        text = render_finding_text(finding)

        assert "agent.json:3-4" in text

    def test_evidence_without_a_path_renders_no_location_line(self) -> None:
        finding = _finding(evidence=_UNLOCATED_EVIDENCE, severity=FindingSeverity.HIGH)

        text = render_finding_text(finding)

        assert text.count("\n") == 0

    @pytest.mark.parametrize("severity", list(FindingSeverity))
    def test_every_severity_renders_without_error(
        self, severity: FindingSeverity
    ) -> None:
        finding = _finding(evidence=_LOCATED_EVIDENCE, severity=severity)

        text = render_finding_text(finding)

        assert severity.value.upper() in text

    def test_critical_label_is_separated_from_the_rule_id(self) -> None:
        # The label column was once a literal 8 and `CRITICAL` is exactly 8
        # characters, so that one severity rendered with no space before the
        # rule id (`✕ CRITICALpolicy.capability-ceiling`).
        finding = _finding(
            evidence=_LOCATED_EVIDENCE, severity=FindingSeverity.CRITICAL
        )

        summary_line = render_finding_text(finding).split("\n")[0]

        assert f"CRITICAL {finding.rule_id}:" in summary_line
        assert f"CRITICAL{finding.rule_id}" not in summary_line

    def test_rule_id_starts_in_the_same_column_for_every_severity(self) -> None:
        columns: set[int] = set()
        for severity in FindingSeverity:
            finding = _finding(evidence=_LOCATED_EVIDENCE, severity=severity)

            summary_line = render_finding_text(finding).split("\n")[0]

            column = summary_line.index(finding.rule_id)
            assert summary_line[column - 1] == " ", severity
            columns.add(column)
        assert len(columns) == 1, columns


class TestFindingToSarifResult:
    def test_rule_id_and_message_are_present(self) -> None:
        finding = _finding(evidence=_LOCATED_EVIDENCE, severity=FindingSeverity.HIGH)

        result = finding_to_sarif_result(finding)

        assert result["ruleId"] == finding.rule_id
        message = result["message"]
        assert isinstance(message, dict)
        assert message["text"] == finding.message

    @pytest.mark.parametrize(
        ("severity", "expected_level"),
        [
            (FindingSeverity.INFO, "note"),
            (FindingSeverity.LOW, "note"),
            (FindingSeverity.MEDIUM, "warning"),
            (FindingSeverity.HIGH, "error"),
            (FindingSeverity.CRITICAL, "error"),
        ],
    )
    def test_severity_maps_to_the_expected_sarif_level(
        self, severity: FindingSeverity, expected_level: str
    ) -> None:
        finding = _finding(evidence=_LOCATED_EVIDENCE, severity=severity)

        result = finding_to_sarif_result(finding)

        assert result["level"] == expected_level

    def test_located_evidence_produces_one_location(self) -> None:
        finding = _finding(evidence=_LOCATED_EVIDENCE, severity=FindingSeverity.HIGH)

        result = finding_to_sarif_result(finding)

        locations = result["locations"]
        assert isinstance(locations, list)
        assert len(locations) == 1
        physical = locations[0]["physicalLocation"]
        assert physical["artifactLocation"]["uri"] == "agent.json"
        assert physical["region"] == {"startLine": 3, "endLine": 4}

    def test_unlocated_evidence_produces_no_location(self) -> None:
        finding = _finding(evidence=_UNLOCATED_EVIDENCE, severity=FindingSeverity.HIGH)

        result = finding_to_sarif_result(finding)

        assert result["locations"] == []

    def test_properties_bag_carries_every_req1_field_without_a_native_slot(
        self,
    ) -> None:
        finding = _finding(evidence=_LOCATED_EVIDENCE, severity=FindingSeverity.HIGH)

        result = finding_to_sarif_result(finding)

        properties = result["properties"]
        assert isinstance(properties, dict)
        bag = properties["controlloop"]
        assert bag["findingId"] == finding.id
        assert bag["ruleVersion"] == finding.rule_version
        assert bag["confidence"] == finding.confidence.value
        assert bag["affectedAgent"] == finding.affected_agent
        assert bag["changeState"] == finding.change_state.value
        assert bag["remediation"] == finding.remediation
        assert bag["documentationUrl"] == finding.documentation_url
        assert finding.capability_path is not None
        assert bag["capabilityPath"]["agentId"] == finding.capability_path.agent_id
        assert bag["capabilityPath"]["hopEdgeIds"] == [_EDGE_ID]

    def test_result_is_json_serializable(self) -> None:
        finding = _finding(evidence=_LOCATED_EVIDENCE, severity=FindingSeverity.HIGH)

        result = finding_to_sarif_result(finding)

        assert isinstance(json.dumps(result), str)


def _repository_scoped_finding(
    *, evidence: tuple[Evidence, ...], severity: FindingSeverity
) -> Finding:
    return Finding(
        schema_version=CURRENT_FINDING_SCHEMA_VERSION,
        id=_FINDING_ID,
        rule_id="policy.hardcoded-secrets",
        rule_version="1.0.0",
        message="a value matching a known credential shape was found",
        severity=severity,
        confidence=Confidence.HIGH,
        affected_agent=None,
        evidence=evidence,
        capability_path=None,
        change_state=FindingChangeState.NOT_COMPARED,
        remediation="rotate and remove the credential",
        documentation_url="https://docs.controlloop.dev/rules/hardcoded-secrets",
    )


class TestRepositoryScopedRendering:
    """Rendering a finding with no affected agent or capability path never
    crashes and never fabricates either."""

    def test_human_text_renders_without_error(self) -> None:
        finding = _repository_scoped_finding(
            evidence=_LOCATED_EVIDENCE, severity=FindingSeverity.CRITICAL
        )

        text = render_finding_text(finding)

        assert finding.message in text
        assert "agent.json:3-4" in text

    def test_sarif_result_omits_affected_agent_and_capability_path(self) -> None:
        finding = _repository_scoped_finding(
            evidence=_LOCATED_EVIDENCE, severity=FindingSeverity.CRITICAL
        )

        result = finding_to_sarif_result(finding)

        bag = result["properties"]["controlloop"]  # type: ignore[index]
        assert bag["affectedAgent"] is None
        assert "capabilityPath" not in bag

    def test_sarif_result_is_still_json_serializable(self) -> None:
        finding = _repository_scoped_finding(
            evidence=_LOCATED_EVIDENCE, severity=FindingSeverity.CRITICAL
        )

        result = finding_to_sarif_result(finding)

        assert isinstance(json.dumps(result), str)


class TestCrossFormatConsistency:
    """The same evidence location data is derivable from the human line, the
    JSON evidence array, and the SARIF locations array for the same
    finding."""

    def test_evidence_locations_agree_across_all_three_formats(self) -> None:
        evidence = (
            Evidence(adapter="mcp", path="a.json", line_start=1, line_end=2),
            Evidence(adapter="mcp", path="b.json"),
        )
        finding = _finding(evidence=evidence, severity=FindingSeverity.HIGH)

        human = render_finding_text(finding)
        payload = json.loads(finding.model_dump_json())
        sarif = finding_to_sarif_result(finding)

        assert "a.json:1-2" in human
        assert "b.json" in human

        json_evidence = payload["evidence"]
        assert {item["path"] for item in json_evidence} == {"a.json", "b.json"}

        sarif_locations = sarif["locations"]
        assert isinstance(sarif_locations, list)
        sarif_uris = {
            location["physicalLocation"]["artifactLocation"]["uri"]
            for location in sarif_locations
        }
        assert sarif_uris == {"a.json", "b.json"}


class TestSuppressedFindingText:
    def test_a_suppressed_finding_says_so_and_drops_the_blocking_glyph(self) -> None:
        finding = _finding(
            evidence=_LOCATED_EVIDENCE, severity=FindingSeverity.CRITICAL
        )

        text = render_finding_text(finding, suppressed_until="2026-12-31")

        summary, *rest = text.split("\n")
        assert summary.startswith("• CRITICAL")
        assert (
            rest[-1] == "    suppressed until 2026-12-31; does not affect the verdict"
        )

    def test_an_unsuppressed_finding_is_unchanged(self) -> None:
        finding = _finding(
            evidence=_LOCATED_EVIDENCE, severity=FindingSeverity.CRITICAL
        )

        assert render_finding_text(finding) == render_finding_text(
            finding, suppressed_until=None
        )
        assert render_finding_text(finding).startswith("✕ CRITICAL")
        assert "suppressed" not in render_finding_text(finding)


class TestOrganizationDecidedFindingText:
    def test_an_excepted_finding_says_so_and_drops_the_blocking_glyph(self) -> None:
        finding = _finding(evidence=_LOCATED_EVIDENCE, severity=FindingSeverity.HIGH)

        text = render_finding_text(finding, excepted_until="2099-01-01")

        summary, *rest = text.split("\n")
        assert summary.startswith("• HIGH")
        assert rest[-1] == (
            "    organization exception until 2099-01-01; does not affect the verdict"
        )

    @pytest.mark.parametrize(
        ("action", "glyph", "closing"),
        [
            ("fail", "✕", "organization action `fail`: blocks"),
            (
                "require_review",
                "!",
                "organization action `require_review`: needs review",
            ),
            ("warn", "!", "organization action `warn`: reported, does not block"),
            ("pass", "•", "organization action `pass`: does not affect the verdict"),
            ("quarantine", "✕", "organization action `fail`: blocks"),
        ],
    )
    def test_an_organization_action_sets_the_glyph_and_says_so(
        self, action: str, glyph: str, closing: str
    ) -> None:
        finding = _finding(evidence=_LOCATED_EVIDENCE, severity=FindingSeverity.LOW)

        text = render_finding_text(finding, organization_action=action)

        summary, *rest = text.split("\n")
        assert summary.startswith(f"{glyph} LOW")
        assert rest[-1] == f"    {closing}"

    def test_an_exception_outranks_the_action(self) -> None:
        finding = _finding(evidence=_LOCATED_EVIDENCE, severity=FindingSeverity.HIGH)

        text = render_finding_text(
            finding, excepted_until="2099-01-01", organization_action="fail"
        )

        assert text.startswith("• HIGH")
        assert "organization action" not in text
