"""Tests for controlloop.findings.models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from controlloop.acbom.models import Confidence, EdgeType, Evidence, NodeType
from controlloop.capability.models import CapabilityPath, PathHop
from controlloop.findings.models import (
    CURRENT_FINDING_SCHEMA_VERSION,
    Finding,
    FindingChangeState,
    FindingSeverity,
    finding_from_observation,
)
from controlloop.policy.models import RuleObservation

_AGENT_ID = f"clp:agent:sha256:{'a' * 64}"
_OTHER_AGENT_ID = f"clp:agent:sha256:{'9' * 64}"
_TOOL_ID = f"clp:tool:sha256:{'b' * 64}"
_EDGE_ID = f"clp:edge:sha256:{'c' * 64}"
_FINDING_ID = f"clp:finding:sha256:{'d' * 64}"

_EVIDENCE = (Evidence(adapter="mcp", path="agent.json", line_start=3, line_end=4),)


def _hop(*, source: str = _AGENT_ID, target: str = _TOOL_ID) -> PathHop:
    return PathHop(
        edge_id=_EDGE_ID,
        edge_type=EdgeType.INVOKES,
        source_id=source,
        target_id=target,
        evidence=_EVIDENCE,
    )


def _capability_path(*, agent_id: str = _AGENT_ID) -> CapabilityPath:
    return CapabilityPath(
        schema_version="1.0.0",
        agent_id=agent_id,
        target_id=_TOOL_ID,
        target_type=NodeType.TOOL,
        hops=(_hop(source=agent_id),),
        confidence=Confidence.HIGH,
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


def _observation() -> RuleObservation:
    return RuleObservation(
        rule_id="policy.undeclared-tools",
        message="undeclared tool reachable",
        evidence=_EVIDENCE,
    )


class TestConstruction:
    """A finding carries every named field."""

    def test_constructs_with_every_required_field(self) -> None:
        finding = _finding()

        assert finding.schema_version == CURRENT_FINDING_SCHEMA_VERSION
        assert finding.id == _FINDING_ID
        assert finding.rule_id == "policy.undeclared-tools"
        assert finding.rule_version == "1.0.0"
        assert finding.message == "undeclared tool reachable"
        assert finding.severity is FindingSeverity.HIGH
        assert finding.confidence is Confidence.HIGH
        assert finding.affected_agent == _AGENT_ID
        assert finding.evidence == _EVIDENCE
        assert finding.capability_path is not None
        assert finding.capability_path.agent_id == _AGENT_ID
        assert finding.change_state is FindingChangeState.ADDED
        assert finding.remediation == "declare the tool in controlloop.yaml"
        assert finding.documentation_url.startswith("https://")

    def test_from_observation_copies_rule_id_message_and_evidence(self) -> None:
        observation = _observation()

        finding = finding_from_observation(
            observation,
            rule_version="1.0.0",
            severity=FindingSeverity.HIGH,
            confidence=Confidence.HIGH,
            affected_agent=_AGENT_ID,
            capability_path=_capability_path(),
            change_state=FindingChangeState.ADDED,
            remediation="declare the tool in controlloop.yaml",
            documentation_url="https://docs.controlloop.ai/rules/undeclared-tools",
        )

        assert finding.rule_id == observation.rule_id
        assert finding.message == observation.message
        assert finding.evidence == observation.evidence

    def test_is_frozen(self) -> None:
        finding = _finding()
        with pytest.raises(ValidationError):
            finding.severity = FindingSeverity.LOW

    def test_rejects_unknown_extra_field(self) -> None:
        payload = _finding().model_dump(mode="json")
        payload["extra_field"] = "should not be accepted"
        with pytest.raises(ValidationError):
            Finding.model_validate(payload)


class TestMissingRequiredField:
    """A finding missing any required field fails validation rather than
    being emitted -- one case per required field."""

    _REQUIRED_FIELDS = (
        "schema_version",
        "id",
        "rule_id",
        "rule_version",
        "message",
        "severity",
        "confidence",
        "affected_agent",
        "evidence",
        "capability_path",
        "change_state",
        "remediation",
        "documentation_url",
    )

    @pytest.mark.parametrize("field_name", _REQUIRED_FIELDS)
    def test_omitting_a_required_field_fails_validation(self, field_name: str) -> None:
        payload = _finding().model_dump(mode="json")
        del payload[field_name]

        with pytest.raises(ValidationError):
            Finding.model_validate(payload)


class TestMalformedFields:
    """Validation extended to malformed shapes, not only omission."""

    def test_rejects_rule_id_with_invalid_characters(self) -> None:
        with pytest.raises(ValidationError):
            _finding(rule_id="not a valid identifier!!")

    def test_rejects_non_semver_rule_version(self) -> None:
        with pytest.raises(ValidationError):
            _finding(rule_version="not-a-version")

    def test_rejects_unknown_severity_value(self) -> None:
        with pytest.raises(ValidationError):
            Finding.model_validate(
                {**_finding().model_dump(mode="json"), "severity": "extreme"}
            )

    def test_rejects_unknown_change_state_value(self) -> None:
        with pytest.raises(ValidationError):
            Finding.model_validate(
                {**_finding().model_dump(mode="json"), "change_state": "sideways"}
            )

    def test_rejects_affected_agent_not_shaped_like_an_agent_node_id(self) -> None:
        with pytest.raises(ValidationError):
            _finding(affected_agent=_TOOL_ID)

    def test_rejects_documentation_url_without_https_scheme(self) -> None:
        with pytest.raises(ValidationError):
            _finding(documentation_url="http://docs.controlloop.ai/rules/x")

    def test_rejects_documentation_url_with_control_character(self) -> None:
        with pytest.raises(ValidationError):
            _finding(documentation_url="https://docs.controlloop.ai/\nrules/x")

    def test_rejects_empty_remediation(self) -> None:
        with pytest.raises(ValidationError):
            _finding(remediation="")

    def test_rejects_empty_message(self) -> None:
        with pytest.raises(ValidationError):
            _finding(message="")

    def test_rejects_empty_evidence(self) -> None:
        with pytest.raises(ValidationError):
            _finding(evidence=())

    def test_rejects_finding_id_not_shaped_like_a_finding_identifier(self) -> None:
        with pytest.raises(ValidationError):
            _finding(id=f"clp:agent:sha256:{'d' * 64}")


class TestAffectedAgentMustMatchCapabilityPath:
    def test_mismatched_affected_agent_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="affected_agent"):
            _finding(affected_agent=_OTHER_AGENT_ID)

    def test_matching_affected_agent_is_accepted(self) -> None:
        finding = _finding(
            affected_agent=_OTHER_AGENT_ID,
            capability_path=_capability_path(agent_id=_OTHER_AGENT_ID),
        )
        assert finding.affected_agent == _OTHER_AGENT_ID


class TestRepositoryScopedFinding:
    """`affected_agent`/`capability_path` may both be
    omitted (repository-scoped), but never exactly one."""

    def test_both_omitted_is_a_valid_repository_scoped_finding(self) -> None:
        finding = _finding(affected_agent=None, capability_path=None)

        assert finding.affected_agent is None
        assert finding.capability_path is None

    def test_affected_agent_present_without_capability_path_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="capability_path"):
            _finding(capability_path=None)

    def test_capability_path_present_without_affected_agent_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="affected_agent"):
            _finding(affected_agent=None)

    def test_current_schema_version_is_the_minor_bump_to_1_1_0(self) -> None:
        assert CURRENT_FINDING_SCHEMA_VERSION == "1.1.0"


class TestBoundaries:
    def test_single_hop_capability_path_is_the_minimum_and_is_accepted(self) -> None:
        finding = _finding()
        assert finding.capability_path is not None
        assert len(finding.capability_path.hops) == 1

    def test_multi_hop_capability_path_is_accepted(self) -> None:
        middle_id = f"clp:tool:sha256:{'e' * 64}"
        first_hop = PathHop(
            edge_id=_EDGE_ID,
            edge_type=EdgeType.DELEGATES_TO,
            source_id=_AGENT_ID,
            target_id=middle_id,
            evidence=_EVIDENCE,
        )
        second_hop = PathHop(
            edge_id=f"clp:edge:sha256:{'f' * 64}",
            edge_type=EdgeType.INVOKES,
            source_id=middle_id,
            target_id=_TOOL_ID,
            evidence=_EVIDENCE,
        )
        path = CapabilityPath(
            schema_version="1.0.0",
            agent_id=_AGENT_ID,
            target_id=_TOOL_ID,
            target_type=NodeType.TOOL,
            hops=(first_hop, second_hop),
            confidence=Confidence.HIGH,
        )

        finding = _finding(capability_path=path)

        assert finding.capability_path is not None
        assert len(finding.capability_path.hops) == 2

    def test_documentation_url_at_minimum_valid_length(self) -> None:
        finding = _finding(documentation_url="https://x")
        assert finding.documentation_url == "https://x"

    def test_severity_accepts_every_declared_member(self) -> None:
        for severity in FindingSeverity:
            finding = _finding(severity=severity)
            assert finding.severity is severity

    def test_change_state_accepts_every_declared_member(self) -> None:
        for state in FindingChangeState:
            finding = _finding(change_state=state)
            assert finding.change_state is state


class TestSchemaVersion:
    """Version-drift coverage: the schema version is a real, checked
    field, not a decorative constant."""

    def test_current_schema_version_constant_is_used_by_default_fixture(self) -> None:
        assert _finding().schema_version == CURRENT_FINDING_SCHEMA_VERSION

    def test_malformed_schema_version_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _finding(schema_version="not-a-version")

    def test_a_different_but_well_formed_schema_version_is_accepted(self) -> None:
        """This model does not yet enforce a compatibility policy across
        schema versions (no reader has been built against a second
        version); it accepts any well-formed semantic version string,
        the same permissive-until-a-second-version-exists posture
        `controlloop.diff.models.DiffResult.schema_version` and
        `controlloop.capability.models.CapabilityPath.schema_version`
        already take."""

        finding = _finding(schema_version="1.0.1")
        assert finding.schema_version == "1.0.1"
