"""Tests for controlloop.findings.models.finding_from_observation -- the
small, additive RuleObservation -> Finding bridge, built without changing
controlloop.policy.models.RuleObservation itself."""

from __future__ import annotations

from controlloop.acbom.models import Confidence, EdgeType, Evidence, NodeType
from controlloop.capability.models import CapabilityPath, PathHop
from controlloop.findings.identity import finding_id
from controlloop.findings.models import (
    FindingChangeState,
    FindingSeverity,
    finding_from_observation,
)
from controlloop.policy.models import RuleObservation

_AGENT_ID = f"clp:agent:sha256:{'a' * 64}"
_TOOL_ID = f"clp:tool:sha256:{'b' * 64}"
_EDGE_ID = f"clp:edge:sha256:{'c' * 64}"
_EVIDENCE = (Evidence(adapter="mcp", path="agent.json", line_start=5),)


def _path() -> CapabilityPath:
    hop = PathHop(
        edge_id=_EDGE_ID,
        edge_type=EdgeType.INVOKES,
        source_id=_AGENT_ID,
        target_id=_TOOL_ID,
        evidence=_EVIDENCE,
    )
    return CapabilityPath(
        schema_version="1.0.0",
        agent_id=_AGENT_ID,
        target_id=_TOOL_ID,
        target_type=NodeType.TOOL,
        hops=(hop,),
        confidence=Confidence.HIGH,
    )


class TestRepositoryScopedFindingFromObservation:
    """`finding_from_observation` with no `affected_agent`/`capability_path`
    builds a valid repository-scoped `Finding`, computing identity from the
    observation's own evidence paths automatically."""

    def test_builds_a_valid_repository_scoped_finding(self) -> None:
        observation = RuleObservation(
            rule_id="policy.hardcoded-secrets",
            message="a value matching a known credential shape was found",
            evidence=(Evidence(adapter="secret-scan", path="config/secrets.yaml"),),
        )

        finding = finding_from_observation(
            observation,
            rule_version="1.0.0",
            severity=FindingSeverity.CRITICAL,
            confidence=Confidence.HIGH,
            change_state=FindingChangeState.NOT_COMPARED,
            remediation="rotate and remove the credential",
            documentation_url="https://docs.controlloop.dev/x",
        )

        assert finding.affected_agent is None
        assert finding.capability_path is None

    def test_id_matches_a_direct_finding_id_call_with_evidence_paths(self) -> None:
        evidence = (Evidence(adapter="secret-scan", path="config/secrets.yaml"),)
        observation = RuleObservation(
            rule_id="policy.hardcoded-secrets",
            message="a value matching a known credential shape was found",
            evidence=evidence,
        )

        finding = finding_from_observation(
            observation,
            rule_version="1.0.0",
            severity=FindingSeverity.CRITICAL,
            confidence=Confidence.HIGH,
            change_state=FindingChangeState.NOT_COMPARED,
            remediation="rotate and remove the credential",
            documentation_url="https://docs.controlloop.dev/x",
        )

        expected_id = finding_id(
            rule_id=observation.rule_id,
            affected_agent=None,
            capability_path=None,
            evidence_paths=("config/secrets.yaml",),
        )
        assert finding.id == expected_id


class TestFindingFromObservation:
    def test_rule_id_message_and_evidence_pass_through_unchanged(self) -> None:
        observation = RuleObservation(
            rule_id="policy.undeclared-tools",
            message="undeclared tool reachable",
            evidence=_EVIDENCE,
        )

        finding = finding_from_observation(
            observation,
            rule_version="1.0.0",
            severity=FindingSeverity.HIGH,
            confidence=Confidence.HIGH,
            affected_agent=_AGENT_ID,
            capability_path=_path(),
            change_state=FindingChangeState.ADDED,
            remediation="declare the tool",
            documentation_url="https://docs.controlloop.ai/x",
        )

        assert finding.rule_id == observation.rule_id
        assert finding.message == observation.message
        assert finding.evidence == observation.evidence

    def test_id_matches_a_direct_finding_id_call_with_the_same_inputs(self) -> None:
        observation = RuleObservation(
            rule_id="policy.undeclared-tools",
            message="undeclared tool reachable",
            evidence=_EVIDENCE,
        )
        path = _path()

        finding = finding_from_observation(
            observation,
            rule_version="1.0.0",
            severity=FindingSeverity.HIGH,
            confidence=Confidence.HIGH,
            affected_agent=_AGENT_ID,
            capability_path=path,
            change_state=FindingChangeState.ADDED,
            remediation="declare the tool",
            documentation_url="https://docs.controlloop.ai/x",
        )

        expected_id = finding_id(
            rule_id=observation.rule_id,
            affected_agent=_AGENT_ID,
            capability_path=path,
        )
        assert finding.id == expected_id

    def test_every_keyword_argument_lands_on_the_correct_field(self) -> None:
        observation = RuleObservation(
            rule_id="policy.undeclared-tools",
            message="undeclared tool reachable",
            evidence=_EVIDENCE,
        )
        path = _path()

        finding = finding_from_observation(
            observation,
            rule_version="2.3.4",
            severity=FindingSeverity.CRITICAL,
            confidence=Confidence.MEDIUM,
            affected_agent=_AGENT_ID,
            capability_path=path,
            change_state=FindingChangeState.NOT_COMPARED,
            remediation="disable the delegation",
            documentation_url="https://docs.controlloop.ai/rules/y",
        )

        assert finding.rule_version == "2.3.4"
        assert finding.severity is FindingSeverity.CRITICAL
        assert finding.confidence is Confidence.MEDIUM
        assert finding.affected_agent == _AGENT_ID
        assert finding.capability_path == path
        assert finding.change_state is FindingChangeState.NOT_COMPARED
        assert finding.remediation == "disable the delegation"
        assert finding.documentation_url == "https://docs.controlloop.ai/rules/y"

    def test_constructing_a_finding_directly_without_the_bridge_also_succeeds(
        self,
    ) -> None:
        """`finding_from_observation` is a convenience constructor, not
        the only valid one -- see `controlloop.findings.models.Finding`'s
        own docstring."""

        from controlloop.findings.models import CURRENT_FINDING_SCHEMA_VERSION, Finding

        path = _path()
        identity = finding_id(
            rule_id="policy.undeclared-tools",
            affected_agent=_AGENT_ID,
            capability_path=path,
        )

        finding = Finding(
            schema_version=CURRENT_FINDING_SCHEMA_VERSION,
            id=identity,
            rule_id="policy.undeclared-tools",
            rule_version="1.0.0",
            message="undeclared tool reachable",
            severity=FindingSeverity.HIGH,
            confidence=Confidence.HIGH,
            affected_agent=_AGENT_ID,
            evidence=_EVIDENCE,
            capability_path=path,
            change_state=FindingChangeState.ADDED,
            remediation="declare the tool",
            documentation_url="https://docs.controlloop.ai/x",
        )

        assert finding.id == identity
