"""Tests for controlloop.findings.identity: finding identity is stable
across runs, so the same issue is recognizable between scans."""

from __future__ import annotations

import re

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
_OTHER_AGENT_ID = f"clp:agent:sha256:{'9' * 64}"
_TOOL_ID = f"clp:tool:sha256:{'b' * 64}"
_OTHER_TOOL_ID = f"clp:tool:sha256:{'2' * 64}"
_EDGE_ID = f"clp:edge:sha256:{'c' * 64}"
_OTHER_EDGE_ID = f"clp:edge:sha256:{'3' * 64}"

_FINDING_ID_PATTERN = re.compile(r"^clp:finding:sha256:[0-9a-f]{64}$")


def _path(
    *,
    agent_id: str = _AGENT_ID,
    target_id: str = _TOOL_ID,
    edge_id: str = _EDGE_ID,
    evidence: tuple[Evidence, ...] = (Evidence(adapter="mcp", path="a.json"),),
) -> CapabilityPath:
    hop = PathHop(
        edge_id=edge_id,
        edge_type=EdgeType.INVOKES,
        source_id=agent_id,
        target_id=target_id,
        evidence=evidence,
    )
    return CapabilityPath(
        schema_version="1.0.0",
        agent_id=agent_id,
        target_id=target_id,
        target_type=NodeType.TOOL,
        hops=(hop,),
        confidence=Confidence.HIGH,
    )


class TestShape:
    def test_returned_id_matches_the_finding_id_pattern(self) -> None:
        identity = finding_id(
            rule_id="policy.undeclared-tools",
            affected_agent=_AGENT_ID,
            capability_path=_path(),
        )
        assert _FINDING_ID_PATTERN.fullmatch(identity)


class TestDeterminism:
    def test_repeated_calls_with_identical_input_produce_an_identical_id(self) -> None:
        first = finding_id(
            rule_id="policy.undeclared-tools",
            affected_agent=_AGENT_ID,
            capability_path=_path(),
        )
        second = finding_id(
            rule_id="policy.undeclared-tools",
            affected_agent=_AGENT_ID,
            capability_path=_path(),
        )
        assert first == second


class TestIdentityChangesWithSemanticContent:
    def test_different_rule_id_produces_a_different_identity(self) -> None:
        path = _path()
        first = finding_id(
            rule_id="policy.rule-a", affected_agent=_AGENT_ID, capability_path=path
        )
        second = finding_id(
            rule_id="policy.rule-b", affected_agent=_AGENT_ID, capability_path=path
        )
        assert first != second

    def test_different_affected_agent_produces_a_different_identity(self) -> None:
        first = finding_id(
            rule_id="policy.rule-a", affected_agent=_AGENT_ID, capability_path=_path()
        )
        second = finding_id(
            rule_id="policy.rule-a",
            affected_agent=_OTHER_AGENT_ID,
            capability_path=_path(agent_id=_OTHER_AGENT_ID),
        )
        assert first != second

    def test_different_target_id_produces_a_different_identity(self) -> None:
        first = finding_id(
            rule_id="policy.rule-a", affected_agent=_AGENT_ID, capability_path=_path()
        )
        second = finding_id(
            rule_id="policy.rule-a",
            affected_agent=_AGENT_ID,
            capability_path=_path(target_id=_OTHER_TOOL_ID),
        )
        assert first != second

    def test_different_hop_edge_id_produces_a_different_identity(self) -> None:
        first = finding_id(
            rule_id="policy.rule-a", affected_agent=_AGENT_ID, capability_path=_path()
        )
        second = finding_id(
            rule_id="policy.rule-a",
            affected_agent=_AGENT_ID,
            capability_path=_path(edge_id=_OTHER_EDGE_ID),
        )
        assert first != second


class TestRepositoryScopedIdentity:
    """Identity for a finding with no affected agent
    is anchored to its evidence's own sanitized paths instead."""

    def test_returned_id_matches_the_finding_id_pattern(self) -> None:
        identity = finding_id(
            rule_id="policy.hardcoded-secrets",
            affected_agent=None,
            capability_path=None,
            evidence_paths=("config/secrets.yaml",),
        )
        assert _FINDING_ID_PATTERN.fullmatch(identity)

    def test_repeated_calls_with_identical_input_produce_an_identical_id(self) -> None:
        first = finding_id(
            rule_id="policy.hardcoded-secrets",
            affected_agent=None,
            capability_path=None,
            evidence_paths=("config/secrets.yaml",),
        )
        second = finding_id(
            rule_id="policy.hardcoded-secrets",
            affected_agent=None,
            capability_path=None,
            evidence_paths=("config/secrets.yaml",),
        )
        assert first == second

    def test_different_resource_path_produces_a_different_identity(self) -> None:
        first = finding_id(
            rule_id="policy.hardcoded-secrets",
            affected_agent=None,
            capability_path=None,
            evidence_paths=("config/secrets.yaml",),
        )
        second = finding_id(
            rule_id="policy.hardcoded-secrets",
            affected_agent=None,
            capability_path=None,
            evidence_paths=("config/other.yaml",),
        )
        assert first != second

    def test_agent_scoped_and_repository_scoped_identities_never_collide(self) -> None:
        agent_scoped = finding_id(
            rule_id="policy.hardcoded-secrets",
            affected_agent=_AGENT_ID,
            capability_path=_path(),
        )
        repository_scoped = finding_id(
            rule_id="policy.hardcoded-secrets",
            affected_agent=None,
            capability_path=None,
            evidence_paths=("config/secrets.yaml",),
        )
        assert agent_scoped != repository_scoped

    def test_evidence_path_order_does_not_affect_identity(self) -> None:
        """`evidence_paths` is deduplicated and sorted before hashing, so
        this is stable regardless of which order a rule's own evidence
        happened to list its locations in."""

        first = finding_id(
            rule_id="policy.hardcoded-secrets",
            affected_agent=None,
            capability_path=None,
            evidence_paths=("b.yaml", "a.yaml"),
        )
        second = finding_id(
            rule_id="policy.hardcoded-secrets",
            affected_agent=None,
            capability_path=None,
            evidence_paths=("a.yaml", "b.yaml"),
        )
        assert first == second

    def test_agent_scoped_identity_is_unaffected_by_this_addition(self) -> None:
        """The existing agent-scoped payload shape must stay
        byte-for-byte unchanged: calling with an unused `evidence_paths`
        alongside a real agent must not perturb the computed ID."""

        without = finding_id(
            rule_id="policy.undeclared-tools",
            affected_agent=_AGENT_ID,
            capability_path=_path(),
        )
        with_unused_evidence_paths = finding_id(
            rule_id="policy.undeclared-tools",
            affected_agent=_AGENT_ID,
            capability_path=_path(),
            evidence_paths=("ignored.yaml",),
        )
        assert without == with_unused_evidence_paths


class TestIdentityExcludesNonSemanticFields:
    """The point of stable identity: the same underlying issue is recognizable
    between scans even when evidence, severity, confidence, change
    state, or presentation text legitimately differs run to run."""

    def _observation(self) -> RuleObservation:
        return RuleObservation(
            rule_id="policy.undeclared-tools",
            message="undeclared tool reachable",
            evidence=(Evidence(adapter="mcp", path="a.json", line_start=1),),
        )

    def test_identity_is_unaffected_by_evidence_line_numbers(self) -> None:
        path = _path(evidence=(Evidence(adapter="mcp", path="a.json", line_start=1),))
        other_path = _path(
            evidence=(Evidence(adapter="mcp", path="a.json", line_start=99),)
        )

        first = finding_id(
            rule_id="policy.rule-a", affected_agent=_AGENT_ID, capability_path=path
        )
        second = finding_id(
            rule_id="policy.rule-a",
            affected_agent=_AGENT_ID,
            capability_path=other_path,
        )
        assert first == second

    def test_identity_is_unaffected_by_severity_confidence_and_change_state(
        self,
    ) -> None:
        observation = self._observation()
        common = {
            "rule_version": "1.0.0",
            "affected_agent": _AGENT_ID,
            "capability_path": _path(),
            "remediation": "fix it",
            "documentation_url": "https://docs.controlloop.ai/x",
        }

        first = finding_from_observation(
            observation,
            severity=FindingSeverity.LOW,
            confidence=Confidence.LOW,
            change_state=FindingChangeState.NOT_COMPARED,
            **common,  # type: ignore[arg-type]
        )
        second = finding_from_observation(
            observation,
            severity=FindingSeverity.CRITICAL,
            confidence=Confidence.HIGH,
            change_state=FindingChangeState.ADDED,
            **common,  # type: ignore[arg-type]
        )

        assert first.id == second.id
        assert first.severity != second.severity
        assert first.change_state != second.change_state

    def test_identity_is_unaffected_by_message_remediation_url_and_rule_version(
        self,
    ) -> None:
        common = {
            "severity": FindingSeverity.HIGH,
            "confidence": Confidence.HIGH,
            "affected_agent": _AGENT_ID,
            "capability_path": _path(),
            "change_state": FindingChangeState.ADDED,
        }

        first = finding_from_observation(
            RuleObservation(
                rule_id="policy.undeclared-tools",
                message="first wording",
                evidence=(Evidence(adapter="mcp", path="a.json"),),
            ),
            rule_version="1.0.0",
            remediation="first remediation",
            documentation_url="https://docs.controlloop.ai/v1",
            **common,  # type: ignore[arg-type]
        )
        second = finding_from_observation(
            RuleObservation(
                rule_id="policy.undeclared-tools",
                message="clearer wording",
                evidence=(Evidence(adapter="mcp", path="a.json"),),
            ),
            rule_version="2.0.0",
            remediation="clearer remediation",
            documentation_url="https://docs.controlloop.ai/v2",
            **common,  # type: ignore[arg-type]
        )

        assert first.id == second.id
        assert first.message != second.message
        assert first.rule_version != second.rule_version
