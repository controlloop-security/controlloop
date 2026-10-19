"""Tests for controlloop.policy.rules.broad_permission."""

from __future__ import annotations

import io

import pytest

from controlloop import redaction
from controlloop.acbom.models import (
    ACBOMDocument,
    Confidence,
    Edge,
    EdgeStatus,
    EdgeType,
    Evidence,
    Generator,
    Node,
    NodeType,
    Repository,
    SecurityAttributes,
)
from controlloop.findings.models import FindingSeverity
from controlloop.findings.rendering import finding_to_sarif_result, render_finding_text
from controlloop.policy.models import RuleContext
from controlloop.policy.rules.broad_permission import RULE, evaluate, findings

_AGENT_ID = f"clp:agent:sha256:{'a' * 64}"
_IDENTITY_ID = f"clp:identity:sha256:{'b' * 64}"
_PERMISSION_ID = f"clp:permission:sha256:{'c' * 64}"
_OTHER_AGENT_ID = f"clp:agent:sha256:{'d' * 64}"
_AUTH_EDGE_ID = f"clp:edge:sha256:{'1' * 64}"
_PERMIT_EDGE_ID = f"clp:edge:sha256:{'2' * 64}"
_PLACEHOLDER_DIGEST = f"sha256:{'e' * 64}"

_EVIDENCE = (Evidence(adapter="iam", path="policies/statement.json", line_start=4),)


def _permission_node(
    node_id: str, name: str, permission_scopes: tuple[str, ...]
) -> Node:
    return Node(
        id=node_id,
        type=NodeType.PERMISSION,
        subtype="iam-statement",
        name=name,
        security_attributes=SecurityAttributes(permission_scopes=permission_scopes),
        confidence=Confidence.HIGH,
        evidence=_EVIDENCE,
    )


def _node(node_id: str, node_type: NodeType, name: str) -> Node:
    return Node(
        id=node_id,
        type=node_type,
        name=name,
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=_EVIDENCE,
    )


def _edge(edge_id: str, edge_type: EdgeType, source: str, target: str) -> Edge:
    return Edge(
        id=edge_id,
        source=source,
        target=target,
        type=edge_type,
        status=EdgeStatus.DIRECT,
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=_EVIDENCE,
    )


def _document(nodes: tuple[Node, ...], edges: tuple[Edge, ...]) -> ACBOMDocument:
    return ACBOMDocument(
        schema_version="1.0.0",
        generator=Generator(name="controlloop", version="0.1.0"),
        repository=Repository(commit="abc123", root_digest=_PLACEHOLDER_DIGEST),
        nodes=nodes,
        edges=edges,
        diagnostics=(),
        digest=_PLACEHOLDER_DIGEST,
    )


def _reachable_permission_document(permission_scopes: tuple[str, ...]) -> ACBOMDocument:
    agent = _node(_AGENT_ID, NodeType.AGENT, "refund-agent")
    identity = _node(_IDENTITY_ID, NodeType.IDENTITY, "service-account")
    permission = _permission_node(
        _PERMISSION_ID, "Allow: s3 actions", permission_scopes
    )
    edges = (
        _edge(_AUTH_EDGE_ID, EdgeType.AUTHENTICATES_AS, _AGENT_ID, _IDENTITY_ID),
        _edge(_PERMIT_EDGE_ID, EdgeType.PERMITTED_BY, _IDENTITY_ID, _PERMISSION_ID),
    )
    return _document((agent, identity, permission), edges)


class TestWildcardFires:
    """Wildcards in action or resource produce a finding stating what the
    grant permits in the worst case."""

    def test_wildcard_scope_produces_a_finding_naming_it(self) -> None:
        context = RuleContext(
            acbom=_reachable_permission_document(("s3:WILDCARD",)),
            policy_version="1",
        )

        observations = evaluate(context)

        assert len(observations) == 1
        assert "s3:WILDCARD" in observations[0].message
        assert "worst case" in observations[0].message

    def test_wildcard_produces_a_high_severity_finding_with_real_path(self) -> None:
        context = RuleContext(
            acbom=_reachable_permission_document(("s3:WILDCARD",)),
            policy_version="1",
        )

        results = findings(context)

        assert len(results) == 1
        finding = results[0]
        assert finding.severity is FindingSeverity.HIGH
        assert finding.confidence is Confidence.HIGH
        assert finding.affected_agent == _AGENT_ID
        assert finding.capability_path is not None
        assert finding.capability_path.target_id == _PERMISSION_ID
        assert len(finding.capability_path.hops) == 2


class TestUnevaluatedConditionFires:
    """A grant restricted by an unevaluated condition is reported as
    potentially broad, explicitly noting the condition was not evaluated."""

    def test_condition_only_grant_fires_at_reduced_certainty(self) -> None:
        context = RuleContext(
            acbom=_reachable_permission_document(("s3:GetObject", "condition:present")),
            policy_version="1",
        )

        results = findings(context)

        assert len(results) == 1
        finding = results[0]
        assert finding.severity is FindingSeverity.MEDIUM
        assert finding.confidence is Confidence.MEDIUM
        assert "condition" in finding.message.lower()
        assert "not evaluat" in finding.message.lower()

    def test_wildcard_and_condition_together_mentions_both(self) -> None:
        context = RuleContext(
            acbom=_reachable_permission_document(("s3:WILDCARD", "condition:present")),
            policy_version="1",
        )

        (finding,) = findings(context)

        assert finding.severity is FindingSeverity.HIGH  # wildcard dominates
        assert "condition" in finding.message.lower()
        assert "WILDCARD" in finding.message or "s3:WILDCARD" in finding.message


class TestNarrowGrantsProduceNoFinding:
    """Narrow grants produce no finding."""

    def test_narrow_scope_with_no_condition_produces_nothing(self) -> None:
        context = RuleContext(
            acbom=_reachable_permission_document(("s3:GetObject", "s3:PutObject")),
            policy_version="1",
        )

        assert evaluate(context) == ()
        assert findings(context) == ()

    def test_empty_scopes_produce_nothing(self) -> None:
        context = RuleContext(
            acbom=_reachable_permission_document(()), policy_version="1"
        )

        assert evaluate(context) == ()


class TestGenericOverSources:
    """The rule operates on canonical permission nodes, so it works
    identically for IAM, MCP, and OpenAPI sources -- no adapter-name branch
    exists."""

    @pytest.mark.parametrize("adapter_name", ["iam", "mcp", "openapi"])
    def test_wildcard_fires_regardless_of_originating_adapter(
        self, adapter_name: str
    ) -> None:
        agent = _node(_AGENT_ID, NodeType.AGENT, "refund-agent")
        identity = _node(_IDENTITY_ID, NodeType.IDENTITY, "service-account")
        permission = Node(
            id=_PERMISSION_ID,
            type=NodeType.PERMISSION,
            name="broad-scope",
            security_attributes=SecurityAttributes(
                permission_scopes=("resource:WILDCARD",)
            ),
            confidence=Confidence.HIGH,
            evidence=(Evidence(adapter=adapter_name, path="config.json"),),
        )
        edges = (
            _edge(_AUTH_EDGE_ID, EdgeType.AUTHENTICATES_AS, _AGENT_ID, _IDENTITY_ID),
            _edge(_PERMIT_EDGE_ID, EdgeType.PERMITTED_BY, _IDENTITY_ID, _PERMISSION_ID),
        )
        context = RuleContext(
            acbom=_document((agent, identity, permission), edges), policy_version="1"
        )

        assert len(evaluate(context)) == 1


class TestUnattributedPermissionIsNotDropped:
    def test_unreachable_broad_permission_is_an_advisory_observation_only(
        self,
    ) -> None:
        permission = _permission_node(
            _PERMISSION_ID, "orphan-statement", ("s3:WILDCARD",)
        )
        context = RuleContext(acbom=_document((permission,), ()), policy_version="1")

        observations = evaluate(context)

        assert len(observations) == 1
        assert "s3:WILDCARD" in observations[0].message
        assert findings(context) == ()


class TestBoundaryAndMalformed:
    def test_permission_reachable_by_two_agents_produces_two_findings(self) -> None:
        agent_one = _node(_AGENT_ID, NodeType.AGENT, "front-desk-agent")
        agent_two = _node(_OTHER_AGENT_ID, NodeType.AGENT, "billing-agent")
        identity = _node(_IDENTITY_ID, NodeType.IDENTITY, "shared-service-account")
        permission = _permission_node(
            _PERMISSION_ID, "Allow: s3 actions", ("s3:WILDCARD",)
        )
        edges = (
            _edge(_AUTH_EDGE_ID, EdgeType.AUTHENTICATES_AS, _AGENT_ID, _IDENTITY_ID),
            _edge(
                f"clp:edge:sha256:{'3' * 64}",
                EdgeType.AUTHENTICATES_AS,
                _OTHER_AGENT_ID,
                _IDENTITY_ID,
            ),
            _edge(_PERMIT_EDGE_ID, EdgeType.PERMITTED_BY, _IDENTITY_ID, _PERMISSION_ID),
        )
        context = RuleContext(
            acbom=_document((agent_one, agent_two, identity, permission), edges),
            policy_version="1",
        )

        results = findings(context)

        assert {result.affected_agent for result in results} == {
            _AGENT_ID,
            _OTHER_AGENT_ID,
        }

    def test_non_permission_node_with_similar_attributes_is_ignored(self) -> None:
        agent = _node(_AGENT_ID, NodeType.AGENT, "refund-agent")
        # A tool node cannot even carry permission_scopes meaningfully for
        # this rule since only NodeType.PERMISSION nodes are considered.
        tool = _node(_PERMISSION_ID, NodeType.TOOL, "refund-tool")
        edge = _edge(_AUTH_EDGE_ID, EdgeType.INVOKES, _AGENT_ID, _PERMISSION_ID)
        context = RuleContext(
            acbom=_document((agent, tool), (edge,)), policy_version="1"
        )

        assert evaluate(context) == ()


class TestDeterminism:
    def test_repeated_evaluation_is_byte_identical(self) -> None:
        context = RuleContext(
            acbom=_reachable_permission_document(("s3:WILDCARD",)),
            policy_version="1",
        )

        assert evaluate(context) == evaluate(context)
        assert findings(context) == findings(context)

    def test_rule_is_registered_under_a_stable_id(self) -> None:
        assert RULE.id == "policy.broad-permission"
        assert RULE.evaluate is evaluate


class TestOffline:
    def test_offline_harness_is_active_for_this_module(self) -> None:
        import socket

        with pytest.raises(RuntimeError, match="offline harness"):
            socket.socket()


class TestPrivacyCanary:
    def test_secret_shaped_permission_name_never_survives_rendering(self) -> None:
        planted_secret = "ghp_" + "c" * 36
        agent = _node(_AGENT_ID, NodeType.AGENT, "refund-agent")
        identity = _node(_IDENTITY_ID, NodeType.IDENTITY, "service-account")
        permission = _permission_node(_PERMISSION_ID, planted_secret, ("s3:WILDCARD",))
        edges = (
            _edge(_AUTH_EDGE_ID, EdgeType.AUTHENTICATES_AS, _AGENT_ID, _IDENTITY_ID),
            _edge(_PERMIT_EDGE_ID, EdgeType.PERMITTED_BY, _IDENTITY_ID, _PERMISSION_ID),
        )
        context = RuleContext(
            acbom=_document((agent, identity, permission), edges), policy_version="1"
        )

        (finding,) = findings(context)
        stdout_buffer = io.StringIO()
        with redaction.redirected_streams(target_stdout=stdout_buffer):
            print(render_finding_text(finding))
            print(finding.model_dump_json())
            print(finding_to_sarif_result(finding))

        output = stdout_buffer.getvalue()
        assert planted_secret not in output
        assert "controlloop:redacted:sha256:" in output
