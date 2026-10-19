"""Tests for controlloop.policy.rules.undeclared_tools."""

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
from controlloop.findings.rendering import finding_to_sarif_result, render_finding_text
from controlloop.manifest.models import (
    CURRENT_MANIFEST_SCHEMA_VERSION,
    Approval,
    ManifestDocument,
)
from controlloop.policy.models import RuleContext
from controlloop.policy.rules.undeclared_tools import RULE, evaluate, findings

_AGENT_ID = f"clp:agent:sha256:{'a' * 64}"
_TOOL_ID = f"clp:tool:sha256:{'b' * 64}"
_OTHER_AGENT_ID = f"clp:agent:sha256:{'c' * 64}"
_DELEGATE_TOOL_ID = f"clp:tool:sha256:{'d' * 64}"
_INVOKE_EDGE_ID = f"clp:edge:sha256:{'1' * 64}"
_DELEGATE_EDGE_ID = f"clp:edge:sha256:{'2' * 64}"
_DELEGATE_INVOKE_EDGE_ID = f"clp:edge:sha256:{'3' * 64}"
_PLACEHOLDER_DIGEST = f"sha256:{'e' * 64}"

_EVIDENCE = (Evidence(adapter="mcp", path="agents/refund-agent.json", line_start=3),)


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


def _single_tool_document(tool_name: str = "refund-tool") -> ACBOMDocument:
    agent = _node(_AGENT_ID, NodeType.AGENT, "refund-agent")
    tool = _node(_TOOL_ID, NodeType.TOOL, tool_name)
    edge = _edge(_INVOKE_EDGE_ID, EdgeType.INVOKES, _AGENT_ID, _TOOL_ID)
    return _document((agent, tool), (edge,))


def _manifest(*capabilities: str) -> ManifestDocument:
    return ManifestDocument(
        schema_version=CURRENT_MANIFEST_SCHEMA_VERSION,
        owner="platform-team",
        approvals=tuple(
            Approval(capability=capability, approver="platform-team")
            for capability in capabilities
        ),
    )


class TestUndeclaredToolFires:
    """A discovered tool absent from the manifest produces a finding naming
    the tool and where it was discovered."""

    def test_undeclared_tool_produces_an_observation_naming_it(self) -> None:
        context = RuleContext(
            acbom=_single_tool_document(),
            policy_version="1",
            manifest=_manifest("some-other-capability"),
        )

        observations = evaluate(context)

        assert len(observations) == 1
        assert observations[0].rule_id == "policy.undeclared-tools"
        assert "refund-tool" in observations[0].message
        assert observations[0].evidence == _EVIDENCE

    def test_undeclared_tool_produces_a_finding_with_the_real_path(self) -> None:
        context = RuleContext(
            acbom=_single_tool_document(),
            policy_version="1",
            manifest=_manifest(),
        )

        results = findings(context)

        assert len(results) == 1
        finding = results[0]
        assert finding.affected_agent == _AGENT_ID
        assert finding.capability_path is not None
        assert finding.capability_path.agent_id == _AGENT_ID
        assert finding.capability_path.target_id == _TOOL_ID
        assert finding.capability_path.target_type is NodeType.TOOL
        assert finding.capability_path.hops[0].edge_id == _INVOKE_EDGE_ID
        assert finding.rule_id == "policy.undeclared-tools"

    def test_undeclared_tool_reachable_only_transitively_still_fires(self) -> None:
        """A tool reached through delegation, at two hops, must not be
        silently missed -- 'silently dropped capability produces a
        confident pass' is this product's worst failure mode. Both the
        delegating agent's direct one-hop reach and the delegator's own
        two-hop transitive reach are distinct real facts, so both produce
        their own finding."""

        agent = _node(_AGENT_ID, NodeType.AGENT, "front-desk-agent")
        delegate = _node(_OTHER_AGENT_ID, NodeType.AGENT, "billing-agent")
        tool = _node(_DELEGATE_TOOL_ID, NodeType.TOOL, "billing-tool")
        edges = (
            _edge(_DELEGATE_EDGE_ID, EdgeType.DELEGATES_TO, _AGENT_ID, _OTHER_AGENT_ID),
            _edge(
                _DELEGATE_INVOKE_EDGE_ID,
                EdgeType.INVOKES,
                _OTHER_AGENT_ID,
                _DELEGATE_TOOL_ID,
            ),
        )
        context = RuleContext(
            acbom=_document((agent, delegate, tool), edges),
            policy_version="1",
            manifest=_manifest(),
        )

        results = findings(context)

        by_agent = {result.affected_agent: result for result in results}
        assert set(by_agent) == {_AGENT_ID, _OTHER_AGENT_ID}
        other_path = by_agent[_OTHER_AGENT_ID].capability_path
        agent_path = by_agent[_AGENT_ID].capability_path
        assert other_path is not None
        assert agent_path is not None
        assert len(other_path.hops) == 1
        assert len(agent_path.hops) == 2


class TestDeclaredToolProducesNoFinding:
    """A declared tool produces no finding."""

    def test_matching_approval_suppresses_the_finding(self) -> None:
        context = RuleContext(
            acbom=_single_tool_document("refund-tool"),
            policy_version="1",
            manifest=_manifest("refund-tool"),
        )

        assert evaluate(context) == ()
        assert findings(context) == ()

    def test_non_matching_approval_still_fires(self) -> None:
        context = RuleContext(
            acbom=_single_tool_document("refund-tool"),
            policy_version="1",
            manifest=_manifest("unrelated-tool"),
        )

        assert len(evaluate(context)) == 1


class TestNoManifestPresent:
    """With no manifest present, the rule reports the count without failing,
    and says a manifest would improve the result."""

    def test_no_manifest_reports_count_and_suggests_a_manifest(self) -> None:
        context = RuleContext(
            acbom=_single_tool_document(), policy_version="1", manifest=None
        )

        observations = evaluate(context)

        assert len(observations) == 1
        assert "1 tool" in observations[0].message
        assert "manifest" in observations[0].message.lower()

    def test_no_manifest_never_raises(self) -> None:
        context = RuleContext(
            acbom=_single_tool_document(), policy_version="1", manifest=None
        )

        evaluate(context)  # must not raise

    def test_no_manifest_produces_no_findings(self) -> None:
        """The count-only advisory has no natural single affected agent
        and is deliberately never promoted through finding_from_observation."""

        context = RuleContext(
            acbom=_single_tool_document(), policy_version="1", manifest=None
        )

        assert findings(context) == ()

    def test_no_manifest_with_no_reachable_tools_reports_zero(self) -> None:
        agent = _node(_AGENT_ID, NodeType.AGENT, "idle-agent")
        context = RuleContext(
            acbom=_document((agent,), ()), policy_version="1", manifest=None
        )

        observations = evaluate(context)

        assert "0 tool" in observations[0].message


class TestBoundaryAndMalformed:
    def test_reachable_resource_is_not_reported_as_a_tool(self) -> None:
        """Only NodeType.TOOL targets are in scope for this rule -- a
        reachable resource (or any other capability category) must not be
        misreported as an undeclared tool."""

        agent = _node(_AGENT_ID, NodeType.AGENT, "refund-agent")
        resource = _node(_TOOL_ID, NodeType.RESOURCE, "billing-db")
        edge = _edge(_INVOKE_EDGE_ID, EdgeType.WRITES, _AGENT_ID, _TOOL_ID)
        context = RuleContext(
            acbom=_document((agent, resource), (edge,)),
            policy_version="1",
            manifest=_manifest(),
        )

        assert evaluate(context) == ()
        assert findings(context) == ()

    def test_bound_exceeded_transitive_walk_is_reported_not_dropped(self) -> None:
        """A delegation chain deeper than the transitive walk's default
        bound must surface its own incompleteness, never a silent,
        confident 'nothing found'."""

        chain_length = 8  # exceeds the default max_depth of 5
        agents = [
            _node(
                f"clp:agent:sha256:{str(index).zfill(2) * 32}",
                NodeType.AGENT,
                f"agent-{index}",
            )
            for index in range(chain_length)
        ]
        tool = _node(_TOOL_ID, NodeType.TOOL, "deep-tool")
        edges = [
            _edge(
                f"clp:edge:sha256:{str(index).zfill(2) * 32}",
                EdgeType.DELEGATES_TO,
                agents[index].id,
                agents[index + 1].id,
            )
            for index in range(chain_length - 1)
        ]
        edges.append(_edge(_INVOKE_EDGE_ID, EdgeType.INVOKES, agents[-1].id, _TOOL_ID))
        context = RuleContext(
            acbom=_document((*agents, tool), tuple(edges)),
            policy_version="1",
            manifest=_manifest(),
        )

        observations = evaluate(context)

        assert any(
            "could not fully explore" in observation.message
            for observation in observations
        )

    def test_empty_document_produces_nothing(self) -> None:
        context = RuleContext(
            acbom=_document((), ()), policy_version="1", manifest=_manifest()
        )

        assert evaluate(context) == ()
        assert findings(context) == ()

    def test_manifest_with_no_approvals_still_flags_every_tool(self) -> None:
        context = RuleContext(
            acbom=_single_tool_document(),
            policy_version="1",
            manifest=ManifestDocument(
                schema_version=CURRENT_MANIFEST_SCHEMA_VERSION, owner="platform-team"
            ),
        )

        assert len(evaluate(context)) == 1

    def test_tool_reachable_by_two_routes_is_reported_once(self) -> None:
        agent = _node(_AGENT_ID, NodeType.AGENT, "refund-agent")
        tool = _node(_TOOL_ID, NodeType.TOOL, "refund-tool")
        edge_one = _edge(_INVOKE_EDGE_ID, EdgeType.INVOKES, _AGENT_ID, _TOOL_ID)
        edge_two = _edge(
            f"clp:edge:sha256:{'9' * 64}", EdgeType.READS, _AGENT_ID, _TOOL_ID
        )
        context = RuleContext(
            acbom=_document((agent, tool), (edge_one, edge_two)),
            policy_version="1",
            manifest=_manifest(),
        )

        assert len(evaluate(context)) == 1


class TestDeterminism:
    """Identical input produces an identical verdict."""

    def test_repeated_evaluation_is_byte_identical(self) -> None:
        context = RuleContext(
            acbom=_single_tool_document(), policy_version="1", manifest=_manifest()
        )

        first = evaluate(context)
        second = evaluate(context)

        assert first == second
        assert findings(context) == findings(context)

    def test_rule_is_registered_under_a_stable_id(self) -> None:
        assert RULE.id == "policy.undeclared-tools"
        assert RULE.evaluate is evaluate


class TestOffline:
    def test_offline_harness_is_active_for_this_module(self) -> None:
        import socket

        with pytest.raises(RuntimeError, match="offline harness"):
            socket.socket()


class TestPrivacyCanary:
    """A secret-shaped value planted in discovered evidence must never
    survive rendering. Mirrors controlloop.findings' own canary
    discipline (docs/reference/finding-model.md, 'Privacy')."""

    def test_secret_shaped_tool_name_never_survives_rendering(self) -> None:
        planted_secret = "ghp_" + "a" * 36
        context = RuleContext(
            acbom=_single_tool_document(tool_name=planted_secret),
            policy_version="1",
            manifest=_manifest(),
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
