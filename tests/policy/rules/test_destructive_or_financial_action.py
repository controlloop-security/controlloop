"""Tests for controlloop.policy.rules.destructive_or_financial_action."""

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
    Sensitivity,
)
from controlloop.diff.compute import compute_diff
from controlloop.diff.models import DiffResult
from controlloop.findings.models import FindingSeverity
from controlloop.findings.rendering import finding_to_sarif_result, render_finding_text
from controlloop.policy.models import RuleContext
from controlloop.policy.rules.destructive_or_financial_action import (
    RULE,
    evaluate,
    findings,
)

_AGENT_ID = f"clp:agent:sha256:{'a' * 64}"
_RESOURCE_ID = f"clp:resource:sha256:{'b' * 64}"
_DELEGATE_AGENT_ID = f"clp:agent:sha256:{'d' * 64}"
_WRITE_EDGE_ID = f"clp:edge:sha256:{'1' * 64}"
_DELEGATE_EDGE_ID = f"clp:edge:sha256:{'2' * 64}"
_PLACEHOLDER_DIGEST = f"sha256:{'e' * 64}"

_EVIDENCE = (Evidence(adapter="mcp", path="agents/refund-agent.json", line_start=3),)


def _node(
    node_id: str,
    node_type: NodeType,
    name: str,
    *,
    security_attributes: SecurityAttributes | None = None,
) -> Node:
    return Node(
        id=node_id,
        type=node_type,
        name=name,
        security_attributes=security_attributes or SecurityAttributes(),
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


def _diff_from(
    baseline_nodes: tuple[Node, ...],
    baseline_edges: tuple[Edge, ...],
    current_nodes: tuple[Node, ...],
    current_edges: tuple[Edge, ...],
) -> DiffResult:
    return compute_diff(
        baseline_nodes=baseline_nodes,
        baseline_edges=baseline_edges,
        current_nodes=current_nodes,
        current_edges=current_edges,
    )


class TestTaxonomyDriven:
    """Destructive and financial classes come from the capability taxonomy,
    never from matching a node's or edge's name."""

    def test_a_suggestively_named_resource_with_no_attribute_does_not_fire(
        self,
    ) -> None:
        agent = _node(_AGENT_ID, NodeType.AGENT, "refund-agent")
        resource = _node(
            _RESOURCE_ID, NodeType.RESOURCE, "delete-everything-destroy-db"
        )
        edge = _edge(_WRITE_EDGE_ID, EdgeType.WRITES, _AGENT_ID, _RESOURCE_ID)
        context = RuleContext(
            acbom=_document((agent, resource), (edge,)),
            policy_version="1",
            diff=_diff_from((agent, resource), (), (agent, resource), (edge,)),
        )

        assert evaluate(context) == ()

    def test_destructive_attribute_fires(self) -> None:
        agent = _node(_AGENT_ID, NodeType.AGENT, "refund-agent")
        resource = _node(
            _RESOURCE_ID,
            NodeType.RESOURCE,
            "billing-db",
            security_attributes=SecurityAttributes(destructive=True),
        )
        edge = _edge(_WRITE_EDGE_ID, EdgeType.WRITES, _AGENT_ID, _RESOURCE_ID)
        context = RuleContext(
            acbom=_document((agent, resource), (edge,)),
            policy_version="1",
            diff=_diff_from((agent, resource), (), (agent, resource), (edge,)),
        )

        observations = evaluate(context)

        assert len(observations) == 1
        assert "destructive-action" in observations[0].message

    def test_financial_attribute_fires(self) -> None:
        agent = _node(_AGENT_ID, NodeType.AGENT, "refund-agent")
        resource = _node(
            _RESOURCE_ID,
            NodeType.RESOURCE,
            "payments-ledger",
            security_attributes=SecurityAttributes(financial_action=True),
        )
        edge = _edge(_WRITE_EDGE_ID, EdgeType.WRITES, _AGENT_ID, _RESOURCE_ID)
        context = RuleContext(
            acbom=_document((agent, resource), (edge,)),
            policy_version="1",
            diff=_diff_from((agent, resource), (), (agent, resource), (edge,)),
        )

        observations = evaluate(context)

        assert len(observations) == 1
        assert "financial-action" in observations[0].message

    def test_unrelated_sensitive_data_class_does_not_fire(self) -> None:
        """Only destructive/financial classes are this rule's concern --
        a merely sensitive-data-access capability is a different rule's
        job entirely."""

        agent = _node(_AGENT_ID, NodeType.AGENT, "refund-agent")
        resource = _node(
            _RESOURCE_ID,
            NodeType.RESOURCE,
            "customer-records",
            security_attributes=SecurityAttributes(sensitivity=Sensitivity.RESTRICTED),
        )
        edge = _edge(_WRITE_EDGE_ID, EdgeType.WRITES, _AGENT_ID, _RESOURCE_ID)
        context = RuleContext(
            acbom=_document((agent, resource), (edge,)),
            policy_version="1",
            diff=_diff_from((agent, resource), (), (agent, resource), (edge,)),
        )

        assert evaluate(context) == ()


class TestNewlyGainedOnly:
    """The finding fires only on newly gained authority, asserted against an
    unchanged baseline."""

    def _destructive_document(self) -> tuple[Node, Node, Edge]:
        agent = _node(_AGENT_ID, NodeType.AGENT, "refund-agent")
        resource = _node(
            _RESOURCE_ID,
            NodeType.RESOURCE,
            "billing-db",
            security_attributes=SecurityAttributes(destructive=True),
        )
        edge = _edge(_WRITE_EDGE_ID, EdgeType.WRITES, _AGENT_ID, _RESOURCE_ID)
        return agent, resource, edge

    def test_unchanged_capability_does_not_fire(self) -> None:
        agent, resource, edge = self._destructive_document()
        current = _document((agent, resource), (edge,))
        context = RuleContext(
            acbom=current,
            policy_version="1",
            diff=_diff_from((agent, resource), (edge,), (agent, resource), (edge,)),
        )

        assert evaluate(context) == ()

    def test_removed_capability_does_not_fire(self) -> None:
        agent, resource, edge = self._destructive_document()
        current = _document((agent, resource), ())
        context = RuleContext(
            acbom=current,
            policy_version="1",
            diff=_diff_from((agent, resource), (edge,), (agent, resource), ()),
        )

        assert evaluate(context) == ()

    def test_no_diff_at_all_produces_nothing(self) -> None:
        agent, resource, edge = self._destructive_document()
        context = RuleContext(
            acbom=_document((agent, resource), (edge,)), policy_version="1", diff=None
        )

        assert evaluate(context) == ()
        assert findings(context) == ()


#: `compute_transitive_capability_paths` only ever chains through
#: `invokes`, `delegates-to`, `authenticates-as`, and `permitted-by`
#: edges (confirmed by reading `controlloop.capability.compute` in
#: full) -- a `reads`/`writes` action edge is never part of any
#: transitive path, including its final hop. A resource reached only by
#: a direct write is therefore always a *direct* fact
#: (`TestNewlyGainedOnly`'s territory), never a transitive one; a genuinely transitive
#: destructive/financial reach requires the target itself -- typically
#: a tool -- to carry the classifying attribute.
_INVOKE_EDGE_ID = f"clp:edge:sha256:{'3' * 64}"


class TestTransitiveAuthority:
    """Authority gained transitively fires the rule, with its path
    reported."""

    def test_new_delegation_to_existing_destructive_tool_reach_fires(self) -> None:
        front_desk = _node(_AGENT_ID, NodeType.AGENT, "front-desk-agent")
        billing_agent = _node(_DELEGATE_AGENT_ID, NodeType.AGENT, "billing-agent")
        tool = _node(
            _RESOURCE_ID,
            NodeType.TOOL,
            "delete-account-tool",
            security_attributes=SecurityAttributes(destructive=True),
        )
        invoke_edge = _edge(
            _INVOKE_EDGE_ID, EdgeType.INVOKES, _DELEGATE_AGENT_ID, _RESOURCE_ID
        )
        delegate_edge = _edge(
            _DELEGATE_EDGE_ID, EdgeType.DELEGATES_TO, _AGENT_ID, _DELEGATE_AGENT_ID
        )
        nodes = (front_desk, billing_agent, tool)
        baseline_edges = (invoke_edge,)  # billing-agent's own reach pre-exists
        current_edges = (invoke_edge, delegate_edge)  # front-desk newly delegates

        context = RuleContext(
            acbom=_document(nodes, current_edges),
            policy_version="1",
            diff=_diff_from(nodes, baseline_edges, nodes, current_edges),
        )

        results = findings(context)

        assert len(results) == 1
        finding = results[0]
        assert finding.affected_agent == _AGENT_ID
        assert finding.capability_path is not None
        assert len(finding.capability_path.hops) == 2
        assert finding.capability_path.hops[0].edge_id == _DELEGATE_EDGE_ID
        assert finding.capability_path.hops[1].edge_id == _INVOKE_EDGE_ID

    def test_transitive_path_of_only_preexisting_edges_does_not_fire(self) -> None:
        front_desk = _node(_AGENT_ID, NodeType.AGENT, "front-desk-agent")
        billing_agent = _node(_DELEGATE_AGENT_ID, NodeType.AGENT, "billing-agent")
        tool = _node(
            _RESOURCE_ID,
            NodeType.TOOL,
            "delete-account-tool",
            security_attributes=SecurityAttributes(destructive=True),
        )
        invoke_edge = _edge(
            _INVOKE_EDGE_ID, EdgeType.INVOKES, _DELEGATE_AGENT_ID, _RESOURCE_ID
        )
        delegate_edge = _edge(
            _DELEGATE_EDGE_ID, EdgeType.DELEGATES_TO, _AGENT_ID, _DELEGATE_AGENT_ID
        )
        nodes = (front_desk, billing_agent, tool)
        edges = (invoke_edge, delegate_edge)

        context = RuleContext(
            acbom=_document(nodes, edges),
            policy_version="1",
            diff=_diff_from(nodes, edges, nodes, edges),  # nothing changed
        )

        assert findings(context) == ()

    def test_new_direct_write_to_a_resource_is_not_treated_as_transitive(
        self,
    ) -> None:
        """A reads/writes edge is never part of a transitive path -- this
        is exercised end to end by TestNewlyGainedOnly and
        TestReferenceRefundScenario, whose findings must each carry
        exactly a one-hop, direct capability path."""

        agent = _node(_AGENT_ID, NodeType.AGENT, "refund-agent")
        resource = _node(
            _RESOURCE_ID,
            NodeType.RESOURCE,
            "billing-db",
            security_attributes=SecurityAttributes(destructive=True),
        )
        edge = _edge(_WRITE_EDGE_ID, EdgeType.WRITES, _AGENT_ID, _RESOURCE_ID)
        context = RuleContext(
            acbom=_document((agent, resource), (edge,)),
            policy_version="1",
            diff=_diff_from((agent, resource), (), (agent, resource), (edge,)),
        )

        (finding,) = findings(context)

        assert finding.capability_path is not None
        assert len(finding.capability_path.hops) == 1


#: The same "refund-agent"/"billing-db" reference scenario
#: `tests/concepts/reference_fixture.py` establishes as this
#: codebase's own shared worked example -- same node IDs and names,
#: reconstructed locally rather than cross-imported, since pytest's
#: default "prepend" import mode does not make a sibling test
#: directory's bare module name importable across directories without
#: an explicit `pythonpath` configuration this repository does not set.
_REFUND_AGENT_ID = f"clp:agent:sha256:{'a' * 64}"
_BILLING_DB_ID = f"clp:resource:sha256:{'d' * 64}"
_REFUND_WRITE_EDGE_ID = f"clp:edge:sha256:{'2' * 64}"


class TestReferenceRefundScenario:
    """The reference refund scenario fires this rule at the expected
    severity."""

    def test_refund_scenario_fires_at_high_severity(self) -> None:
        refund_agent = _node(_REFUND_AGENT_ID, NodeType.AGENT, "refund-agent")
        billing_db = _node(
            _BILLING_DB_ID,
            NodeType.RESOURCE,
            "billing-db",
            security_attributes=SecurityAttributes(
                destructive=True, sensitivity=Sensitivity.RESTRICTED
            ),
        )
        write_edge = _edge(
            _REFUND_WRITE_EDGE_ID, EdgeType.WRITES, _REFUND_AGENT_ID, _BILLING_DB_ID
        )
        nodes = (refund_agent, billing_db)
        context = RuleContext(
            acbom=_document(nodes, (write_edge,)),
            policy_version="1",
            diff=_diff_from(nodes, (), nodes, (write_edge,)),
        )

        results = findings(context)

        assert len(results) == 1
        finding = results[0]
        assert finding.severity is FindingSeverity.HIGH
        assert finding.affected_agent == _REFUND_AGENT_ID
        assert finding.capability_path is not None
        assert finding.capability_path.target_id == _BILLING_DB_ID


class TestDeterminism:
    def test_repeated_evaluation_is_byte_identical(self) -> None:
        agent = _node(_AGENT_ID, NodeType.AGENT, "refund-agent")
        resource = _node(
            _RESOURCE_ID,
            NodeType.RESOURCE,
            "billing-db",
            security_attributes=SecurityAttributes(destructive=True),
        )
        edge = _edge(_WRITE_EDGE_ID, EdgeType.WRITES, _AGENT_ID, _RESOURCE_ID)
        context = RuleContext(
            acbom=_document((agent, resource), (edge,)),
            policy_version="1",
            diff=_diff_from((agent, resource), (), (agent, resource), (edge,)),
        )

        assert evaluate(context) == evaluate(context)
        assert findings(context) == findings(context)

    def test_rule_is_registered_under_a_stable_id(self) -> None:
        assert RULE.id == "policy.destructive-or-financial-action"
        assert RULE.evaluate is evaluate


class TestOffline:
    def test_offline_harness_is_active_for_this_module(self) -> None:
        import socket

        with pytest.raises(RuntimeError, match="offline harness"):
            socket.socket()


class TestPrivacyCanary:
    def test_secret_shaped_resource_name_never_survives_rendering(self) -> None:
        planted_secret = "ghp_" + "b" * 36
        agent = _node(_AGENT_ID, NodeType.AGENT, "refund-agent")
        resource = _node(
            _RESOURCE_ID,
            NodeType.RESOURCE,
            planted_secret,
            security_attributes=SecurityAttributes(destructive=True),
        )
        edge = _edge(_WRITE_EDGE_ID, EdgeType.WRITES, _AGENT_ID, _RESOURCE_ID)
        context = RuleContext(
            acbom=_document((agent, resource), (edge,)),
            policy_version="1",
            diff=_diff_from((agent, resource), (), (agent, resource), (edge,)),
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
