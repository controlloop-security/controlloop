"""Tests for controlloop.policy.rules.exfiltration_triangle."""

from __future__ import annotations

import pytest
from _helpers import (
    acbom,
    agent_node,
    context,
    hex_id,
    invokes_edge,
    receives_from_edge,
    resource_node,
    tool_node,
    trigger_node,
)

from controlloop.acbom.models import Confidence, Node, SecurityAttributes, Sensitivity
from controlloop.findings.models import FindingChangeState, FindingSeverity
from controlloop.policy import engine as engine_module
from controlloop.policy.engine import evaluate as engine_evaluate
from controlloop.policy.models import RuleContext
from controlloop.policy.rules import exfiltration_triangle as rule_module
from controlloop.policy.rules.exfiltration_triangle import (
    RULE,
    RULE_ID,
    evaluate,
    findings,
)

_AGENT_ID = hex_id("agent", "a")
_RESOURCE_ID = hex_id("resource", "b")
_TRIGGER_ID = hex_id("trigger", "c")
_TOOL_ID = hex_id("tool", "d")
_TOOL_A_ID = hex_id("tool", "1")
_TOOL_B_ID = hex_id("tool", "2")

_RESOURCE_EDGE_ID = hex_id("edge", "1")
_RECEIVES_EDGE_ID = hex_id("edge", "2")
_TOOL_EDGE_ID = hex_id("edge", "3")
_TOOL_A_EDGE_ID = hex_id("edge", "4")
_TOOL_B_EDGE_ID = hex_id("edge", "5")

_SENSITIVE = SecurityAttributes(sensitivity=Sensitivity.CONFIDENTIAL)
_SENSITIVE_UNKNOWN = SecurityAttributes(sensitivity=Sensitivity.UNKNOWN)
_EXTERNAL_COMM = SecurityAttributes(external_communication=True)
_EXTERNAL_COMM_UNKNOWN = SecurityAttributes(external_communication="unknown")


def _agent() -> Node:
    return agent_node(_AGENT_ID, name="support-agent")


def _sensitive_resource(security_attributes: SecurityAttributes = _SENSITIVE) -> Node:
    return resource_node(
        _RESOURCE_ID, name="customer-records", security_attributes=security_attributes
    )


def _trigger() -> Node:
    return trigger_node(_TRIGGER_ID, name="support-ticket-created")


def _comm_tool(security_attributes: SecurityAttributes = _EXTERNAL_COMM) -> Node:
    return tool_node(
        _TOOL_ID, name="notify-webhook", security_attributes=security_attributes
    )


def _full_triangle_context() -> RuleContext:
    """All three legs, all direct, on one agent."""

    return context(
        acbom=acbom(
            nodes=(_agent(), _sensitive_resource(), _trigger(), _comm_tool()),
            edges=(
                invokes_edge(_RESOURCE_EDGE_ID, source=_AGENT_ID, target=_RESOURCE_ID),
                receives_from_edge(
                    _RECEIVES_EDGE_ID, source=_AGENT_ID, target=_TRIGGER_ID
                ),
                invokes_edge(_TOOL_EDGE_ID, source=_AGENT_ID, target=_TOOL_ID),
            ),
        )
    )


class TestPositive:
    def test_all_three_direct_legs_produce_one_observation(self) -> None:
        result = evaluate(_full_triangle_context())

        assert len(result) == 1
        message = result[0].message
        assert "sensitive-data-access" in message
        assert "untrusted-input" in message
        assert "external-communication" in message
        assert "customer-records" in message
        assert "support-ticket-created" in message
        assert "notify-webhook" in message

    def test_all_three_direct_legs_produce_one_critical_finding(self) -> None:
        result = findings(_full_triangle_context())

        assert len(result) == 1
        finding = result[0]
        assert finding.rule_id == RULE_ID
        assert finding.affected_agent == _AGENT_ID
        assert finding.severity is FindingSeverity.CRITICAL
        # capability_path is the external-communication leg's path (a
        # design decision in the rule module: preferred over
        # sensitive-data-access).
        assert finding.capability_path is not None
        assert finding.capability_path.agent_id == _AGENT_ID
        assert finding.capability_path.target_id == _TOOL_ID
        assert finding.change_state is FindingChangeState.NOT_COMPARED

    def test_transitive_external_communication_leg_still_counts(self) -> None:
        """The external-communication leg reached only transitively (agent
        -invokes-> tool-a -invokes-> tool-b, with tool-b carrying
        external_communication=True) still counts, while
        sensitive-data-access and untrusted-input stay direct."""

        tool_a = tool_node(_TOOL_A_ID, name="dispatcher")
        tool_b = tool_node(
            _TOOL_B_ID, name="external-relay", security_attributes=_EXTERNAL_COMM
        )
        ctx = context(
            acbom=acbom(
                nodes=(_agent(), _sensitive_resource(), _trigger(), tool_a, tool_b),
                edges=(
                    invokes_edge(
                        _RESOURCE_EDGE_ID, source=_AGENT_ID, target=_RESOURCE_ID
                    ),
                    receives_from_edge(
                        _RECEIVES_EDGE_ID, source=_AGENT_ID, target=_TRIGGER_ID
                    ),
                    invokes_edge(_TOOL_A_EDGE_ID, source=_AGENT_ID, target=_TOOL_A_ID),
                    invokes_edge(_TOOL_B_EDGE_ID, source=_TOOL_A_ID, target=_TOOL_B_ID),
                ),
            )
        )

        result = findings(ctx)

        assert len(result) == 1
        finding = result[0]
        assert finding.severity is FindingSeverity.CRITICAL
        assert finding.capability_path is not None
        assert finding.capability_path.target_id == _TOOL_B_ID
        assert len(finding.capability_path.hops) == 2


class TestNegativePairs:
    """Two of three legs, asserted separately per pair, produce no triangle
    finding."""

    def test_sensitive_and_untrusted_only_produces_nothing(self) -> None:
        ctx = context(
            acbom=acbom(
                nodes=(_agent(), _sensitive_resource(), _trigger()),
                edges=(
                    invokes_edge(
                        _RESOURCE_EDGE_ID, source=_AGENT_ID, target=_RESOURCE_ID
                    ),
                    receives_from_edge(
                        _RECEIVES_EDGE_ID, source=_AGENT_ID, target=_TRIGGER_ID
                    ),
                ),
            )
        )

        assert evaluate(ctx) == ()
        assert findings(ctx) == ()

    def test_sensitive_and_comm_only_produces_nothing(self) -> None:
        ctx = context(
            acbom=acbom(
                nodes=(_agent(), _sensitive_resource(), _comm_tool()),
                edges=(
                    invokes_edge(
                        _RESOURCE_EDGE_ID, source=_AGENT_ID, target=_RESOURCE_ID
                    ),
                    invokes_edge(_TOOL_EDGE_ID, source=_AGENT_ID, target=_TOOL_ID),
                ),
            )
        )

        assert evaluate(ctx) == ()
        assert findings(ctx) == ()

    def test_untrusted_and_comm_only_produces_nothing(self) -> None:
        ctx = context(
            acbom=acbom(
                nodes=(_agent(), _trigger(), _comm_tool()),
                edges=(
                    receives_from_edge(
                        _RECEIVES_EDGE_ID, source=_AGENT_ID, target=_TRIGGER_ID
                    ),
                    invokes_edge(_TOOL_EDGE_ID, source=_AGENT_ID, target=_TOOL_ID),
                ),
            )
        )

        assert evaluate(ctx) == ()
        assert findings(ctx) == ()


class TestQualifiedFinding:
    """Exactly two legs present plus the third genuinely unknown produces a
    qualified finding naming the unproven leg, never silence or a confident
    top-severity claim."""

    def test_unknown_sensitivity_with_the_other_two_legs_present(self) -> None:
        ctx = context(
            acbom=acbom(
                nodes=(
                    _agent(),
                    _sensitive_resource(_SENSITIVE_UNKNOWN),
                    _trigger(),
                    _comm_tool(),
                ),
                edges=(
                    invokes_edge(
                        _RESOURCE_EDGE_ID, source=_AGENT_ID, target=_RESOURCE_ID
                    ),
                    receives_from_edge(
                        _RECEIVES_EDGE_ID, source=_AGENT_ID, target=_TRIGGER_ID
                    ),
                    invokes_edge(_TOOL_EDGE_ID, source=_AGENT_ID, target=_TOOL_ID),
                ),
            )
        )

        observations = evaluate(ctx)
        assert len(observations) == 1
        assert "sensitive-data-access" in observations[0].message
        assert "unknown" in observations[0].message

        result = findings(ctx)
        assert len(result) == 1
        finding = result[0]
        assert finding.severity is FindingSeverity.HIGH
        assert finding.confidence is Confidence.UNKNOWN
        # capability_path falls back to the (present) external-comm leg.
        assert finding.capability_path is not None
        assert finding.capability_path.target_id == _TOOL_ID

    def test_unknown_external_communication_with_the_other_two_legs_present(
        self,
    ) -> None:
        ctx = context(
            acbom=acbom(
                nodes=(
                    _agent(),
                    _sensitive_resource(),
                    _trigger(),
                    _comm_tool(_EXTERNAL_COMM_UNKNOWN),
                ),
                edges=(
                    invokes_edge(
                        _RESOURCE_EDGE_ID, source=_AGENT_ID, target=_RESOURCE_ID
                    ),
                    receives_from_edge(
                        _RECEIVES_EDGE_ID, source=_AGENT_ID, target=_TRIGGER_ID
                    ),
                    invokes_edge(_TOOL_EDGE_ID, source=_AGENT_ID, target=_TOOL_ID),
                ),
            )
        )

        result = findings(ctx)
        assert len(result) == 1
        finding = result[0]
        assert finding.severity is FindingSeverity.HIGH
        assert finding.confidence is Confidence.UNKNOWN
        assert "external-communication" in finding.message
        # capability_path falls back to the (present) sensitive-data leg,
        # since the external-comm leg itself has no confirmed path here.
        assert finding.capability_path is not None
        assert finding.capability_path.target_id == _RESOURCE_ID


class TestBoundary:
    def test_empty_acbom_produces_nothing(self) -> None:
        ctx = context()
        assert evaluate(ctx) == ()
        assert findings(ctx) == ()

    def test_receives_from_edge_from_a_non_agent_source_is_ignored(self) -> None:
        """A receives-from edge sourced at a tool, not the agent, must
        not count toward that agent's untrusted-input leg -- leaving
        only sensitive-data-access and external-communication present,
        which is `TestNegativePairs`' own two-leg negative case, not a
        qualified or full finding."""

        ctx = context(
            acbom=acbom(
                nodes=(_agent(), _sensitive_resource(), _trigger(), _comm_tool()),
                edges=(
                    invokes_edge(
                        _RESOURCE_EDGE_ID, source=_AGENT_ID, target=_RESOURCE_ID
                    ),
                    invokes_edge(_TOOL_EDGE_ID, source=_AGENT_ID, target=_TOOL_ID),
                    receives_from_edge(
                        _RECEIVES_EDGE_ID, source=_TOOL_ID, target=_TRIGGER_ID
                    ),
                ),
            )
        )

        assert evaluate(ctx) == ()
        assert findings(ctx) == ()

    def test_one_leg_present_with_two_unknown_legs_produces_nothing(self) -> None:
        """The rule's firing threshold: at least two legs must
        be definitively PRESENT. One present plus two unknown never
        fires, even though "something is unproven" is technically true
        of two legs at once here."""

        ctx = context(
            acbom=acbom(
                nodes=(
                    _agent(),
                    _sensitive_resource(_SENSITIVE_UNKNOWN),
                    _comm_tool(_EXTERNAL_COMM_UNKNOWN),
                ),
                edges=(
                    invokes_edge(
                        _RESOURCE_EDGE_ID, source=_AGENT_ID, target=_RESOURCE_ID
                    ),
                    invokes_edge(_TOOL_EDGE_ID, source=_AGENT_ID, target=_TOOL_ID),
                ),
            )
        )

        assert evaluate(ctx) == ()
        assert findings(ctx) == ()

    def test_agent_with_no_edges_produces_nothing(self) -> None:
        ctx = context(acbom=acbom(nodes=(_agent(),)))
        assert evaluate(ctx) == ()
        assert findings(ctx) == ()


class TestDeterminism:
    def test_identical_context_twice_produces_identical_result(self) -> None:
        ctx = _full_triangle_context()
        assert evaluate(ctx) == evaluate(ctx)
        assert findings(ctx) == findings(ctx)

    def test_shuffled_node_and_edge_order_produces_identical_result(self) -> None:
        agent = _agent()
        resource = _sensitive_resource()
        trigger = _trigger()
        tool = _comm_tool()
        resource_edge = invokes_edge(
            _RESOURCE_EDGE_ID, source=_AGENT_ID, target=_RESOURCE_ID
        )
        receives_edge = receives_from_edge(
            _RECEIVES_EDGE_ID, source=_AGENT_ID, target=_TRIGGER_ID
        )
        tool_edge = invokes_edge(_TOOL_EDGE_ID, source=_AGENT_ID, target=_TOOL_ID)

        forward = context(
            acbom=acbom(
                nodes=(agent, resource, trigger, tool),
                edges=(resource_edge, receives_edge, tool_edge),
            )
        )
        reverse = context(
            acbom=acbom(
                nodes=(tool, trigger, resource, agent),
                edges=(tool_edge, receives_edge, resource_edge),
            )
        )

        assert evaluate(forward) == evaluate(reverse)
        assert findings(forward) == findings(reverse)


class TestEngineIntegration:
    def test_registers_and_runs_through_the_real_engine(self) -> None:
        result = engine_evaluate((RULE,), _full_triangle_context())
        assert len(result.observations) == 1
        assert result.observations[0].rule_id == RULE_ID


class TestStructuralSafety:
    def test_module_has_no_forbidden_imports(self) -> None:
        assert engine_module.module_forbidden_imports(rule_module) == frozenset()


class TestOffline:
    def test_offline_harness_is_active_for_this_module(self) -> None:
        import socket

        with pytest.raises(RuntimeError, match="offline harness"):
            socket.socket()


class TestPrivacy:
    def test_no_raw_content_path_exists(self) -> None:
        assert engine_module.module_forbidden_imports(rule_module) == frozenset()


def _inferred_triangle_context() -> RuleContext:
    """Sensitive data and external communication confirmed; the input
    leg inferred (an A2A endpoint: `untrusted_input="unknown"` on the
    edge), the shape `controlloop.adapters.a2a` produces from a card's
    `url`."""

    inferred = receives_from_edge(
        _RECEIVES_EDGE_ID, source=_AGENT_ID, target=_TRIGGER_ID
    ).model_copy(
        update={"security_attributes": SecurityAttributes(untrusted_input="unknown")}
    )
    return context(
        acbom=acbom(
            nodes=(_agent(), _sensitive_resource(), _trigger(), _comm_tool()),
            edges=(
                invokes_edge(_RESOURCE_EDGE_ID, source=_AGENT_ID, target=_RESOURCE_ID),
                inferred,
                invokes_edge(_TOOL_EDGE_ID, source=_AGENT_ID, target=_TOOL_ID),
            ),
        )
    )


class TestInferredInput:
    """An inferred input is reported, never confirmed, and never blocks
    on its own."""

    def test_inferred_input_with_the_other_two_legs_is_a_medium_qualified_finding(
        self,
    ) -> None:
        result = findings(_inferred_triangle_context())

        assert len(result) == 1
        finding = result[0]
        assert finding.severity is FindingSeverity.MEDIUM
        assert finding.confidence is Confidence.UNKNOWN
        assert "inferred, not declared" in finding.message
        assert "support-ticket-created" in finding.message
        assert "external_inputs" in finding.remediation

    def test_inferred_input_alone_with_one_other_leg_produces_nothing(self) -> None:
        inferred = receives_from_edge(
            _RECEIVES_EDGE_ID, source=_AGENT_ID, target=_TRIGGER_ID
        ).model_copy(
            update={
                "security_attributes": SecurityAttributes(untrusted_input="unknown")
            }
        )
        ctx = context(
            acbom=acbom(
                nodes=(_agent(), _trigger(), _comm_tool()),
                edges=(
                    inferred,
                    invokes_edge(_TOOL_EDGE_ID, source=_AGENT_ID, target=_TOOL_ID),
                ),
            )
        )

        assert findings(ctx) == ()

    def test_a_declared_input_outranks_an_inferred_one(self) -> None:
        """Both edges on the same agent: the confirmed one decides, so
        the finding is the full critical triangle, whatever the edge
        order."""
        inferred = receives_from_edge(
            hex_id("edge", "f"), source=_AGENT_ID, target=_TRIGGER_ID
        ).model_copy(
            update={
                "security_attributes": SecurityAttributes(untrusted_input="unknown")
            }
        )
        declared = receives_from_edge(
            _RECEIVES_EDGE_ID, source=_AGENT_ID, target=_TRIGGER_ID
        )
        base = (
            invokes_edge(_RESOURCE_EDGE_ID, source=_AGENT_ID, target=_RESOURCE_ID),
            invokes_edge(_TOOL_EDGE_ID, source=_AGENT_ID, target=_TOOL_ID),
        )
        nodes = (_agent(), _sensitive_resource(), _trigger(), _comm_tool())

        forward = findings(
            context(acbom=acbom(nodes=nodes, edges=(*base, inferred, declared)))
        )
        backward = findings(
            context(acbom=acbom(nodes=nodes, edges=(*base, declared, inferred)))
        )

        assert forward == backward
        assert len(forward) == 1
        assert forward[0].severity is FindingSeverity.CRITICAL
