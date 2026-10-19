"""Tests for controlloop.policy.rules.unresolved_dynamic_registration."""

from __future__ import annotations

import pytest
from _helpers import (
    acbom,
    agent_node,
    context,
    dynamic_registration_diagnostic,
    hex_id,
    invokes_edge,
    resource_node,
    tool_node,
)

from controlloop.acbom.completeness import completeness_summary
from controlloop.acbom.models import Confidence
from controlloop.findings.models import FindingSeverity
from controlloop.policy import engine as engine_module
from controlloop.policy.engine import evaluate as engine_evaluate
from controlloop.policy.models import RuleContext
from controlloop.policy.rules import unresolved_dynamic_registration as rule_module
from controlloop.policy.rules.unresolved_dynamic_registration import (
    RULE,
    RULE_ID,
    evaluate,
    findings,
)

_AGENT_ID = hex_id("agent", "a")
_TOOL_ID = hex_id("tool", "b")
_EDGE_ID = hex_id("edge", "c")


def _dynamic_registration_context() -> RuleContext:
    agent = agent_node(_AGENT_ID, name="dispatch-agent")
    tool = tool_node(
        _TOOL_ID,
        name="dynamic-tool",
        confidence=Confidence.UNKNOWN,
        path="server.py",
        line_start=42,
    )
    edge = invokes_edge(_EDGE_ID, source=_AGENT_ID, target=_TOOL_ID)
    diagnostic = dynamic_registration_diagnostic(path="server.py", line_start=42)
    return context(
        acbom=acbom(nodes=(agent, tool), edges=(edge,), diagnostics=(diagnostic,))
    )


class TestPositive:
    def test_dynamic_registration_diagnostic_produces_an_observation(self) -> None:
        result = evaluate(_dynamic_registration_context())

        assert len(result) == 1
        assert result[0].rule_id == RULE_ID
        assert "cannot enumerate" in result[0].message

    def test_correlated_unknown_tool_produces_a_finding(self) -> None:
        result = findings(_dynamic_registration_context())

        assert len(result) == 1
        finding = result[0]
        assert finding.rule_id == RULE_ID
        assert finding.affected_agent == _AGENT_ID
        assert finding.capability_path is not None
        assert finding.capability_path.target_id == _TOOL_ID
        assert finding.confidence is Confidence.UNKNOWN
        assert finding.severity is FindingSeverity.MEDIUM

    def test_finding_participates_in_completeness_state(self) -> None:
        """The finding participates in completeness state by construction,
        since it only ever fires from a diagnostic that is already part of
        `acbom.diagnostics` with `incomplete=True`."""
        ctx = _dynamic_registration_context()

        assert findings(ctx) != ()
        summary = completeness_summary(ctx.acbom)
        assert any(d.code == "INCOMPLETE-DYNAMIC-REGISTRATION" for d in summary)


class TestNegative:
    def test_statically_enumerable_tool_produces_nothing(self) -> None:
        """An ordinary, confidently discovered tool -- no
        dynamic-registration diagnostic anywhere -- never fires."""
        agent = agent_node(_AGENT_ID, name="dispatch-agent")
        tool = tool_node(_TOOL_ID, name="static-tool", confidence=Confidence.HIGH)
        edge = invokes_edge(_EDGE_ID, source=_AGENT_ID, target=_TOOL_ID)
        ctx = context(acbom=acbom(nodes=(agent, tool), edges=(edge,)))

        assert evaluate(ctx) == ()
        assert findings(ctx) == ()

    def test_static_tool_alongside_a_genuinely_dynamic_one_only_finds_the_dynamic_one(
        self,
    ) -> None:
        """A confidently discovered tool reached in the same graph as a
        genuinely dynamic one must not itself be reported -- proves the
        per-node correlation filter actually skips a non-`UNKNOWN`-
        confidence node, not just that nothing fires when every tool in
        the graph happens to be unknown."""
        static_tool_id = hex_id("tool", "9")
        static_edge_id = hex_id("edge", "9")

        agent = agent_node(_AGENT_ID, name="dispatch-agent")
        dynamic_tool = tool_node(
            _TOOL_ID,
            name="dynamic-tool",
            confidence=Confidence.UNKNOWN,
            path="server.py",
            line_start=42,
        )
        static_tool = tool_node(
            static_tool_id, name="static-tool", confidence=Confidence.HIGH
        )
        dynamic_edge = invokes_edge(_EDGE_ID, source=_AGENT_ID, target=_TOOL_ID)
        static_edge = invokes_edge(
            static_edge_id, source=_AGENT_ID, target=static_tool_id
        )
        diagnostic = dynamic_registration_diagnostic(path="server.py", line_start=42)
        ctx = context(
            acbom=acbom(
                nodes=(agent, dynamic_tool, static_tool),
                edges=(dynamic_edge, static_edge),
                diagnostics=(diagnostic,),
            )
        )

        result = findings(ctx)

        assert len(result) == 1
        assert result[0].capability_path is not None
        assert result[0].capability_path.target_id == _TOOL_ID

    def test_unrelated_incomplete_diagnostic_code_is_ignored(self) -> None:
        agent = agent_node(_AGENT_ID, name="dispatch-agent")
        tool = tool_node(
            _TOOL_ID, name="unresolved-tool", confidence=Confidence.UNKNOWN
        )
        edge = invokes_edge(_EDGE_ID, source=_AGENT_ID, target=_TOOL_ID)
        other_diagnostic = dynamic_registration_diagnostic(
            path="server.py", line_start=42
        )
        other_diagnostic = other_diagnostic.model_copy(
            update={"code": "INCOMPLETE-UNRESOLVED-REFERENCE"}
        )
        ctx = context(
            acbom=acbom(
                nodes=(agent, tool), edges=(edge,), diagnostics=(other_diagnostic,)
            )
        )

        assert evaluate(ctx) == ()
        assert findings(ctx) == ()

    def test_unknown_confidence_tool_without_a_correlated_diagnostic_produces_nothing(
        self,
    ) -> None:
        """A node's mere low/unknown confidence is not, on its own,
        evidence of dynamic registration -- only a correlated
        `INCOMPLETE-DYNAMIC-REGISTRATION` diagnostic at the same
        location is."""
        agent = agent_node(_AGENT_ID, name="dispatch-agent")
        tool = tool_node(_TOOL_ID, name="unknown-tool", confidence=Confidence.UNKNOWN)
        edge = invokes_edge(_EDGE_ID, source=_AGENT_ID, target=_TOOL_ID)
        ctx = context(acbom=acbom(nodes=(agent, tool), edges=(edge,)))

        assert evaluate(ctx) == ()
        assert findings(ctx) == ()


class TestBoundary:
    def test_diagnostic_with_no_correlated_node_still_produces_an_observation(
        self,
    ) -> None:
        """No adapter exists yet that emits a placeholder node
        alongside its own dynamic-registration diagnostic
        (`tests/acbom/test_completeness.py`'s own
        `test_dynamically_registered_tool_fixture_produces_an_unknown`
        makes the same point for the diagnostic mechanism itself). The
        `RuleObservation` layer covers this unconditionally; the
        `Finding` layer cannot, for lack of anything to attribute it
        to."""
        diagnostic = dynamic_registration_diagnostic(path="server.py", line_start=42)
        ctx = context(acbom=acbom(diagnostics=(diagnostic,)))

        assert len(evaluate(ctx)) == 1
        assert findings(ctx) == ()

    def test_correlated_node_of_the_wrong_type_is_not_a_finding_target(self) -> None:
        """`findings()` only attaches a `CapabilityPath` to a `TOOL`
        target -- the one node type this rule is scoped to, even
        though `compute_direct_capability_paths` would happily return
        a path to a `RESOURCE` target reached by an (unusual, but not
        structurally forbidden) `invokes` edge."""
        agent = agent_node(_AGENT_ID, name="dispatch-agent")
        resource = resource_node(
            _TOOL_ID,
            name="not-a-tool",
            confidence=Confidence.UNKNOWN,
            path="server.py",
            line_start=42,
        )
        edge = invokes_edge(_EDGE_ID, source=_AGENT_ID, target=_TOOL_ID)
        diagnostic = dynamic_registration_diagnostic(path="server.py", line_start=42)
        ctx = context(
            acbom=acbom(
                nodes=(agent, resource), edges=(edge,), diagnostics=(diagnostic,)
            )
        )

        assert findings(ctx) == ()

    def test_empty_acbom_produces_nothing(self) -> None:
        ctx = context()
        assert evaluate(ctx) == ()
        assert findings(ctx) == ()


class TestDeterminism:
    def test_identical_context_twice_produces_identical_result(self) -> None:
        ctx = _dynamic_registration_context()
        assert evaluate(ctx) == evaluate(ctx)
        assert findings(ctx) == findings(ctx)

    def test_shuffled_diagnostics_order_produces_identical_result(self) -> None:
        agent = agent_node(_AGENT_ID, name="dispatch-agent")
        tool = tool_node(_TOOL_ID, name="dynamic-tool", confidence=Confidence.UNKNOWN)
        edge = invokes_edge(_EDGE_ID, source=_AGENT_ID, target=_TOOL_ID)
        diagnostic_a = dynamic_registration_diagnostic(
            path="server.py", line_start=42, message="first"
        )
        diagnostic_b = dynamic_registration_diagnostic(
            path="other.py", line_start=1, message="second"
        )

        forward = context(
            acbom=acbom(
                nodes=(agent, tool),
                edges=(edge,),
                diagnostics=(diagnostic_a, diagnostic_b),
            )
        )
        reverse = context(
            acbom=acbom(
                nodes=(agent, tool),
                edges=(edge,),
                diagnostics=(diagnostic_b, diagnostic_a),
            )
        )

        assert evaluate(forward) == evaluate(reverse)


class TestEngineIntegration:
    def test_registers_and_runs_through_the_real_engine(self) -> None:
        result = engine_evaluate((RULE,), _dynamic_registration_context())
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
