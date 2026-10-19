"""Tests for controlloop.policy.rules.missing_action_logging."""

from __future__ import annotations

import random

import pytest
from _helpers import (
    acbom,
    agent_node,
    context,
    hex_id,
    invokes_edge,
    tool_node,
)

from controlloop.acbom.models import SecurityAttributes
from controlloop.diff.models import (
    CURRENT_DIFF_SCHEMA_VERSION,
    ChangeKind,
    DiffResult,
    NodeChange,
)
from controlloop.findings.models import FindingChangeState, FindingSeverity
from controlloop.manifest.models import ToolLoggingDeclaration
from controlloop.policy import engine as engine_module
from controlloop.policy.engine import evaluate as engine_evaluate
from controlloop.policy.models import EvaluationBounds, RuleContext
from controlloop.policy.rules import missing_action_logging as rule_module
from controlloop.policy.rules.missing_action_logging import (
    RULE,
    RULE_ID,
    evaluate,
    findings,
)

_AGENT_ID = hex_id("agent", "a")
_AGENT_B_ID = hex_id("agent", "b")
_TOOL_ID = hex_id("tool", "b")
_EDGE_ID = hex_id("edge", "c")
_EDGE_B_ID = hex_id("edge", "d")

_DESTRUCTIVE = SecurityAttributes(destructive=True)
_UNCLASSIFIED = SecurityAttributes(destructive="unknown")
_HARMLESS = SecurityAttributes()


def _privileged_tool_context(
    *, manifest_kwargs: dict[str, object] | None = None
) -> RuleContext:
    agent = agent_node(_AGENT_ID, name="refund-agent")
    tool = tool_node(_TOOL_ID, name="refund-tool", security_attributes=_DESTRUCTIVE)
    edge = invokes_edge(_EDGE_ID, source=_AGENT_ID, target=_TOOL_ID)
    manifest = None
    if manifest_kwargs is not None:
        from _helpers import manifest as _manifest_builder

        manifest = _manifest_builder(**manifest_kwargs)
    return context(acbom=acbom(nodes=(agent, tool), edges=(edge,)), manifest=manifest)


class TestPositive:
    def test_privileged_undeclared_tool_produces_an_observation(self) -> None:
        result = evaluate(_privileged_tool_context())

        assert len(result) == 1
        assert result[0].rule_id == RULE_ID
        assert "refund-tool" in result[0].message
        assert "destructive-action" in result[0].message
        assert "logged_tools" in result[0].message

    def test_privileged_undeclared_tool_produces_a_finding(self) -> None:
        result = findings(_privileged_tool_context())

        assert len(result) == 1
        finding = result[0]
        assert finding.rule_id == RULE_ID
        assert finding.affected_agent == _AGENT_ID
        assert finding.capability_path is not None
        assert finding.capability_path.agent_id == _AGENT_ID
        assert finding.capability_path.target_id == _TOOL_ID
        assert finding.severity is FindingSeverity.HIGH
        assert finding.change_state is FindingChangeState.NOT_COMPARED
        assert "logged_tools" in finding.remediation

    def test_two_invoking_agents_produce_two_independently_scoped_findings(
        self,
    ) -> None:
        agent_a = agent_node(_AGENT_ID, name="refund-agent")
        agent_b = agent_node(_AGENT_B_ID, name="support-agent")
        tool = tool_node(_TOOL_ID, name="refund-tool", security_attributes=_DESTRUCTIVE)
        edge_a = invokes_edge(_EDGE_ID, source=_AGENT_ID, target=_TOOL_ID)
        edge_b = invokes_edge(_EDGE_B_ID, source=_AGENT_B_ID, target=_TOOL_ID)
        ctx = context(
            acbom=acbom(nodes=(agent_a, agent_b, tool), edges=(edge_a, edge_b))
        )

        result = findings(ctx)

        assert len(result) == 2
        assert {finding.affected_agent for finding in result} == {
            _AGENT_ID,
            _AGENT_B_ID,
        }

    def test_privileged_and_harmless_tool_only_reports_the_privileged_one(
        self,
    ) -> None:
        """A direct capability path to a non-privileged tool the same
        agent also invokes is skipped, not just absent -- proves the
        per-path filter in `findings()`, not merely the early-return
        when nothing at all is privileged."""
        harmless_tool_id = hex_id("tool", "9")
        harmless_edge_id = hex_id("edge", "9")
        agent = agent_node(_AGENT_ID, name="refund-agent")
        privileged_tool = tool_node(
            _TOOL_ID, name="refund-tool", security_attributes=_DESTRUCTIVE
        )
        harmless_tool = tool_node(
            harmless_tool_id, name="lookup-tool", security_attributes=_HARMLESS
        )
        privileged_edge = invokes_edge(_EDGE_ID, source=_AGENT_ID, target=_TOOL_ID)
        harmless_edge = invokes_edge(
            harmless_edge_id, source=_AGENT_ID, target=harmless_tool_id
        )
        ctx = context(
            acbom=acbom(
                nodes=(agent, privileged_tool, harmless_tool),
                edges=(privileged_edge, harmless_edge),
            )
        )

        result = findings(ctx)

        assert len(result) == 1
        assert result[0].capability_path is not None
        assert result[0].capability_path.target_id == _TOOL_ID

    def test_unclassified_tool_is_still_reported_as_privileged(self) -> None:
        """`classify_material_capability` returning only
        `UNCLASSIFIED` (an explicit "unknown" security-attribute
        assertion) must still count as privileged -- this codebase's
        "unknown, never omitted" invariant means an unclassifiable tool
        is never treated as safer than a classified one."""
        agent = agent_node(_AGENT_ID, name="refund-agent")
        tool = tool_node(
            _TOOL_ID, name="refund-tool", security_attributes=_UNCLASSIFIED
        )
        edge = invokes_edge(_EDGE_ID, source=_AGENT_ID, target=_TOOL_ID)
        ctx = context(acbom=acbom(nodes=(agent, tool), edges=(edge,)))

        result = evaluate(ctx)

        assert len(result) == 1
        assert "unclassified" in result[0].message


class TestNegative:
    def test_declared_tool_produces_nothing(self) -> None:
        ctx = _privileged_tool_context(
            manifest_kwargs={
                "logged_tools": (
                    ToolLoggingDeclaration(
                        tool="refund-tool", audit_path="audit/refund-tool.log"
                    ),
                )
            }
        )

        assert evaluate(ctx) == ()
        assert findings(ctx) == ()

    def test_non_privileged_tool_produces_nothing(self) -> None:
        agent = agent_node(_AGENT_ID, name="refund-agent")
        tool = tool_node(_TOOL_ID, name="lookup-tool", security_attributes=_HARMLESS)
        edge = invokes_edge(_EDGE_ID, source=_AGENT_ID, target=_TOOL_ID)
        ctx = context(acbom=acbom(nodes=(agent, tool), edges=(edge,)))

        assert evaluate(ctx) == ()
        assert findings(ctx) == ()

    def test_tool_declared_for_a_different_tool_name_still_fires(self) -> None:
        ctx = _privileged_tool_context(
            manifest_kwargs={
                "logged_tools": (
                    ToolLoggingDeclaration(
                        tool="unrelated-tool", audit_path="audit/unrelated.log"
                    ),
                )
            }
        )

        assert len(evaluate(ctx)) == 1


class TestBoundary:
    def test_tool_with_no_invokes_edge_is_ignored(self) -> None:
        """A privileged tool node that no agent actually invokes is not
        held by anyone and is not reported."""
        tool = tool_node(_TOOL_ID, name="orphan-tool", security_attributes=_DESTRUCTIVE)
        ctx = context(acbom=acbom(nodes=(tool,)))

        assert evaluate(ctx) == ()
        assert findings(ctx) == ()

    def test_empty_acbom_produces_nothing(self) -> None:
        ctx = context()
        assert evaluate(ctx) == ()
        assert findings(ctx) == ()

    def test_change_state_derived_from_diff(self) -> None:
        base_ctx = _privileged_tool_context()
        diff = DiffResult(
            schema_version=CURRENT_DIFF_SCHEMA_VERSION,
            node_changes=(
                NodeChange(kind=ChangeKind.ADDED, node_id=_TOOL_ID, after=None),
            ),
            edge_changes=(),
            effective_authority_changes=(),
        )
        ctx = context(acbom=base_ctx.acbom, diff=diff, manifest=base_ctx.manifest)

        result = findings(ctx)
        assert result[0].change_state is FindingChangeState.ADDED


class TestDeterminism:
    def test_identical_context_twice_produces_identical_result(self) -> None:
        ctx = _privileged_tool_context()
        assert evaluate(ctx) == evaluate(ctx)
        assert findings(ctx) == findings(ctx)

    def test_shuffled_node_order_produces_identical_result(self) -> None:
        agent = agent_node(_AGENT_ID, name="refund-agent")
        tool = tool_node(_TOOL_ID, name="refund-tool", security_attributes=_DESTRUCTIVE)
        edge = invokes_edge(_EDGE_ID, source=_AGENT_ID, target=_TOOL_ID)

        forward = context(acbom=acbom(nodes=(agent, tool), edges=(edge,)))
        nodes_shuffled = (tool, agent)
        reverse = context(acbom=acbom(nodes=nodes_shuffled, edges=(edge,)))

        assert evaluate(forward) == evaluate(reverse)
        assert findings(forward) == findings(reverse)


class TestEngineIntegration:
    def test_registers_and_runs_through_the_real_engine(self) -> None:
        result = engine_evaluate(
            (RULE,),
            _privileged_tool_context(),
            bounds=EvaluationBounds(),
        )
        assert len(result.observations) == 1
        assert result.observations[0].rule_id == RULE_ID
        assert not result.is_incomplete


class TestStructuralSafety:
    """The engine's structural safety check, applied to this rule module:
    a rule reads only `RuleContext`, never a file, subprocess, or
    socket."""

    def test_module_has_no_forbidden_imports(self) -> None:
        assert engine_module.module_forbidden_imports(rule_module) == frozenset()


class TestOffline:
    def test_offline_harness_is_active_for_this_module(self) -> None:
        import socket

        with pytest.raises(RuntimeError, match="offline harness"):
            socket.socket()


class TestPrivacy:
    def test_no_raw_content_path_exists(self) -> None:
        """The same structural proof `TestStructuralSafety` already
        performs also proves privacy for this module: a rule that
        cannot import `os`/`subprocess`/`socket`/`urllib`/`http` and
        contains no bare `open(...)` call has no way to read raw
        repository content in the first place, matching
        `tests/findings/test_finding_offline.py`'s identical
        reasoning."""
        assert engine_module.module_forbidden_imports(rule_module) == frozenset()

    def test_random_seed_does_not_affect_output_order(self) -> None:
        random.seed(1234)
        ctx = _privileged_tool_context()
        assert evaluate(ctx) == evaluate(ctx)
