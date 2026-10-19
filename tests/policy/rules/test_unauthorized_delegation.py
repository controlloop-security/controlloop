"""Tests for controlloop.policy.rules.unauthorized_delegation."""

from __future__ import annotations

import pytest
from _helpers import (
    acbom,
    agent_node,
    context,
    delegates_to_edge,
    hex_id,
    invokes_edge,
    manifest,
    tool_node,
)

from controlloop.acbom.models import SecurityAttributes
from controlloop.findings.models import FindingChangeState, FindingSeverity
from controlloop.manifest.models import AllowedDelegation, TrustBoundary
from controlloop.policy import engine as engine_module
from controlloop.policy.engine import evaluate as engine_evaluate
from controlloop.policy.models import RuleContext
from controlloop.policy.rules import unauthorized_delegation as rule_module
from controlloop.policy.rules.unauthorized_delegation import (
    RULE,
    RULE_ID,
    evaluate,
    findings,
)

_ORIGIN_ID = hex_id("agent", "a")
_DISALLOWED_TARGET_ID = hex_id("agent", "b")
_ALLOWED_TARGET_ID = hex_id("agent", "c")
_TOOL_ID = hex_id("tool", "d")
_DELEGATE_EDGE_ID = hex_id("edge", "e")
_INVOKE_EDGE_ID = hex_id("edge", "f")

_DESTRUCTIVE = SecurityAttributes(destructive=True)


def _chain_context(*, manifest_doc: object = None) -> RuleContext:
    """origin --delegates-to--> disallowed-target --invokes--> tool."""
    origin = agent_node(_ORIGIN_ID, name="coordinator")
    target = agent_node(_DISALLOWED_TARGET_ID, name="researcher")
    tool = tool_node(_TOOL_ID, name="delete-repo", security_attributes=_DESTRUCTIVE)
    delegation = delegates_to_edge(
        _DELEGATE_EDGE_ID, source=_ORIGIN_ID, target=_DISALLOWED_TARGET_ID
    )
    invocation = invokes_edge(
        _INVOKE_EDGE_ID, source=_DISALLOWED_TARGET_ID, target=_TOOL_ID
    )
    return context(
        acbom=acbom(nodes=(origin, target, tool), edges=(delegation, invocation)),
        manifest=manifest_doc,
    )


class TestPositive:
    def test_disallowed_delegation_produces_an_observation(self) -> None:
        result = evaluate(_chain_context())

        assert len(result) == 1
        assert "coordinator" in result[0].message
        assert "researcher" in result[0].message

    def test_disallowed_delegation_reaching_material_capability_produces_a_finding(
        self,
    ) -> None:
        result = findings(_chain_context())

        assert len(result) == 1
        finding = result[0]
        assert finding.rule_id == RULE_ID
        assert finding.affected_agent == _ORIGIN_ID
        assert finding.capability_path is not None
        assert finding.capability_path.agent_id == _ORIGIN_ID
        assert finding.capability_path.target_id == _TOOL_ID
        assert len(finding.capability_path.hops) == 2
        assert finding.change_state is FindingChangeState.NOT_COMPARED

    def test_delegation_outside_a_declared_trust_boundary_is_elevated(self) -> None:
        manifest_doc = manifest(
            trust_boundaries=(TrustBoundary(name="prod", agents=("coordinator",)),)
        )

        result = findings(_chain_context(manifest_doc=manifest_doc))

        assert result[0].severity is FindingSeverity.HIGH
        assert "crosses a declared trust boundary" in result[0].message

    def test_delegation_within_a_shared_trust_boundary_is_not_elevated(
        self,
    ) -> None:
        manifest_doc = manifest(
            trust_boundaries=(
                TrustBoundary(name="prod", agents=("coordinator", "researcher")),
            )
        )

        result = findings(_chain_context(manifest_doc=manifest_doc))

        assert len(result) == 1
        assert result[0].severity is FindingSeverity.MEDIUM

    def test_no_declared_allowed_set_still_reports_without_failing(self) -> None:
        """No manifest at all still reports discovered delegation; the rule
        never raises."""
        result = evaluate(_chain_context(manifest_doc=None))
        assert len(result) == 1


class TestNegative:
    def test_allowed_delegation_target_produces_nothing(self) -> None:
        manifest_doc = manifest(
            allowed_delegation=(
                AllowedDelegation(agent="coordinator", targets=("researcher",)),
            )
        )

        ctx = _chain_context(manifest_doc=manifest_doc)

        assert evaluate(ctx) == ()
        assert findings(ctx) == ()

    def test_allowed_delegation_for_a_different_agent_does_not_suppress(self) -> None:
        manifest_doc = manifest(
            allowed_delegation=(
                AllowedDelegation(agent="someone-else", targets=("researcher",)),
            )
        )

        result = evaluate(_chain_context(manifest_doc=manifest_doc))
        assert len(result) == 1

    def test_an_allowed_chain_alongside_a_disallowed_one_only_finds_the_disallowed_one(
        self,
    ) -> None:
        """A second, wholly allowed delegation chain reached by the
        same bounded transitive walk must not produce a finding --
        proves the per-path `_offending_hop` filter actually skips a
        path with no disallowed hop, not just that nothing at all is
        flagged when every chain happens to be disallowed."""
        allowed_target_id = hex_id("agent", "9")
        allowed_tool_id = hex_id("tool", "9")
        allowed_delegate_edge_id = hex_id("edge", "8")
        allowed_invoke_edge_id = hex_id("edge", "7")

        origin = agent_node(_ORIGIN_ID, name="coordinator")
        disallowed_target = agent_node(_DISALLOWED_TARGET_ID, name="researcher")
        allowed_target = agent_node(allowed_target_id, name="writer")
        disallowed_tool = tool_node(
            _TOOL_ID, name="delete-repo", security_attributes=_DESTRUCTIVE
        )
        allowed_tool = tool_node(
            allowed_tool_id, name="publish-doc", security_attributes=_DESTRUCTIVE
        )

        disallowed_delegation = delegates_to_edge(
            _DELEGATE_EDGE_ID, source=_ORIGIN_ID, target=_DISALLOWED_TARGET_ID
        )
        disallowed_invocation = invokes_edge(
            _INVOKE_EDGE_ID, source=_DISALLOWED_TARGET_ID, target=_TOOL_ID
        )
        allowed_delegation = delegates_to_edge(
            allowed_delegate_edge_id, source=_ORIGIN_ID, target=allowed_target_id
        )
        allowed_invocation = invokes_edge(
            allowed_invoke_edge_id, source=allowed_target_id, target=allowed_tool_id
        )

        manifest_doc = manifest(
            allowed_delegation=(
                AllowedDelegation(agent="coordinator", targets=("writer",)),
            )
        )
        ctx = context(
            acbom=acbom(
                nodes=(
                    origin,
                    disallowed_target,
                    allowed_target,
                    disallowed_tool,
                    allowed_tool,
                ),
                edges=(
                    disallowed_delegation,
                    disallowed_invocation,
                    allowed_delegation,
                    allowed_invocation,
                ),
            ),
            manifest=manifest_doc,
        )

        result = findings(ctx)

        assert len(result) == 1
        assert result[0].capability_path is not None
        assert result[0].capability_path.target_id == _TOOL_ID


class TestBoundary:
    def test_dead_end_disallowed_delegation_has_no_finding_but_has_an_observation(
        self,
    ) -> None:
        """Disclosed scope boundary: a disallowed `delegates-to` edge
        to an agent with zero further discovered capability cannot be
        attached to a valid `CapabilityPath` (`target_type` excludes
        `agent`), so it never appears in `findings()` -- but it is
        unconditionally covered by `evaluate()`'s `RuleObservation`s."""
        origin = agent_node(_ORIGIN_ID, name="coordinator")
        target = agent_node(_DISALLOWED_TARGET_ID, name="researcher")
        delegation = delegates_to_edge(
            _DELEGATE_EDGE_ID, source=_ORIGIN_ID, target=_DISALLOWED_TARGET_ID
        )
        ctx = context(acbom=acbom(nodes=(origin, target), edges=(delegation,)))

        assert len(evaluate(ctx)) == 1
        assert findings(ctx) == ()

    def test_empty_acbom_produces_nothing(self) -> None:
        ctx = context()
        assert evaluate(ctx) == ()
        assert findings(ctx) == ()

    def test_delegation_from_a_non_agent_source_is_ignored(self) -> None:
        """Malformed-graph defense: a `delegates-to` edge cannot
        realistically originate from a non-agent node, but this rule
        does not assume graph well-formedness -- it explicitly checks
        the source is an `AGENT` node before considering the edge."""
        tool = tool_node(_ORIGIN_ID, name="not-an-agent")
        target = agent_node(_DISALLOWED_TARGET_ID, name="researcher")
        delegation = delegates_to_edge(
            _DELEGATE_EDGE_ID, source=_ORIGIN_ID, target=_DISALLOWED_TARGET_ID
        )
        ctx = context(acbom=acbom(nodes=(tool, target), edges=(delegation,)))

        assert evaluate(ctx) == ()


class TestDeterminism:
    def test_identical_context_twice_produces_identical_result(self) -> None:
        ctx = _chain_context()
        assert evaluate(ctx) == evaluate(ctx)
        assert findings(ctx) == findings(ctx)

    def test_shuffled_edge_order_produces_identical_result(self) -> None:
        origin = agent_node(_ORIGIN_ID, name="coordinator")
        target = agent_node(_DISALLOWED_TARGET_ID, name="researcher")
        tool = tool_node(_TOOL_ID, name="delete-repo", security_attributes=_DESTRUCTIVE)
        delegation = delegates_to_edge(
            _DELEGATE_EDGE_ID, source=_ORIGIN_ID, target=_DISALLOWED_TARGET_ID
        )
        invocation = invokes_edge(
            _INVOKE_EDGE_ID, source=_DISALLOWED_TARGET_ID, target=_TOOL_ID
        )

        forward = context(
            acbom=acbom(nodes=(origin, target, tool), edges=(delegation, invocation))
        )
        reverse = context(
            acbom=acbom(nodes=(tool, target, origin), edges=(invocation, delegation))
        )

        assert evaluate(forward) == evaluate(reverse)
        assert findings(forward) == findings(reverse)


class TestEngineIntegration:
    def test_registers_and_runs_through_the_real_engine(self) -> None:
        result = engine_evaluate((RULE,), _chain_context())
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
