"""Tests for controlloop.policy.rules.capability_ceiling."""

from __future__ import annotations

import pytest
from _helpers import (
    acbom,
    agent_node,
    context,
    data_class_node,
    delegates_to_edge,
    dynamic_registration_diagnostic,
    hex_id,
    invokes_edge,
    manifest,
    reads_edge,
    resource_node,
    tool_node,
    writes_edge,
)

from controlloop.acbom.models import (
    Confidence,
    EdgeType,
    SecurityAttributes,
    Sensitivity,
)
from controlloop.config import ConfigSource
from controlloop.findings.models import FindingChangeState, FindingSeverity
from controlloop.manifest.models import CapabilityCeiling
from controlloop.policy import engine as engine_module
from controlloop.policy.engine import evaluate as engine_evaluate
from controlloop.policy.models import RuleContext
from controlloop.policy.rules import ALL_RULES
from controlloop.policy.rules import capability_ceiling as rule_module
from controlloop.policy.rules.capability_ceiling import (
    RULE,
    RULE_ID,
    evaluate,
    findings,
)
from controlloop.policy.thresholds import (
    CompletenessEnforcement,
    LowConfidenceAction,
    PolicyConfig,
    RuleMetadata,
    evaluate_gate,
    validate_disabled_rules,
)

_AGENT_ID = hex_id("agent", "a")
_OTHER_AGENT_ID = hex_id("agent", "b")
_TOOL_ID = hex_id("tool", "c")
_RESOURCE_ID = hex_id("resource", "d")
_EDGE_ID = hex_id("edge", "e")
_OTHER_EDGE_ID = hex_id("edge", "f")


def _policy_config(
    *,
    severity_threshold: FindingSeverity = FindingSeverity.INFO,
    disabled_rule_ids: frozenset[str] = frozenset(),
) -> PolicyConfig:
    return PolicyConfig(
        severity_threshold=severity_threshold,
        severity_threshold_source=ConfigSource.DEFAULT,
        low_confidence_action=LowConfidenceAction.BLOCK,
        low_confidence_action_source=ConfigSource.DEFAULT,
        disabled_rule_ids=disabled_rule_ids,
        disabled_rule_ids_source=ConfigSource.DEFAULT,
        completeness_enforcement=CompletenessEnforcement.WARN,
        completeness_enforcement_source=ConfigSource.DEFAULT,
    )


def _direct_action_context(
    *, prohibited_actions: tuple[EdgeType, ...] = (EdgeType.WRITES,)
) -> RuleContext:
    """origin --writes--> resource, with a ceiling prohibiting writes."""
    origin = agent_node(_AGENT_ID, name="coordinator")
    resource = resource_node(_RESOURCE_ID, name="prod-db")
    edge = writes_edge(_EDGE_ID, source=_AGENT_ID, target=_RESOURCE_ID)
    manifest_doc = manifest(
        ceilings=(
            CapabilityCeiling(
                agent="coordinator", prohibited_actions=prohibited_actions
            ),
        )
    )
    return context(
        acbom=acbom(nodes=(origin, resource), edges=(edge,)), manifest=manifest_doc
    )


class TestPositive:
    def test_direct_prohibited_action_produces_a_finding(self) -> None:
        ctx = _direct_action_context()

        observations = evaluate(ctx)
        results = findings(ctx)

        assert len(observations) == 1
        assert "coordinator" in observations[0].message
        assert len(results) == 1
        finding = results[0]
        assert finding.rule_id == RULE_ID
        assert finding.affected_agent == _AGENT_ID
        assert finding.capability_path is not None
        assert finding.capability_path.target_id == _RESOURCE_ID
        assert finding.severity is FindingSeverity.CRITICAL
        assert finding.change_state is FindingChangeState.NOT_COMPARED

    def test_prohibited_resource_by_name_produces_a_finding(self) -> None:
        origin = agent_node(_AGENT_ID, name="coordinator")
        resource = resource_node(_RESOURCE_ID, name="prod-db")
        edge = reads_edge(_EDGE_ID, source=_AGENT_ID, target=_RESOURCE_ID)
        manifest_doc = manifest(
            ceilings=(
                CapabilityCeiling(
                    agent="coordinator", prohibited_resources=("prod-db",)
                ),
            )
        )
        ctx = context(
            acbom=acbom(nodes=(origin, resource), edges=(edge,)),
            manifest=manifest_doc,
        )

        assert len(findings(ctx)) == 1

    def test_prohibited_external_destination_by_name_produces_a_finding(self) -> None:
        origin = agent_node(_AGENT_ID, name="coordinator")
        resource = resource_node(_RESOURCE_ID, name="evil.example.com")
        edge = invokes_edge(_EDGE_ID, source=_AGENT_ID, target=_RESOURCE_ID)
        manifest_doc = manifest(
            ceilings=(
                CapabilityCeiling(
                    agent="coordinator",
                    prohibited_external_destinations=("evil.example.com",),
                ),
            )
        )
        ctx = context(
            acbom=acbom(nodes=(origin, resource), edges=(edge,)),
            manifest=manifest_doc,
        )

        assert len(findings(ctx)) == 1

    def test_prohibited_data_class_produces_a_finding(self) -> None:
        data_class_id = hex_id("data-class", "9")
        origin = agent_node(_AGENT_ID, name="coordinator")
        data_class = data_class_node(
            data_class_id,
            name="pii",
            security_attributes=SecurityAttributes(sensitivity=Sensitivity.RESTRICTED),
        )
        edge = reads_edge(_EDGE_ID, source=_AGENT_ID, target=data_class_id)
        manifest_doc = manifest(
            ceilings=(
                CapabilityCeiling(
                    agent="coordinator",
                    prohibited_data_classes=(Sensitivity.RESTRICTED,),
                ),
            )
        )
        ctx = context(
            acbom=acbom(nodes=(origin, data_class), edges=(edge,)),
            manifest=manifest_doc,
        )

        result = findings(ctx)
        assert len(result) == 1
        assert "restricted" in result[0].message

    def test_transitive_breach_reports_the_full_path(self) -> None:
        """A breach reachable only transitively is caught, with its full
        path reported. `compute_transitive_capability_paths` only ever
        chains through `invokes`, `delegates-to`, `authenticates-as`, or
        `permitted-by` edges -- never a `reads`/`writes` action edge,
        which is always a leaf (see that function's own
        `_TRANSITIVE_EDGE_TYPES` constant) -- so the second hop here is
        `invokes`, matching `unauthorized_delegation.py`'s own identical
        transitive-chain test fixture shape."""
        origin = agent_node(_AGENT_ID, name="coordinator")
        intermediary = agent_node(_OTHER_AGENT_ID, name="worker")
        tool = tool_node(_TOOL_ID, name="delete-repo")
        delegation = delegates_to_edge(
            _EDGE_ID, source=_AGENT_ID, target=_OTHER_AGENT_ID
        )
        invocation = invokes_edge(
            _OTHER_EDGE_ID, source=_OTHER_AGENT_ID, target=_TOOL_ID
        )
        manifest_doc = manifest(
            ceilings=(
                CapabilityCeiling(
                    agent="coordinator", prohibited_actions=(EdgeType.INVOKES,)
                ),
            )
        )
        ctx = context(
            acbom=acbom(
                nodes=(origin, intermediary, tool), edges=(delegation, invocation)
            ),
            manifest=manifest_doc,
        )

        result = findings(ctx)

        assert len(result) == 1
        path = result[0].capability_path
        assert path is not None
        assert path.agent_id == _AGENT_ID
        assert path.target_id == _TOOL_ID
        assert len(path.hops) == 2

    def test_prohibited_delegation_target_reaching_capability_produces_a_finding(
        self,
    ) -> None:
        origin = agent_node(_AGENT_ID, name="coordinator")
        target = agent_node(_OTHER_AGENT_ID, name="untrusted")
        tool = tool_node(_TOOL_ID, name="delete-repo")
        delegation = delegates_to_edge(
            _EDGE_ID, source=_AGENT_ID, target=_OTHER_AGENT_ID
        )
        invocation = invokes_edge(
            _OTHER_EDGE_ID, source=_OTHER_AGENT_ID, target=_TOOL_ID
        )
        manifest_doc = manifest(
            ceilings=(
                CapabilityCeiling(
                    agent="coordinator", prohibited_delegation_targets=("untrusted",)
                ),
            )
        )
        ctx = context(
            acbom=acbom(nodes=(origin, target, tool), edges=(delegation, invocation)),
            manifest=manifest_doc,
        )

        result = findings(ctx)
        assert len(result) == 1
        assert result[0].capability_path is not None
        assert len(result[0].capability_path.hops) == 2

    def test_repository_wide_ceiling_applies_to_every_agent(self) -> None:
        origin = agent_node(_AGENT_ID, name="coordinator")
        resource = resource_node(_RESOURCE_ID, name="prod-db")
        edge = writes_edge(_EDGE_ID, source=_AGENT_ID, target=_RESOURCE_ID)
        manifest_doc = manifest(
            ceilings=(CapabilityCeiling(prohibited_actions=(EdgeType.WRITES,)),)
        )
        ctx = context(
            acbom=acbom(nodes=(origin, resource), edges=(edge,)),
            manifest=manifest_doc,
        )

        assert len(findings(ctx)) == 1


class TestNegative:
    def test_action_not_prohibited_produces_nothing(self) -> None:
        ctx = _direct_action_context(prohibited_actions=(EdgeType.INVOKES,))

        assert evaluate(ctx) == ()
        assert findings(ctx) == ()

    def test_ceiling_declared_for_a_different_agent_does_not_apply(self) -> None:
        origin = agent_node(_AGENT_ID, name="coordinator")
        resource = resource_node(_RESOURCE_ID, name="prod-db")
        edge = writes_edge(_EDGE_ID, source=_AGENT_ID, target=_RESOURCE_ID)
        manifest_doc = manifest(
            ceilings=(
                CapabilityCeiling(
                    agent="someone-else", prohibited_actions=(EdgeType.WRITES,)
                ),
            )
        )
        ctx = context(
            acbom=acbom(nodes=(origin, resource), edges=(edge,)),
            manifest=manifest_doc,
        )

        assert evaluate(ctx) == ()
        assert findings(ctx) == ()

    def test_delegation_from_an_agent_with_no_ceiling_is_ignored(self) -> None:
        """A `delegates-to` edge sourced by an agent that has no
        declared ceiling of its own is never treated as a bare-
        delegation breach, even while a different agent in the same
        graph does have one."""
        coordinator = agent_node(_AGENT_ID, name="coordinator")
        bystander = agent_node(_OTHER_AGENT_ID, name="bystander")
        untrusted = agent_node(hex_id("agent", "9"), name="untrusted")
        delegation = delegates_to_edge(
            _EDGE_ID, source=_OTHER_AGENT_ID, target=hex_id("agent", "9")
        )
        manifest_doc = manifest(
            ceilings=(
                CapabilityCeiling(
                    agent="coordinator", prohibited_delegation_targets=("untrusted",)
                ),
            )
        )
        ctx = context(
            acbom=acbom(nodes=(coordinator, bystander, untrusted), edges=(delegation,)),
            manifest=manifest_doc,
        )

        assert evaluate(ctx) == ()
        assert findings(ctx) == ()

    def test_delegation_to_an_allowed_target_is_not_a_breach(self) -> None:
        origin = agent_node(_AGENT_ID, name="coordinator")
        target = agent_node(_OTHER_AGENT_ID, name="trusted")
        delegation = delegates_to_edge(
            _EDGE_ID, source=_AGENT_ID, target=_OTHER_AGENT_ID
        )
        manifest_doc = manifest(
            ceilings=(
                CapabilityCeiling(
                    agent="coordinator", prohibited_delegation_targets=("untrusted",)
                ),
            )
        )
        ctx = context(
            acbom=acbom(nodes=(origin, target), edges=(delegation,)),
            manifest=manifest_doc,
        )

        assert evaluate(ctx) == ()
        assert findings(ctx) == ()


class TestNoDeclaredCeiling:
    def test_no_manifest_reports_absence_without_failing(self) -> None:
        """No ceiling declared is not failed for its absence, but is
        stated."""
        base = _direct_action_context()
        ctx = context(acbom=base.acbom, manifest=None)

        observations = evaluate(ctx)

        assert len(observations) == 1
        assert "no capability ceiling is declared" in observations[0].message
        assert findings(ctx) == ()

    def test_manifest_with_no_ceilings_reports_absence_without_failing(self) -> None:
        base = _direct_action_context()
        ctx = context(acbom=base.acbom, manifest=manifest())

        observations = evaluate(ctx)

        assert len(observations) == 1
        assert "no capability ceiling is declared" in observations[0].message
        assert findings(ctx) == ()


class TestBoundary:
    def test_dead_end_disallowed_delegation_has_no_finding_but_has_an_observation(
        self,
    ) -> None:
        origin = agent_node(_AGENT_ID, name="coordinator")
        target = agent_node(_OTHER_AGENT_ID, name="untrusted")
        delegation = delegates_to_edge(
            _EDGE_ID, source=_AGENT_ID, target=_OTHER_AGENT_ID
        )
        manifest_doc = manifest(
            ceilings=(
                CapabilityCeiling(
                    agent="coordinator", prohibited_delegation_targets=("untrusted",)
                ),
            )
        )
        ctx = context(
            acbom=acbom(nodes=(origin, target), edges=(delegation,)),
            manifest=manifest_doc,
        )

        assert len(evaluate(ctx)) == 1
        assert findings(ctx) == ()

    def test_empty_acbom_produces_nothing(self) -> None:
        manifest_doc = manifest(
            ceilings=(
                CapabilityCeiling(
                    agent="coordinator", prohibited_actions=(EdgeType.WRITES,)
                ),
            )
        )
        ctx = context(manifest=manifest_doc)

        assert evaluate(ctx) == ()
        assert findings(ctx) == ()


class TestUnverifiable:
    def test_unknown_confidence_path_is_reported_as_unverifiable_never_compliant(
        self,
    ) -> None:
        """A path of unknown confidence is reported as unverifiable, never
        as compliant."""
        origin = agent_node(_AGENT_ID, name="coordinator")
        resource = resource_node(_RESOURCE_ID, name="prod-db")
        edge = reads_edge(
            _EDGE_ID,
            source=_AGENT_ID,
            target=_RESOURCE_ID,
            confidence=Confidence.UNKNOWN,
        )
        manifest_doc = manifest(
            ceilings=(
                CapabilityCeiling(
                    agent="coordinator", prohibited_actions=(EdgeType.WRITES,)
                ),
            )
        )
        ctx = context(
            acbom=acbom(nodes=(origin, resource), edges=(edge,)),
            manifest=manifest_doc,
        )

        observations = evaluate(ctx)

        assert len(observations) == 1
        assert "unknown confidence" in observations[0].message
        assert findings(ctx) == ()

    def test_a_confirmed_breach_is_not_also_reported_as_unverifiable(self) -> None:
        """An UNKNOWN-confidence edge that itself constitutes the
        breach is reported once, as the breach -- never doubled up
        with a separate unverifiable observation for the same path."""
        origin = agent_node(_AGENT_ID, name="coordinator")
        resource = resource_node(_RESOURCE_ID, name="prod-db")
        edge = writes_edge(
            _EDGE_ID,
            source=_AGENT_ID,
            target=_RESOURCE_ID,
            confidence=Confidence.UNKNOWN,
        )
        manifest_doc = manifest(
            ceilings=(
                CapabilityCeiling(
                    agent="coordinator", prohibited_actions=(EdgeType.WRITES,)
                ),
            )
        )
        ctx = context(
            acbom=acbom(nodes=(origin, resource), edges=(edge,)),
            manifest=manifest_doc,
        )

        observations = evaluate(ctx)
        assert len(observations) == 1
        assert "prohibited action" in observations[0].message

    def test_an_unrelated_acbom_diagnostic_does_not_trigger_a_false_positive(
        self,
    ) -> None:
        """This module's own unverifiable signal reacts only to
        diagnostics `compute_transitive_capability_paths` itself
        returns from its own bounded walk, never to an unrelated
        diagnostic already present on the ACBOM document."""
        origin = agent_node(_AGENT_ID, name="coordinator")
        manifest_doc = manifest(
            ceilings=(
                CapabilityCeiling(
                    agent="coordinator", prohibited_actions=(EdgeType.WRITES,)
                ),
            )
        )
        diagnostic = dynamic_registration_diagnostic()
        ctx = context(
            acbom=acbom(nodes=(origin,), diagnostics=(diagnostic,)),
            manifest=manifest_doc,
        )

        assert evaluate(ctx) == ()

    def test_a_real_cycle_diagnostic_produces_an_unverifiable_observation(
        self,
    ) -> None:
        """The diagnostic must come from `compute_transitive_capability_
        paths`'s own bounded walk, not merely be present on the ACBOM
        document -- a genuine two-agent delegation cycle triggers that
        function's own `INCOMPLETE-CYCLE-DETECTED` diagnostic."""
        coordinator = agent_node(_AGENT_ID, name="coordinator")
        other = agent_node(_OTHER_AGENT_ID, name="worker")
        there = delegates_to_edge(_EDGE_ID, source=_AGENT_ID, target=_OTHER_AGENT_ID)
        back = delegates_to_edge(
            _OTHER_EDGE_ID, source=_OTHER_AGENT_ID, target=_AGENT_ID
        )
        manifest_doc = manifest(
            ceilings=(
                CapabilityCeiling(
                    agent="coordinator", prohibited_actions=(EdgeType.INVOKES,)
                ),
            )
        )
        ctx = context(
            acbom=acbom(nodes=(coordinator, other), edges=(there, back)),
            manifest=manifest_doc,
        )

        observations = evaluate(ctx)

        assert len(observations) == 1
        assert "could not be fully verified" in observations[0].message
        assert findings(ctx) == ()


class TestDeterminism:
    def test_identical_context_twice_produces_identical_result(self) -> None:
        ctx = _direct_action_context()
        assert evaluate(ctx) == evaluate(ctx)
        assert findings(ctx) == findings(ctx)

    def test_shuffled_edge_and_node_order_produces_identical_result(self) -> None:
        origin = agent_node(_AGENT_ID, name="coordinator")
        intermediary = agent_node(_OTHER_AGENT_ID, name="worker")
        tool = tool_node(_TOOL_ID, name="delete-repo")
        delegation = delegates_to_edge(
            _EDGE_ID, source=_AGENT_ID, target=_OTHER_AGENT_ID
        )
        invocation = invokes_edge(
            _OTHER_EDGE_ID, source=_OTHER_AGENT_ID, target=_TOOL_ID
        )
        manifest_doc = manifest(
            ceilings=(
                CapabilityCeiling(
                    agent="coordinator", prohibited_actions=(EdgeType.INVOKES,)
                ),
            )
        )

        forward = context(
            acbom=acbom(
                nodes=(origin, intermediary, tool), edges=(delegation, invocation)
            ),
            manifest=manifest_doc,
        )
        reverse = context(
            acbom=acbom(
                nodes=(tool, intermediary, origin), edges=(invocation, delegation)
            ),
            manifest=manifest_doc,
        )

        assert evaluate(forward) == evaluate(reverse)
        assert findings(forward) == findings(reverse)
        assert len(findings(forward)) == 1


class TestEngineIntegration:
    def test_registers_and_runs_through_the_real_engine(self) -> None:
        ctx = _direct_action_context()
        result = engine_evaluate((RULE,), ctx)
        assert len(result.observations) == 1
        assert result.observations[0].rule_id == RULE_ID


class TestRuleIndependence:
    def test_breach_survives_every_other_registered_rule_being_disabled(self) -> None:
        """A breach is detected with no matching pattern rule enabled --
        every one of this package's other rule IDs is disabled via
        `PolicyConfig.disabled_rule_ids`, and the ceiling breach still
        produces a blocking finding through the real `evaluate_gate`
        pipeline. This rule's own `evaluate`/`findings` never consult any
        other rule module or the engine's rule registry, so this is not a
        redundant check -- it proves the breach survives the one production
        mechanism (`disabled_rule_ids`) that could otherwise silence a
        pattern-matched rule."""
        other_rule_ids = frozenset(rule.id for rule in ALL_RULES if rule.id != RULE_ID)
        catalog = tuple(RuleMetadata(id=rule.id, mandatory=False) for rule in ALL_RULES)
        policy_config = _policy_config(disabled_rule_ids=other_rule_ids)
        validate_disabled_rules(policy_config, catalog)

        ctx = _direct_action_context()
        result = evaluate_gate(
            findings(ctx),
            policy_config,
            scanner_version="0.0.0-test",
            rule_pack_name="test-pack",
            rule_pack_version="1.0.0",
            rule_pack_fingerprint="sha256:" + "0" * 64,
        )

        assert len(result.blocking_findings) == 1
        assert result.blocking_findings[0].rule_id == RULE_ID


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
