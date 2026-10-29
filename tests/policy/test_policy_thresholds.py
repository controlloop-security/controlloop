"""Tests for controlloop.policy.thresholds."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from controlloop.acbom.models import Confidence, EdgeType, Evidence, NodeType
from controlloop.capability.models import CapabilityPath, PathHop
from controlloop.config import CONFIG_FILENAME, ConfigSource, load_config
from controlloop.findings.models import (
    CURRENT_FINDING_SCHEMA_VERSION,
    Finding,
    FindingChangeState,
    FindingSeverity,
)
from controlloop.policy.thresholds import (
    ActionSource,
    CompletenessEnforcement,
    GateStatus,
    GateVerdict,
    LowConfidenceAction,
    PolicyConfig,
    PolicyConfigError,
    RuleAction,
    RuleMetadata,
    evaluate_gate,
    finding_action,
    resolve_policy_config,
    severity_at_least,
    severity_rank,
    validate_disabled_rules,
)
from controlloop.repository import RepositoryRoot

_AGENT_ID = f"clp:agent:sha256:{'a' * 64}"
_TOOL_ID = f"clp:tool:sha256:{'b' * 64}"
_EDGE_ID = f"clp:edge:sha256:{'c' * 64}"
_EVIDENCE = (Evidence(adapter="mcp", path="agent.json", line_start=3, line_end=4),)


def _root(path: Path) -> RepositoryRoot:
    return RepositoryRoot(path=path)


def _capability_path() -> CapabilityPath:
    return CapabilityPath(
        schema_version="1.0.0",
        agent_id=_AGENT_ID,
        target_id=_TOOL_ID,
        target_type=NodeType.TOOL,
        hops=(
            PathHop(
                edge_id=_EDGE_ID,
                edge_type=EdgeType.INVOKES,
                source_id=_AGENT_ID,
                target_id=_TOOL_ID,
                evidence=_EVIDENCE,
            ),
        ),
        confidence=Confidence.HIGH,
    )


def _finding(
    *,
    finding_id_suffix: str,
    rule_id: str = "policy.undeclared-tools",
    severity: FindingSeverity = FindingSeverity.HIGH,
    confidence: Confidence = Confidence.HIGH,
) -> Finding:
    return Finding(
        schema_version=CURRENT_FINDING_SCHEMA_VERSION,
        id=f"clp:finding:sha256:{finding_id_suffix * 64}",
        rule_id=rule_id,
        rule_version="1.0.0",
        message="undeclared tool reachable",
        severity=severity,
        confidence=confidence,
        affected_agent=_AGENT_ID,
        evidence=_EVIDENCE,
        capability_path=_capability_path(),
        change_state=FindingChangeState.ADDED,
        remediation="declare the tool in controlloop.yaml",
        documentation_url="https://docs.controlloop.ai/rules/undeclared-tools",
    )


def _policy_config(
    *,
    severity_threshold: FindingSeverity = FindingSeverity.MEDIUM,
    low_confidence_action: LowConfidenceAction = LowConfidenceAction.BLOCK,
    disabled_rule_ids: frozenset[str] = frozenset(),
    completeness_enforcement: CompletenessEnforcement = CompletenessEnforcement.WARN,
) -> PolicyConfig:
    return PolicyConfig(
        severity_threshold=severity_threshold,
        severity_threshold_source=ConfigSource.DEFAULT,
        low_confidence_action=low_confidence_action,
        low_confidence_action_source=ConfigSource.DEFAULT,
        disabled_rule_ids=disabled_rule_ids,
        disabled_rule_ids_source=ConfigSource.DEFAULT,
        completeness_enforcement=completeness_enforcement,
        completeness_enforcement_source=ConfigSource.DEFAULT,
    )


#: `evaluate_gate` takes four required rule-pack/scanner identity keyword
#: arguments. This wrapper supplies fixed test values for every
#: severity/confidence/threshold test in this module, which is not
#: testing rule-pack identity itself -- `TestRulePackIdentity` below
#: exercises those four fields directly.
def _evaluate_gate(
    findings: tuple[Finding, ...], policy_config: PolicyConfig
) -> GateVerdict:
    return evaluate_gate(
        findings,
        policy_config,
        scanner_version="1.2.3",
        rule_pack_name="test-pack",
        rule_pack_version="9.9.9",
        rule_pack_fingerprint="deadbeef",
    )


class TestSeverityOrder:
    def test_severity_order_is_the_five_declared_members_ascending(self) -> None:
        assert [severity_rank(s) for s in FindingSeverity] == [0, 1, 2, 3, 4]

    @pytest.mark.parametrize(
        ("lower", "higher"),
        [
            (FindingSeverity.INFO, FindingSeverity.LOW),
            (FindingSeverity.LOW, FindingSeverity.MEDIUM),
            (FindingSeverity.MEDIUM, FindingSeverity.HIGH),
            (FindingSeverity.HIGH, FindingSeverity.CRITICAL),
        ],
    )
    def test_severity_at_least_boundary_pairs(
        self, lower: FindingSeverity, higher: FindingSeverity
    ) -> None:
        assert severity_at_least(higher, lower) is True
        assert severity_at_least(lower, higher) is False

    def test_severity_at_least_is_reflexive(self) -> None:
        for severity in FindingSeverity:
            assert severity_at_least(severity, severity) is True


class TestSeverityValuesMatchFindingSeverity:
    """Guards `controlloop.config`'s local, literal
    `_SEVERITY_THRESHOLD_VALUES` frozenset against silently drifting from
    `FindingSeverity`'s real members -- see `controlloop.config`'s module
    docstring for why the set is duplicated rather than imported."""

    def test_config_severity_values_match_finding_severity_members(self) -> None:
        from controlloop.config import _SEVERITY_THRESHOLD_VALUES

        assert frozenset(s.value for s in FindingSeverity) == _SEVERITY_THRESHOLD_VALUES

    def test_config_action_values_match_low_confidence_action_members(self) -> None:
        from controlloop.config import _LOW_CONFIDENCE_ACTION_VALUES

        assert (
            frozenset(a.value for a in LowConfidenceAction)
            == _LOW_CONFIDENCE_ACTION_VALUES
        )


class TestCompletenessEnforcementValuesMatchConfig:
    """Guards `controlloop.config`'s local, literal
    `_COMPLETENESS_ENFORCEMENT_VALUES` frozenset against silently drifting
    from `CompletenessEnforcement`'s real members -- see
    `controlloop.config`'s module docstring for why the set is duplicated
    rather than imported."""

    def test_config_values_match_completeness_enforcement_members(self) -> None:
        from controlloop.config import _COMPLETENESS_ENFORCEMENT_VALUES

        assert (
            frozenset(e.value for e in CompletenessEnforcement)
            == _COMPLETENESS_ENFORCEMENT_VALUES
        )


class TestResolvePolicyConfig:
    """`resolve_policy_config` reads `ResolvedConfig` correctly, including
    source propagation."""

    def test_defaults_resolve_to_documented_starting_values(
        self, tmp_path: Path
    ) -> None:
        resolved = load_config(_root(tmp_path), environ={}, flags={})

        policy = resolve_policy_config(resolved)

        assert policy.severity_threshold is FindingSeverity.HIGH
        assert policy.severity_threshold_source is ConfigSource.DEFAULT
        assert policy.low_confidence_action is LowConfidenceAction.BLOCK
        assert policy.low_confidence_action_source is ConfigSource.DEFAULT
        assert policy.disabled_rule_ids == frozenset()
        assert policy.disabled_rule_ids_source is ConfigSource.DEFAULT
        assert policy.completeness_enforcement is CompletenessEnforcement.WARN
        assert policy.completeness_enforcement_source is ConfigSource.DEFAULT

    def test_repository_file_values_and_source_propagate(self, tmp_path: Path) -> None:
        (tmp_path / CONFIG_FILENAME).write_text(
            'severity_threshold = "low"\n'
            'low_confidence_action = "warn"\n'
            'disabled_rules = ["policy.rule-a"]\n'
            'completeness_enforcement = "enforce"\n'
        )

        resolved = load_config(_root(tmp_path), environ={}, flags={})
        policy = resolve_policy_config(resolved)

        assert policy.severity_threshold is FindingSeverity.LOW
        assert policy.severity_threshold_source is ConfigSource.REPOSITORY_FILE
        assert policy.low_confidence_action is LowConfidenceAction.WARN
        assert policy.low_confidence_action_source is ConfigSource.REPOSITORY_FILE
        assert policy.disabled_rule_ids == frozenset({"policy.rule-a"})
        assert policy.disabled_rule_ids_source is ConfigSource.REPOSITORY_FILE
        assert policy.completeness_enforcement is CompletenessEnforcement.ENFORCE
        assert policy.completeness_enforcement_source is ConfigSource.REPOSITORY_FILE


class TestValidateDisabledRules:
    """Mandatory rules cannot be disabled; disabling one returns an error
    naming the rule."""

    _CATALOG = (
        RuleMetadata(id="policy.optional-a", mandatory=False),
        RuleMetadata(id="policy.optional-b", mandatory=False),
        RuleMetadata(id="policy.mandatory-a", mandatory=True),
    )

    def test_disabling_a_nonmandatory_known_rule_passes(self) -> None:
        policy = _policy_config(disabled_rule_ids=frozenset({"policy.optional-a"}))

        validate_disabled_rules(policy, self._CATALOG)  # must not raise

    def test_disabling_an_unknown_rule_raises(self) -> None:
        policy = _policy_config(disabled_rule_ids=frozenset({"policy.does-not-exist"}))

        with pytest.raises(PolicyConfigError, match=re.escape("policy.does-not-exist")):
            validate_disabled_rules(policy, self._CATALOG)

    def test_disabling_a_mandatory_rule_raises_naming_the_rule(self) -> None:
        policy = _policy_config(disabled_rule_ids=frozenset({"policy.mandatory-a"}))

        with pytest.raises(
            PolicyConfigError, match=re.escape("policy.mandatory-a")
        ) as excinfo:
            validate_disabled_rules(policy, self._CATALOG)

        assert excinfo.value.exit_code == 2

    def test_multiple_disabled_with_one_mandatory_still_names_it(self) -> None:
        policy = _policy_config(
            disabled_rule_ids=frozenset(
                {"policy.optional-a", "policy.optional-b", "policy.mandatory-a"}
            )
        )

        with pytest.raises(PolicyConfigError, match=re.escape("policy.mandatory-a")):
            validate_disabled_rules(policy, self._CATALOG)

    def test_empty_disabled_set_passes_with_empty_catalog(self) -> None:
        validate_disabled_rules(_policy_config(), catalog=())  # must not raise


class TestEvaluateGate:
    """Severity threshold determines the verdict; a low-confidence finding
    can warn instead of block, without disappearing."""

    def test_finding_above_threshold_blocks(self) -> None:
        finding = _finding(finding_id_suffix="1", severity=FindingSeverity.CRITICAL)
        policy = _policy_config(severity_threshold=FindingSeverity.HIGH)

        verdict = _evaluate_gate((finding,), policy)

        assert verdict.status is GateStatus.FAIL
        assert verdict.blocking_findings == (finding,)
        assert verdict.warning_findings == ()

    def test_finding_at_threshold_blocks(self) -> None:
        finding = _finding(finding_id_suffix="1", severity=FindingSeverity.HIGH)
        policy = _policy_config(severity_threshold=FindingSeverity.HIGH)

        verdict = _evaluate_gate((finding,), policy)

        assert verdict.status is GateStatus.FAIL
        assert finding in verdict.blocking_findings

    def test_finding_below_threshold_neither_blocks_nor_warns(self) -> None:
        finding = _finding(finding_id_suffix="1", severity=FindingSeverity.LOW)
        policy = _policy_config(severity_threshold=FindingSeverity.HIGH)

        verdict = _evaluate_gate((finding,), policy)

        assert verdict.status is GateStatus.PASS
        assert verdict.blocking_findings == ()
        assert verdict.warning_findings == ()

    def test_no_findings_passes(self) -> None:
        verdict = _evaluate_gate((), _policy_config())

        assert verdict.status is GateStatus.PASS
        assert verdict.blocking_findings == ()
        assert verdict.warning_findings == ()

    def test_low_confidence_blocks_by_default(self) -> None:
        finding = _finding(
            finding_id_suffix="1",
            severity=FindingSeverity.HIGH,
            confidence=Confidence.LOW,
        )
        policy = _policy_config(
            severity_threshold=FindingSeverity.MEDIUM,
            low_confidence_action=LowConfidenceAction.BLOCK,
        )

        verdict = _evaluate_gate((finding,), policy)

        assert verdict.status is GateStatus.FAIL
        assert verdict.blocking_findings == (finding,)
        assert verdict.warning_findings == ()

    def test_low_confidence_warns_when_configured_and_is_not_hidden(self) -> None:
        finding = _finding(
            finding_id_suffix="1",
            severity=FindingSeverity.HIGH,
            confidence=Confidence.LOW,
        )
        policy = _policy_config(
            severity_threshold=FindingSeverity.MEDIUM,
            low_confidence_action=LowConfidenceAction.WARN,
        )

        verdict = _evaluate_gate((finding,), policy)

        assert verdict.status is GateStatus.PASS
        assert verdict.blocking_findings == ()
        assert verdict.warning_findings == (finding,)

    def test_unknown_confidence_is_also_treated_as_low(self) -> None:
        finding = _finding(
            finding_id_suffix="1",
            severity=FindingSeverity.HIGH,
            confidence=Confidence.UNKNOWN,
        )
        policy = _policy_config(
            severity_threshold=FindingSeverity.MEDIUM,
            low_confidence_action=LowConfidenceAction.WARN,
        )

        verdict = _evaluate_gate((finding,), policy)

        assert verdict.warning_findings == (finding,)

    def test_high_confidence_finding_never_downgraded_to_warning(self) -> None:
        finding = _finding(
            finding_id_suffix="1",
            severity=FindingSeverity.HIGH,
            confidence=Confidence.HIGH,
        )
        policy = _policy_config(
            severity_threshold=FindingSeverity.MEDIUM,
            low_confidence_action=LowConfidenceAction.WARN,
        )

        verdict = _evaluate_gate((finding,), policy)

        assert verdict.blocking_findings == (finding,)
        assert verdict.warning_findings == ()

    def test_low_confidence_below_threshold_stays_unsurfaced_under_warn(self) -> None:
        finding = _finding(
            finding_id_suffix="1",
            severity=FindingSeverity.LOW,
            confidence=Confidence.LOW,
        )
        policy = _policy_config(
            severity_threshold=FindingSeverity.HIGH,
            low_confidence_action=LowConfidenceAction.WARN,
        )

        verdict = _evaluate_gate((finding,), policy)

        assert verdict.status is GateStatus.PASS
        assert verdict.blocking_findings == ()
        assert verdict.warning_findings == ()

    def test_disabled_rule_finding_is_dropped_entirely(self) -> None:
        finding = _finding(
            finding_id_suffix="1",
            rule_id="policy.disabled-rule",
            severity=FindingSeverity.CRITICAL,
        )
        policy = _policy_config(
            severity_threshold=FindingSeverity.LOW,
            disabled_rule_ids=frozenset({"policy.disabled-rule"}),
        )

        verdict = _evaluate_gate((finding,), policy)

        assert verdict.status is GateStatus.PASS
        assert verdict.blocking_findings == ()
        assert verdict.warning_findings == ()

    def test_verdict_carries_the_policy_config_used(self) -> None:
        policy = _policy_config(severity_threshold=FindingSeverity.CRITICAL)

        verdict = _evaluate_gate((), policy)

        assert verdict.policy_config is policy

    def test_verdict_carries_scanner_version_and_rule_pack_identity(self) -> None:
        """A result records both scanner version and rule pack version."""

        verdict = evaluate_gate(
            (),
            _policy_config(),
            scanner_version="1.2.3",
            rule_pack_name="controlloop-community",
            rule_pack_version="0.1.0",
            rule_pack_fingerprint="abc123",
        )

        assert verdict.scanner_version == "1.2.3"
        assert verdict.rule_pack_name == "controlloop-community"
        assert verdict.rule_pack_version == "0.1.0"
        assert verdict.rule_pack_fingerprint == "abc123"

    def test_ordering_is_deterministic_regardless_of_input_order(self) -> None:
        first = _finding(finding_id_suffix="1", severity=FindingSeverity.CRITICAL)
        second = _finding(finding_id_suffix="2", severity=FindingSeverity.CRITICAL)
        policy = _policy_config(severity_threshold=FindingSeverity.HIGH)

        forward = _evaluate_gate((first, second), policy)
        backward = _evaluate_gate((second, first), policy)

        assert forward.blocking_findings == backward.blocking_findings
        assert forward.blocking_findings == tuple(
            sorted((first, second), key=lambda f: f.id)
        )

    def test_mixed_blocking_and_warning_findings(self) -> None:
        blocking = _finding(finding_id_suffix="1", severity=FindingSeverity.CRITICAL)
        warning = _finding(
            finding_id_suffix="2",
            severity=FindingSeverity.CRITICAL,
            confidence=Confidence.LOW,
        )
        policy = _policy_config(
            severity_threshold=FindingSeverity.HIGH,
            low_confidence_action=LowConfidenceAction.WARN,
        )

        verdict = _evaluate_gate((blocking, warning), policy)

        assert verdict.status is GateStatus.FAIL
        assert verdict.blocking_findings == (blocking,)
        assert verdict.warning_findings == (warning,)


class TestOrganizationActions:
    """On a Team gate a rule's organization action, not the finding's
    severity, decides what the finding does to the verdict."""

    def _evaluate(
        self,
        findings: tuple[Finding, ...],
        actions: dict[str, str],
        policy: PolicyConfig | None = None,
    ) -> GateVerdict:
        return evaluate_gate(
            findings,
            policy or _policy_config(severity_threshold=FindingSeverity.HIGH),
            scanner_version="1.2.3",
            rule_pack_name="test-pack",
            rule_pack_version="9.9.9",
            rule_pack_fingerprint="deadbeef",
            rule_actions=actions,
        )

    def test_fail_blocks_a_finding_below_the_threshold(self) -> None:
        low = _finding(finding_id_suffix="1", severity=FindingSeverity.LOW)

        verdict = self._evaluate((low,), {"policy.undeclared-tools": "fail"})

        assert verdict.status is GateStatus.FAIL
        assert verdict.blocking_findings == (low,)

    def test_require_review_neither_blocks_nor_warns(self) -> None:
        high = _finding(finding_id_suffix="1")

        verdict = self._evaluate((high,), {"policy.undeclared-tools": "require_review"})

        assert verdict.status is GateStatus.PASS
        assert verdict.review_findings == (high,)
        assert verdict.blocking_findings == ()
        assert verdict.warning_findings == ()

    def test_warn_reports_a_finding_above_the_threshold_without_blocking(self) -> None:
        critical = _finding(finding_id_suffix="1", severity=FindingSeverity.CRITICAL)

        verdict = self._evaluate((critical,), {"policy.undeclared-tools": "warn"})

        assert verdict.status is GateStatus.PASS
        assert verdict.warning_findings == (critical,)

    def test_pass_never_affects_the_verdict(self) -> None:
        critical = _finding(finding_id_suffix="1", severity=FindingSeverity.CRITICAL)

        verdict = self._evaluate((critical,), {"policy.undeclared-tools": "pass"})

        assert verdict.status is GateStatus.PASS
        assert verdict.blocking_findings == ()
        assert verdict.review_findings == ()
        assert verdict.warning_findings == ()

    def test_a_rule_without_an_action_keeps_the_threshold(self) -> None:
        high = _finding(finding_id_suffix="1")
        low = _finding(
            finding_id_suffix="2",
            rule_id="policy.broad-permission",
            severity=FindingSeverity.LOW,
        )

        verdict = self._evaluate((high, low), {"policy.other-rule": "pass"})

        assert verdict.blocking_findings == (high,)
        assert verdict.warning_findings == ()

    def test_fail_is_not_softened_by_low_confidence_action(self) -> None:
        low_confidence = _finding(finding_id_suffix="1", confidence=Confidence.LOW)
        policy = _policy_config(
            severity_threshold=FindingSeverity.HIGH,
            low_confidence_action=LowConfidenceAction.WARN,
        )

        verdict = self._evaluate(
            (low_confidence,), {"policy.undeclared-tools": "fail"}, policy
        )

        assert verdict.blocking_findings == (low_confidence,)

    def test_an_unknown_action_is_enforced_as_fail(self) -> None:
        low = _finding(finding_id_suffix="1", severity=FindingSeverity.LOW)

        verdict = self._evaluate((low,), {"policy.undeclared-tools": "quarantine"})

        assert verdict.blocking_findings == (low,)

    def test_a_disabled_rule_is_still_dropped(self) -> None:
        high = _finding(finding_id_suffix="1")
        policy = _policy_config(
            severity_threshold=FindingSeverity.HIGH,
            disabled_rule_ids=frozenset({"policy.undeclared-tools"}),
        )

        verdict = self._evaluate((high,), {"policy.undeclared-tools": "fail"}, policy)

        assert verdict.blocking_findings == ()

    def test_finding_action_names_its_source(self) -> None:
        policy = _policy_config(severity_threshold=FindingSeverity.HIGH)
        high = _finding(finding_id_suffix="1")
        low = _finding(finding_id_suffix="2", severity=FindingSeverity.LOW)

        assert finding_action(high, policy, {"policy.undeclared-tools": "warn"}) == (
            RuleAction.WARN,
            ActionSource.ORGANIZATION,
        )
        assert finding_action(high, policy) == (
            RuleAction.FAIL,
            ActionSource.SEVERITY_THRESHOLD,
        )
        assert finding_action(low, policy) == (
            RuleAction.PASS,
            ActionSource.SEVERITY_THRESHOLD,
        )


class TestOffline:
    def test_offline_harness_is_active_for_this_module(self) -> None:
        """`tests/conftest.py`'s autouse `_deny_network_access` fixture
        already covers every test under `tests/`, including this
        module -- no dedicated network-mocking is required here. This test
        exists only to record that fact explicitly, mirroring
        `tests/policy/test_policy_engine.py`'s own
        `TestOffline.test_offline_harness_is_active_for_this_module`."""

        import socket

        with pytest.raises(RuntimeError, match="offline harness"):
            socket.socket()
