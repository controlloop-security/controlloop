"""Tests for controlloop.policy.rulepack."""

from __future__ import annotations

import importlib.util
import inspect
import sys
from pathlib import Path
from types import ModuleType

import pytest

from controlloop.acbom.models import (
    ACBOMDocument,
    Confidence,
    Evidence,
    Generator,
    Node,
    NodeType,
    Repository,
    SecurityAttributes,
)
from controlloop.policy import evaluate as policy_evaluate
from controlloop.policy import rulepack
from controlloop.policy.models import Rule, RuleContext
from controlloop.policy.rulepack import (
    CURRENT_RULE_PACK,
    KNOWN_RULE_PACK_FINGERPRINTS,
    RulePack,
    RulePackError,
    rule_pack_fingerprint,
)
from controlloop.policy.rules import ALL_RULES
from controlloop.policy.thresholds import RuleMetadata

_FIXTURES_DIR = Path(__file__).parent / "fixtures"
_PLACEHOLDER_DIGEST = f"sha256:{'0' * 64}"


def _load_fixture_module(name: str) -> ModuleType:
    """Load a fixture rule module for real via `importlib`, independent of
    pytest's own import-mode configuration, so `inspect.getmodule`
    resolves it via the standard `sys.modules[__module__]` lookup path
    exactly as it would for a genuinely installed rule module -- the same
    technique `tests/policy/test_policy_engine.py`'s own
    `_load_fixture_module` already established, reused here rather than a
    relative import (this `tests/` tree has no `__init__.py` files, so
    `from .fixtures...` is not resolvable)."""

    module_name = f"controlloop_policy_test_fixture_{name}"
    spec = importlib.util.spec_from_file_location(
        module_name, _FIXTURES_DIR / f"{name}.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


_fixture_rules = _load_fixture_module("rule_pack_fixture_rules")
_evaluate_a = _fixture_rules.evaluate_a
_evaluate_a_changed = _fixture_rules.evaluate_a_changed
_evaluate_b = _fixture_rules.evaluate_b


def _pack(
    *,
    version: str = "1.0.0",
    rules: tuple[Rule, ...] = (Rule(id="policy.rule-a", evaluate=_evaluate_a),),
    metadata: tuple[RuleMetadata, ...] = (
        RuleMetadata(id="policy.rule-a", mandatory=False),
    ),
    name: str = "test-pack",
) -> RulePack:
    return RulePack(name=name, version=version, rules=rules, metadata=metadata)


def _node(node_id: str) -> Node:
    return Node(
        id=node_id,
        type=NodeType.AGENT,
        name="agent",
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=(Evidence(adapter="fixture", path="a.json"),),
    )


def _acbom() -> ACBOMDocument:
    return ACBOMDocument(
        schema_version="1.0.0",
        generator=Generator(name="controlloop", version="0.1.0"),
        repository=Repository(commit="abc123", root_digest=f"sha256:{'d' * 64}"),
        nodes=(_node(f"clp:agent:sha256:{'a' * 64}"),),
        edges=(),
        diagnostics=(),
        digest=_PLACEHOLDER_DIGEST,
    )


class TestRulePackConstruction:
    """A `RulePack` is a validated, versioned, named collection of rules
    paired with governance metadata."""

    def test_valid_pack_constructs(self) -> None:
        pack = _pack()

        assert pack.name == "test-pack"
        assert pack.version == "1.0.0"
        assert len(pack.rules) == 1
        assert len(pack.metadata) == 1

    def test_malformed_name_raises(self) -> None:
        with pytest.raises(Exception):  # noqa: B017 - pydantic TypeAdapter error
            _pack(name="")

    def test_malformed_version_raises(self) -> None:
        with pytest.raises(Exception):  # noqa: B017 - pydantic TypeAdapter error
            _pack(version="not-a-version")

    def test_duplicate_rule_id_raises(self) -> None:
        rules = (
            Rule(id="policy.rule-a", evaluate=_evaluate_a),
            Rule(id="policy.rule-a", evaluate=_evaluate_a_changed),
        )
        with pytest.raises(RulePackError, match="duplicate rule id"):
            _pack(
                rules=rules,
                metadata=(RuleMetadata(id="policy.rule-a", mandatory=False),),
            )

    def test_duplicate_metadata_id_raises(self) -> None:
        metadata = (
            RuleMetadata(id="policy.rule-a", mandatory=False),
            RuleMetadata(id="policy.rule-a", mandatory=True),
        )
        with pytest.raises(RulePackError, match="duplicate metadata id"):
            _pack(metadata=metadata)

    def test_rules_and_metadata_naming_different_ids_raises(self) -> None:
        with pytest.raises(RulePackError, match="same set of rule ids"):
            _pack(
                rules=(Rule(id="policy.rule-a", evaluate=_evaluate_a),),
                metadata=(RuleMetadata(id="policy.rule-b", mandatory=False),),
            )

    def test_empty_pack_is_valid(self) -> None:
        pack = RulePack(name="empty-pack", version="1.0.0", rules=(), metadata=())

        assert pack.rules == ()
        assert pack.metadata == ()


class TestRulePackFingerprint:
    """Adding, removing, or changing a rule's behavior without a version
    increment must change the computed fingerprint, so a pinned fingerprint
    test can fail CI."""

    def test_identical_pack_produces_identical_fingerprint(self) -> None:
        first = rule_pack_fingerprint(_pack())
        second = rule_pack_fingerprint(_pack())

        assert first == second

    def test_fingerprint_is_order_independent(self) -> None:
        rules_ab = (
            Rule(id="policy.rule-a", evaluate=_evaluate_a),
            Rule(id="policy.rule-b", evaluate=_evaluate_b),
        )
        rules_ba = (
            Rule(id="policy.rule-b", evaluate=_evaluate_b),
            Rule(id="policy.rule-a", evaluate=_evaluate_a),
        )
        metadata = (
            RuleMetadata(id="policy.rule-a", mandatory=False),
            RuleMetadata(id="policy.rule-b", mandatory=False),
        )

        forward = rule_pack_fingerprint(_pack(rules=rules_ab, metadata=metadata))
        backward = rule_pack_fingerprint(_pack(rules=rules_ba, metadata=metadata))

        assert forward == backward

    def test_fingerprint_changes_when_a_rules_source_changes(self) -> None:
        original = rule_pack_fingerprint(_pack())
        changed = rule_pack_fingerprint(
            _pack(rules=(Rule(id="policy.rule-a", evaluate=_evaluate_a_changed),))
        )

        assert original != changed

    def test_fingerprint_changes_when_a_rule_is_added(self) -> None:
        base = rule_pack_fingerprint(_pack())
        with_extra = rule_pack_fingerprint(
            _pack(
                rules=(
                    Rule(id="policy.rule-a", evaluate=_evaluate_a),
                    Rule(id="policy.rule-b", evaluate=_evaluate_b),
                ),
                metadata=(
                    RuleMetadata(id="policy.rule-a", mandatory=False),
                    RuleMetadata(id="policy.rule-b", mandatory=False),
                ),
            )
        )

        assert base != with_extra

    def test_fingerprint_changes_when_a_rule_is_removed(self) -> None:
        with_two = rule_pack_fingerprint(
            _pack(
                rules=(
                    Rule(id="policy.rule-a", evaluate=_evaluate_a),
                    Rule(id="policy.rule-b", evaluate=_evaluate_b),
                ),
                metadata=(
                    RuleMetadata(id="policy.rule-a", mandatory=False),
                    RuleMetadata(id="policy.rule-b", mandatory=False),
                ),
            )
        )
        with_one = rule_pack_fingerprint(_pack())

        assert with_two != with_one

    def test_fingerprint_changes_when_only_mandatory_flag_changes(self) -> None:
        not_mandatory = rule_pack_fingerprint(
            _pack(metadata=(RuleMetadata(id="policy.rule-a", mandatory=False),))
        )
        mandatory = rule_pack_fingerprint(
            _pack(metadata=(RuleMetadata(id="policy.rule-a", mandatory=True),))
        )

        assert not_mandatory != mandatory

    def test_empty_pack_fingerprint_is_stable(self) -> None:
        empty = RulePack(name="empty-pack", version="1.0.0", rules=(), metadata=())

        assert rule_pack_fingerprint(empty) == rule_pack_fingerprint(empty)


#: The decided mandatory/nonblocking classification, mirrored here so a
#: change to `CURRENT_RULE_PACK`'s own metadata that silently drifts from
#: this decision fails a real assertion, not only the opaque fingerprint
#: pin below.
_EXPECTED_MANDATORY_BY_RULE_ID: dict[str, bool] = {
    "policy.undeclared-tools": False,
    "policy.destructive-or-financial-action": True,
    "policy.broad-permission": False,
    "policy.sensitive-write-without-approval": True,
    "policy.missing-action-logging": False,
    "policy.unauthorized-delegation": False,
    "policy.unresolved-dynamic-registration": False,
    "policy.capability-ceiling": True,
    "policy.exfiltration-triangle": True,
    "policy.hardcoded-secrets": True,
    "policy.unpinned-agent-component": False,
    "policy.mcp-server-identity-change": False,
    "policy.overprivileged-agent-workflow": False,
    "policy.component-self-grant": False,
    "policy.agent-hook-command-change": False,
    "policy.widened-permission-rule": False,
    "policy.permission-bypass-from-project": False,
    "policy.unsanctioned-agent-component": False,
}


class TestCurrentRulePack:
    """The actual bundled Community rule pack, and its pinned-fingerprint
    CI check."""

    def test_current_rule_pack_ships_all_registered_rules(self) -> None:
        """`CURRENT_RULE_PACK` carries every rule
        `controlloop.policy.rules.ALL_RULES` currently registers, each
        paired with its decided `mandatory` governance flag."""

        assert CURRENT_RULE_PACK.name == "controlloop-community"
        # Includes the seven agent-authority rules and the Team
        # sanctioned-list rule. 0.6.0 fingerprints rule modules and shared
        # helpers; its rules are 0.5.0's, with per-occurrence secret IDs.
        assert CURRENT_RULE_PACK.version == "0.6.0"
        assert len(ALL_RULES) == 18
        assert set(CURRENT_RULE_PACK.rules) == set(ALL_RULES)
        assert {rule.id for rule in CURRENT_RULE_PACK.rules} == {
            rule.id for rule in ALL_RULES
        }

        actual_mandatory_by_id = {
            entry.id: entry.mandatory for entry in CURRENT_RULE_PACK.metadata
        }
        assert actual_mandatory_by_id == _EXPECTED_MANDATORY_BY_RULE_ID

    def test_current_rule_pack_fingerprint_matches_pinned_registry(self) -> None:
        """The actual CI-enforced check: the fingerprint this codebase
        *computes* from `CURRENT_RULE_PACK` right now must match the
        fingerprint *pinned* in `KNOWN_RULE_PACK_FINGERPRINTS` for its
        declared version. A future change that adds, removes, or changes a
        rule in `CURRENT_RULE_PACK` without adding a new pinned entry for a
        new version fails exactly this assertion."""

        assert CURRENT_RULE_PACK.version in KNOWN_RULE_PACK_FINGERPRINTS
        assert (
            rule_pack_fingerprint(CURRENT_RULE_PACK)
            == KNOWN_RULE_PACK_FINGERPRINTS[CURRENT_RULE_PACK.version]
        )


class TestReproducibility:
    """Pinning a rule pack version reproduces a prior verdict on unchanged
    input -- ties directly to `controlloop.policy.engine. evaluate`'s own
    already-proven determinism."""

    def test_pinning_a_rule_pack_version_reproduces_prior_verdict_on_unchanged_input(
        self,
    ) -> None:
        pack = _pack(version="9.9.9")
        context = RuleContext(acbom=_acbom(), policy_version="pinned-9.9.9")

        first = policy_evaluate(pack.rules, context)
        second = policy_evaluate(pack.rules, context)

        assert first == second
        assert first.observations != ()  # the pack's rule really ran


class TestOffline:
    def test_offline_harness_is_active_for_this_module(self) -> None:
        import socket

        with pytest.raises(RuntimeError, match="offline harness"):
            socket.socket()


_RULE_MODULE_TEMPLATE = """\
from controlloop.policy.models import RuleContext, RuleObservation


def findings(context: RuleContext) -> tuple[RuleObservation, ...]:
    return {findings_body}


def evaluate(context: RuleContext) -> tuple[RuleObservation, ...]:
    return findings(context)
"""


def _write_rule_module(tmp_path: Path, name: str, findings_body: str) -> ModuleType:
    path = tmp_path / f"{name}.py"
    path.write_text(
        _RULE_MODULE_TEMPLATE.format(findings_body=findings_body), encoding="utf-8"
    )
    module_name = f"controlloop_policy_test_fixture_{name}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


class TestRulePackFingerprintCoversRuleLogic:
    """Every rule's `evaluate` is a thin wrapper over `findings`, so the
    fingerprint must cover the module that holds the logic, and the shared
    helpers rules call into, or a logic change ships under an old pin."""

    def test_a_change_inside_findings_changes_the_fingerprint(
        self, tmp_path: Path
    ) -> None:
        before = _write_rule_module(tmp_path, "logic_before", "()")
        after = _write_rule_module(tmp_path, "logic_after", "tuple([])")

        assert inspect.getsource(before.evaluate) == inspect.getsource(after.evaluate)
        assert rule_pack_fingerprint(
            _pack(rules=(Rule(id="policy.rule-a", evaluate=before.evaluate),))
        ) != rule_pack_fingerprint(
            _pack(rules=(Rule(id="policy.rule-a", evaluate=after.evaluate),))
        )

    def test_the_shared_rule_helpers_are_part_of_the_fingerprint(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with_helpers = rule_pack_fingerprint(_pack())
        monkeypatch.setattr(rulepack, "_SHARED_RULE_MODULES", ())

        assert rule_pack_fingerprint(_pack()) != with_helpers

    def test_every_shared_rule_helper_module_exists(self) -> None:
        for name in rulepack._SHARED_RULE_MODULES:
            assert importlib.util.find_spec(name) is not None, name
