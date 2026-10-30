"""Integration coverage for controlloop.policy.rules.ALL_RULES: every
rule from both concurrently-developed batches (reconciled into one
merged `controlloop.policy.rules` package), plus every rule added
afterward, is actually engine-compatible together, not just
individually importable.

Proves, against the real `controlloop.policy.engine.evaluate`, that:
every rule's module passes the engine's own structural safety check (no
forbidden file/subprocess/network/LLM-SDK import); rule IDs are unique
across every rule; and running the whole registry
against one shared `RuleContext` does not raise, regardless of which
individual rules have anything to say about that context."""

from __future__ import annotations

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
from controlloop.policy.engine import evaluate
from controlloop.policy.models import RuleContext
from controlloop.policy.rules import ALL_RULES

_PLACEHOLDER_DIGEST = f"sha256:{'a' * 64}"

#: The first batch's four rules. The other three
#: (`policy.missing-action-logging`, `policy.unauthorized-delegation`,
#: `policy.unresolved-dynamic-registration`) landed concurrently in a
#: second batch, reconciled into this same registry by merge.
_THIS_BATCHS_RULE_IDS = frozenset(
    {
        "policy.undeclared-tools",
        "policy.destructive-or-financial-action",
        "policy.broad-permission",
        "policy.sensitive-write-without-approval",
    }
)
_SIBLING_BATCHS_RULE_IDS = frozenset(
    {
        "policy.missing-action-logging",
        "policy.unauthorized-delegation",
        "policy.unresolved-dynamic-registration",
    }
)
#: Added later, after the two-batch (seven-rule) reconciliation above,
#: each separately -- none part of either original batch.
_ISSUE_74_RULE_IDS = frozenset({"policy.capability-ceiling"})
_ISSUE_75_RULE_IDS = frozenset({"policy.exfiltration-triangle"})
_ISSUE_80_RULE_IDS = frozenset({"policy.hardcoded-secrets"})
_ISSUE_442_RULE_IDS = frozenset(
    {
        "policy.unpinned-agent-component",
        "policy.mcp-server-identity-change",
        "policy.overprivileged-agent-workflow",
        "policy.component-self-grant",
    }
)
_ISSUE_441_RULE_IDS = frozenset(
    {
        "policy.agent-hook-command-change",
        "policy.widened-permission-rule",
        "policy.permission-bypass-from-project",
    }
)
_ISSUE_451_RULE_IDS = frozenset({"policy.unsanctioned-agent-component"})
#: Rule pack 0.8.0's coding-agent rules.
_RULE_PACK_0_8_0_RULE_IDS = frozenset(
    {
        "policy.agent-sandbox-weakened",
        "policy.secret-exposed-to-untrusted-agent-run",
        "policy.credentialed-remote-mcp-server",
        "policy.workspace-scope-expansion",
        "policy.component-shell-execution",
    }
)
#: Rule pack 0.9.0's hook script rule.
_RULE_PACK_0_9_0_RULE_IDS = frozenset({"policy.hook-script-changed"})


def _empty_document() -> ACBOMDocument:
    agent = Node(
        id=f"clp:agent:sha256:{'b' * 64}",
        type=NodeType.AGENT,
        name="idle-agent",
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=(Evidence(adapter="mcp", path="agent.json"),),
    )
    return ACBOMDocument(
        schema_version="1.0.0",
        generator=Generator(name="controlloop", version="0.1.0"),
        repository=Repository(commit="abc123", root_digest=_PLACEHOLDER_DIGEST),
        nodes=(agent,),
        edges=(),
        diagnostics=(),
        digest=_PLACEHOLDER_DIGEST,
    )


class TestAllRulesRegistry:
    def test_this_batchs_four_rules_are_all_present(self) -> None:
        ids = {rule.id for rule in ALL_RULES}
        assert ids >= _THIS_BATCHS_RULE_IDS

    def test_the_reconciled_registry_has_every_registered_rule(
        self,
    ) -> None:
        assert {rule.id for rule in ALL_RULES} == (
            _THIS_BATCHS_RULE_IDS
            | _SIBLING_BATCHS_RULE_IDS
            | _ISSUE_74_RULE_IDS
            | _ISSUE_75_RULE_IDS
            | _ISSUE_80_RULE_IDS
            | _ISSUE_442_RULE_IDS
            | _ISSUE_441_RULE_IDS
            | _ISSUE_451_RULE_IDS
            | _RULE_PACK_0_8_0_RULE_IDS
            | _RULE_PACK_0_9_0_RULE_IDS
        )

    def test_every_rule_id_is_unique(self) -> None:
        ids = [rule.id for rule in ALL_RULES]
        assert len(ids) == len(set(ids))

    def test_the_whole_registry_evaluates_against_the_real_engine(self) -> None:
        context = RuleContext(
            acbom=_empty_document(), policy_version="1", manifest=None
        )

        result = evaluate(ALL_RULES, context)

        # Passing the engine's own structural safety check for every rule
        # module (including the three from the sibling batch and the
        # three later rules, capability-ceiling, exfiltration-triangle,
        # and hardcoded-secrets) and running without raising is the
        # assertion itself -- exactly two advisory RuleObservations are
        # expected here: undeclared-tools' own no-manifest count, and
        # capability-ceiling's "no ceiling declared" disclosure
        # (both fire from `manifest=None` alone, independent of the
        # empty graph). Exfiltration-triangle never fires on this
        # fixture: it requires at least two of its three legs to be
        # structurally present on some agent, and this fixture's one
        # agent has no edges at all. Hardcoded-secrets never fires
        # either: it only reads `SECRET-CREDENTIAL-SHAPE-DETECTED`/
        # `SECRET-HIGH-ENTROPY-VALUE-DETECTED` diagnostics, and this
        # fixture's `diagnostics` tuple is empty. An agent with no edges
        # and no diagnostics at all gives every other rule, from either
        # batch, nothing to report.
        assert len(result.observations) == 2
        observed_rule_ids = {observation.rule_id for observation in result.observations}
        assert observed_rule_ids == {
            "policy.undeclared-tools",
            "policy.capability-ceiling",
        }
        assert result.is_incomplete is False

    def test_evaluation_is_deterministic_across_repeated_runs(self) -> None:
        context = RuleContext(
            acbom=_empty_document(), policy_version="1", manifest=None
        )

        first = evaluate(ALL_RULES, context)
        second = evaluate(ALL_RULES, context)

        assert first == second
