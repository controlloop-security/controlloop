"""The deterministic policy/rule engine.

This package is the local CLI's policy engine. It evaluates explicit
evidence (`controlloop.acbom.models.ACBOMDocument`, optionally
`controlloop.diff.models.DiffResult`) against explicit policy
(optionally `controlloop.manifest.models.ManifestDocument`) with no
side effects and no model in the verdict.

`controlloop.policy.models` holds pure data: `Rule`, `RuleContext`,
`RuleObservation`, `EvaluationBounds`, `EvaluationResult`, and the two
exception types this package raises. `controlloop.policy.engine`
holds the actual evaluation logic, `evaluate()`, and is the module the
engine's structural safety tests check.

The concrete rules live in `controlloop.policy.rules`, one module per
rule, registered in one registry, `controlloop.policy.rules.ALL_RULES`.
Expiring suppressions are a suppression mechanism, not a detection rule,
and are not part of this registry. `controlloop.policy.rulepack`'s
`CURRENT_RULE_PACK` carries the registered rules, each paired with a
decided `RuleMetadata.mandatory` governance flag. See
`docs/reference/rule-engine.md` and `docs/reference/policy-rules.md` for
the full design rationale. `controlloop scan`/`gate` consume every
registered rule via `ALL_RULES`.

`controlloop.policy.thresholds` is the deterministic
severity/confidence/threshold decision core layered on top of `Finding`:
`evaluate_gate` turns a tuple of `Finding`s and a resolved
`PolicyConfig` into a `GateVerdict`. See `docs/reference/
policy-thresholds.md`. Both real CLI commands (`scan`, `gate`) consume
it.

`controlloop.policy.rulepack` versions a rule pack independently of the
scanner: `RulePack` pairs execution `Rule`s with governance
`RuleMetadata`, `rule_pack_fingerprint` gives it a content digest, and
`CURRENT_RULE_PACK` is this Community CLI's actual bundled pack.
`controlloop --version` reports its name, version, and rule count. See
`docs/reference/rule-pack-versioning.md`.
"""

from controlloop.policy.engine import evaluate
from controlloop.policy.models import (
    DuplicateRuleIdError,
    EvaluationBounds,
    EvaluationResult,
    Rule,
    RuleContext,
    RuleObservation,
    RuleSafetyError,
    SanctionContext,
)
from controlloop.policy.rulepack import (
    CURRENT_RULE_PACK,
    KNOWN_RULE_PACK_FINGERPRINTS,
    RulePack,
    RulePackError,
    rule_pack_fingerprint,
)
from controlloop.policy.suppressions import (
    SuppressionOutcome,
    SuppressionRecord,
    SuppressionStatus,
    apply_suppressions,
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

__all__ = [
    "CURRENT_RULE_PACK",
    "KNOWN_RULE_PACK_FINGERPRINTS",
    "ActionSource",
    "CompletenessEnforcement",
    "DuplicateRuleIdError",
    "EvaluationBounds",
    "EvaluationResult",
    "GateStatus",
    "GateVerdict",
    "LowConfidenceAction",
    "PolicyConfig",
    "PolicyConfigError",
    "Rule",
    "RuleAction",
    "RuleContext",
    "RuleMetadata",
    "RuleObservation",
    "RulePack",
    "RulePackError",
    "RuleSafetyError",
    "SanctionContext",
    "SuppressionOutcome",
    "SuppressionRecord",
    "SuppressionStatus",
    "apply_suppressions",
    "evaluate",
    "evaluate_gate",
    "finding_action",
    "resolve_policy_config",
    "rule_pack_fingerprint",
    "severity_at_least",
    "severity_rank",
    "validate_disabled_rules",
]
