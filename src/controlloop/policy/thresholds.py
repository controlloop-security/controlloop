"""Severity, confidence, and threshold policy.

`controlloop.findings.models.FindingSeverity` is a field shape only: five
members in ascending declared order, no ranking function, no comparison
operator, no configurable gate threshold. This module supplies the rest:
the deterministic decision core that turns a resolved `severity_threshold`,
a resolved `low_confidence_action`, a resolved `disabled_rules` set, and a
tuple of already-built `Finding`s into a `GateVerdict` -- pass or fail, which
findings blocked, which findings only warned, and the effective policy
configuration and its source.

`PolicyConfigError.exit_code = ExitCode.INVALID_INPUT` translates directly
into a process exit, mirroring `controlloop.config.ConfigError`'s
established shape exactly -- the same relationship `ConfigError` has to
`controlloop --show-config`.

`RuleMetadata`/`mandatory` is a separate concept rather than a widening
of `controlloop.policy.models.Rule`: whether a rule may be disabled is a
policy-governance fact about a rule, orthogonal to the engine's
execution concerns. `severity_threshold` defaults to `"high"` and
`low_confidence_action` defaults to `"block"` (disclosed, overridable
engineering defaults -- not an approved business threshold, the same
precedent `controlloop.policy.models.EvaluationBounds` already
established for this codebase).

On a Team gate an organization rule may also carry an `action`
(`RuleAction`), and for a finding from such a rule the action, not the
severity threshold, decides the verdict. A rule without one keeps the
threshold behaviour, and a Community gate never has any.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from controlloop.acbom.models import Confidence
from controlloop.config import ConfigSource, ResolvedConfig
from controlloop.exit_codes import ExitCode

if TYPE_CHECKING:
    # Deferred to a `TYPE_CHECKING`-only import, not a module-level one:
    # `controlloop.findings.models` itself imports
    # `controlloop.policy.models.RuleObservation`, and importing any
    # submodule of the `controlloop.policy` package first runs
    # `controlloop/policy/__init__.py`, which imports this module -- a
    # module-level import of `controlloop.findings.models` here would be
    # circular. `resolve_policy_config` below imports `FindingSeverity` at
    # call time instead, the same deferred-import pattern
    # `controlloop.findings.models.finding_from_observation` already
    # established for the identical reason (see that function's own
    # docstring).
    from controlloop.findings.models import Finding, FindingSeverity

#: `FindingSeverity`'s own declared member order is already ascending
#: (`INFO < LOW < MEDIUM < HIGH < CRITICAL`); this table mirrors that
#: declaration order as the ranking. Deliberately a local literal tuple of
#: raw strings, not `tuple(FindingSeverity)` computed at module-import
#: time -- see this module's own `TYPE_CHECKING` import block above: a
#: module-level runtime reference to `controlloop.findings.models` here
#: would reintroduce the same circular-import hazard
#: `resolve_policy_config`'s deferred import avoids elsewhere in this
#: module. This still works transparently for a real `FindingSeverity`
#: value: `FindingSeverity` is itself a `StrEnum`, so
#: `FindingSeverity.HIGH == "high"` and
#: `hash(FindingSeverity.HIGH) == hash("high")`, and a `FindingSeverity`
#: member passed to `severity_rank` looks itself up correctly in this
#: string-keyed table. Guarded against drift by
#: `tests/policy/test_policy_thresholds.py`'s
#: `test_severity_order_is_the_five_declared_members_ascending`, which
#: compares this table's order against the real `FindingSeverity` values.
_SEVERITY_ORDER: tuple[str, ...] = ("info", "low", "medium", "high", "critical")
_SEVERITY_RANK: dict[str, int] = {
    severity: rank for rank, severity in enumerate(_SEVERITY_ORDER)
}

#: A finding's `confidence` values this module treats as "low confidence"
#: for the downgrade-to-warn behavior. `Confidence.HIGH`/`.MEDIUM` are
#: never downgraded regardless of `low_confidence_action`.
_LOW_CONFIDENCE_VALUES: frozenset[Confidence] = frozenset(
    {Confidence.LOW, Confidence.UNKNOWN}
)


def severity_rank(severity: FindingSeverity) -> int:
    """Return `severity`'s position in the ascending severity order (`0`
    for `INFO` through `4` for `CRITICAL`). A pure lookup; never raises for
    any real `FindingSeverity` member."""

    return _SEVERITY_RANK[severity]


def severity_at_least(severity: FindingSeverity, threshold: FindingSeverity) -> bool:
    """`True` when `severity` is at or above `threshold` in the ascending
    severity order. Reflexive: `severity_at_least(x, x)` is always
    `True` -- a finding exactly at the configured threshold blocks."""

    return severity_rank(severity) >= severity_rank(threshold)


class LowConfidenceAction(StrEnum):
    """How `evaluate_gate` treats a low-confidence finding that otherwise
    meets the severity threshold."""

    #: Treat a low-confidence finding identically to any other finding
    #: (default -- see the module docstring for why this, not `WARN`, is
    #: the baseline).
    BLOCK = "block"
    #: Surface a low-confidence finding as a warning, never a block, and
    #: never drop it silently ("without being hidden").
    WARN = "warn"


class CompletenessEnforcement(StrEnum):
    """Whether incomplete analysis blocks a `gate` verdict. This module
    does not itself decide *which* verdict or exit code an incomplete
    analysis produces -- that mapping is `controlloop.cli`'s
    `_gate_classify` -- it only carries the resolved setting, the same
    "decision core exposes the fact; the command applies it" split
    `severity_threshold`/`low_confidence_action` already establish."""

    #: Incomplete analysis alone never blocks (default -- "a warning and
    #: exit 0 by default," so a first run is never a wall).
    WARN = "warn"
    #: A repository has opted in: incomplete analysis alone blocks.
    ENFORCE = "enforce"


class RuleAction(StrEnum):
    """What an organization rule's finding does to a Team gate verdict.

    Set per rule in the organization's policy and merged strengthen-only
    (`controlloop.team.policy`). It decides the verdict whatever the
    finding's severity or confidence: a repository setting such as
    `low_confidence_action` cannot soften what the organization requires.
    """

    #: Blocks: `deployment_blocked`, exit `1`.
    FAIL = "fail"
    #: `review_required`, exit `3`, unless something else blocks.
    REQUIRE_REVIEW = "require_review"
    #: Reported as a warning; never blocks.
    WARN = "warn"
    #: Reported; never affects the verdict.
    PASS = "pass"

    @classmethod
    def parse(cls, value: str) -> RuleAction:
        """The action `value` names, or `FAIL` for one this CLI does not
        know. A newer platform's action must not switch a gate off, and
        `FAIL` is the one reading that cannot."""

        try:
            return cls(value)
        except ValueError:
            return cls.FAIL


class ActionSource(StrEnum):
    """Where a finding's effective action came from."""

    #: The rule's organization `action`.
    ORGANIZATION = "organization"
    #: No organization action: derived from the finding's severity against
    #: `severity_threshold` and from `low_confidence_action`.
    SEVERITY_THRESHOLD = "severity_threshold"


class GateStatus(StrEnum):
    """The overall pass/fail decision `evaluate_gate` returns."""

    PASS = "pass"
    FAIL = "fail"


@dataclass(frozen=True, slots=True)
class RuleMetadata:
    """One rule's policy-governance metadata: whether a repository is
    permitted to disable it. Deliberately separate from
    `controlloop.policy.models.Rule` -- see the module docstring. A rule
    pack (`controlloop.policy.rulepack`) supplies its rules as a
    `tuple[RuleMetadata, ...]`."""

    id: str
    mandatory: bool
    summary: str = ""
    """One line naming what this rule actually detects, for
    `controlloop rules`.

    Descriptive only. It is deliberately **not** an input to
    `controlloop.policy.rulepack.rule_pack_fingerprint`, which digests
    `[rule.id, sha256(evaluate source), mandatory]` -- so adding or
    editing a summary never changes a pinned fingerprint and never
    implies a rule-pack version bump.
    `test_summaries_do_not_change_the_pinned_fingerprint` proves it.

    Defaults to `""` so an externally constructed `RuleMetadata` stays
    valid; `CURRENT_RULE_PACK` populates it for every shipped rule, and
    `test_every_shipped_rule_has_a_summary` fails if one is missed.
    """


class PolicyConfigError(ValueError):
    """A policy configuration is invalid: naming, currently, only
    an attempt to disable a mandatory rule or an attempt to disable a rule
    ID absent from the supplied catalog. Carries
    `exit_code = ExitCode.INVALID_INPUT`, mirroring
    `controlloop.config.ConfigError`'s established shape exactly, so the
    `gate` command can translate either error type into the exit-2
    contract the same way. The message names only the offending rule ID --
    a code-level identifier a repository itself supplied in its own
    configuration, never raw file content or a secret value."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.exit_code = ExitCode.INVALID_INPUT


@dataclass(frozen=True, slots=True)
class PolicyConfig:
    """The effective severity/confidence/threshold policy and, for every
    field, which of the four `controlloop.config` precedence tiers supplied
    it ("the effective policy configuration and its source are
    reported in every gate result")."""

    severity_threshold: FindingSeverity
    severity_threshold_source: ConfigSource
    low_confidence_action: LowConfidenceAction
    low_confidence_action_source: ConfigSource
    disabled_rule_ids: frozenset[str]
    disabled_rule_ids_source: ConfigSource
    #: "The active setting is stated in the gate result" -- carried on
    #: `PolicyConfig` exactly like the three fields above, so every
    #: existing consumer of a resolved policy (a future
    #: `EvidenceArtifact`/report, `--show-config`-style rendering)
    #: reaches it the same way.
    completeness_enforcement: CompletenessEnforcement
    completeness_enforcement_source: ConfigSource


def resolve_policy_config(resolved: ResolvedConfig) -> PolicyConfig:
    """Build a `PolicyConfig` from an already-loaded
    `controlloop.config.ResolvedConfig`. Converts `resolved`'s already
    shape-and-membership-validated raw strings into the real
    `FindingSeverity`/`LowConfidenceAction`/`CompletenessEnforcement` enum
    members -- the one place that conversion happens; see this module's
    own docstring and `controlloop.config`'s docstring for why
    `controlloop.config` itself stays a dependency-light leaf that never
    imports any of the three."""

    # Imported here, not at module level -- see this module's own
    # `TYPE_CHECKING` import block above for why.
    from controlloop.findings.models import FindingSeverity

    return PolicyConfig(
        severity_threshold=FindingSeverity(resolved.severity_threshold_value()),
        severity_threshold_source=resolved["severity_threshold"].source,
        low_confidence_action=LowConfidenceAction(
            resolved.low_confidence_action_value()
        ),
        low_confidence_action_source=resolved["low_confidence_action"].source,
        disabled_rule_ids=resolved.disabled_rule_ids(),
        disabled_rule_ids_source=resolved["disabled_rules"].source,
        completeness_enforcement=CompletenessEnforcement(
            resolved.completeness_enforcement_value()
        ),
        completeness_enforcement_source=resolved["completeness_enforcement"].source,
    )


def validate_disabled_rules(
    policy_config: PolicyConfig, catalog: tuple[RuleMetadata, ...]
) -> None:
    """Reject a `PolicyConfig` whose `disabled_rule_ids` names a mandatory
    rule or a rule ID absent from `catalog` -- a repository
    cannot disable a rule it never declared, and no defensive purpose is
    served by silently ignoring a typo in a security-relevant configuration
    key. Raises `PolicyConfigError` naming the first such rule ID in sorted
    order (deterministic regardless of `disabled_rule_ids`'s unordered
    iteration), never a partial or silent acceptance. Call this once per
    resolved policy, before any rule in `catalog` executes."""

    known = {rule.id: rule for rule in catalog}
    for rule_id in sorted(policy_config.disabled_rule_ids):
        if rule_id not in known:
            raise PolicyConfigError(f"cannot disable unknown rule '{rule_id}'")
        if known[rule_id].mandatory:
            raise PolicyConfigError(f"cannot disable mandatory rule '{rule_id}'")


@dataclass(frozen=True, slots=True)
class GateVerdict:
    """The complete result of one `evaluate_gate` call: the overall
    `status`, which findings blocked it, which findings only warned, the
    `PolicyConfig` (with source) that produced this verdict, and the
    scanner version and rule pack identity that produced it.
    `blocking_findings` and `warning_findings` are both sorted by
    `Finding.id` for determinism, independent of the order `findings`
    was supplied in.

    `scanner_version`/`rule_pack_name`/`rule_pack_version`/
    `rule_pack_fingerprint` are an additive amendment to this type; every
    threshold guarantee it already made is unchanged.

    `review_findings` holds findings whose organization action is
    `require_review`. It never changes `status`; the command maps it to
    `review_required`.
    """

    status: GateStatus
    blocking_findings: tuple[Finding, ...]
    warning_findings: tuple[Finding, ...]
    policy_config: PolicyConfig
    scanner_version: str
    rule_pack_name: str
    rule_pack_version: str
    rule_pack_fingerprint: str
    review_findings: tuple[Finding, ...] = ()


def finding_action(
    finding: Finding,
    policy_config: PolicyConfig,
    rule_actions: Mapping[str, str] | None = None,
) -> tuple[RuleAction, ActionSource]:
    """The action `evaluate_gate` takes on `finding`, and where it came
    from. Ignores `disabled_rule_ids`; `evaluate_gate` drops those first.

    Without an organization action the threshold behaviour reads as an
    action too: a finding that blocks is `FAIL`, one that only warns is
    `WARN`, and one below the threshold is `PASS`.
    """

    action = (rule_actions or {}).get(finding.rule_id)
    if action is not None:
        return RuleAction.parse(action), ActionSource.ORGANIZATION
    if not severity_at_least(finding.severity, policy_config.severity_threshold):
        return RuleAction.PASS, ActionSource.SEVERITY_THRESHOLD
    is_low_confidence = finding.confidence in _LOW_CONFIDENCE_VALUES
    if is_low_confidence and policy_config.low_confidence_action is (
        LowConfidenceAction.WARN
    ):
        return RuleAction.WARN, ActionSource.SEVERITY_THRESHOLD
    return RuleAction.FAIL, ActionSource.SEVERITY_THRESHOLD


def evaluate_gate(
    findings: tuple[Finding, ...],
    policy_config: PolicyConfig,
    *,
    scanner_version: str,
    rule_pack_name: str,
    rule_pack_version: str,
    rule_pack_fingerprint: str,
    rule_actions: Mapping[str, str] | None = None,
) -> GateVerdict:
    """Classify every finding in `findings` against `policy_config` and
    return the resulting `GateVerdict`.

    `scanner_version`, `rule_pack_name`, `rule_pack_version`, and
    `rule_pack_fingerprint` are plain, already-computed strings, not a
    `controlloop.policy.rulepack.RulePack` object --
    `controlloop.policy.thresholds` never imports
    `controlloop.policy.rulepack`, only the reverse, to avoid a circular
    import. A caller building a real gate result passes
    `scanner_version=controlloop.__version__`,
    `rule_pack_name=CURRENT_RULE_PACK.name`,
    `rule_pack_version=CURRENT_RULE_PACK.version`,
    `rule_pack_fingerprint=rule_pack_fingerprint(CURRENT_RULE_PACK)`.
    This function does not validate any of the four -- they are recorded
    on the returned `GateVerdict` unchanged ("a result records both
    scanner version and rule pack version").

    A finding whose `rule_id` is in `policy_config.disabled_rule_ids` is
    dropped entirely before classification -- a disclosed defense-in-depth
    safety net; the primary enforcement point for mandatory and unknown
    rules is
    `validate_disabled_rules`, run once at policy-resolution time, before
    any rule executes at all.

    A finding is "low-confidence" when its `confidence` is
    `Confidence.LOW` or `Confidence.UNKNOWN`. When
    `policy_config.low_confidence_action` is `WARN` and a low-confidence
    finding meets the severity threshold, it is placed in
    `warning_findings` (surfaced, never hidden) rather than
    `blocking_findings`, and does not affect `GateStatus`. Every other
    finding meeting the threshold (including a low-confidence one when
    `low_confidence_action` is `BLOCK`, the default) is placed in
    `blocking_findings`. A finding below the threshold, regardless of
    confidence, appears in neither list -- this is a gate verdict, not a
    findings report; a full report listing every finding regardless of
    disposition is separate, not-yet-implemented, later scope.

    `rule_actions` maps a rule ID to its organization action (a Team
    gate's effective policy). A finding from such a rule is classified by
    `RuleAction` alone, whatever its severity and confidence: `FAIL` into
    `blocking_findings`, `REQUIRE_REVIEW` into `review_findings`, `WARN`
    into `warning_findings`, `PASS` into none. See `finding_action`.

    `GateStatus.FAIL` exactly when `blocking_findings` is non-empty.
    """

    blocking: list[Finding] = []
    review: list[Finding] = []
    warning: list[Finding] = []
    by_action = {
        RuleAction.FAIL: blocking,
        RuleAction.REQUIRE_REVIEW: review,
        RuleAction.WARN: warning,
    }

    for finding in findings:
        if finding.rule_id in policy_config.disabled_rule_ids:
            continue
        action, _ = finding_action(finding, policy_config, rule_actions)
        if action is not RuleAction.PASS:
            by_action[action].append(finding)

    blocking.sort(key=lambda finding: finding.id)
    review.sort(key=lambda finding: finding.id)
    warning.sort(key=lambda finding: finding.id)

    status = GateStatus.FAIL if blocking else GateStatus.PASS
    return GateVerdict(
        status=status,
        blocking_findings=tuple(blocking),
        warning_findings=tuple(warning),
        policy_config=policy_config,
        scanner_version=scanner_version,
        rule_pack_name=rule_pack_name,
        rule_pack_version=rule_pack_version,
        rule_pack_fingerprint=rule_pack_fingerprint,
        review_findings=tuple(review),
    )
