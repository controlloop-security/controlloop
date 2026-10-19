---
type: reference
title: Severity, confidence, and thresholds
tags:
  - reference
  - policy
created: 2026-08-20
---

# Severity, confidence, and thresholds

**Status: Implemented and wired in.** The decision core and the four
`controlloop.toml` policy keys described below are implemented and tested
library code. Three (`severity_threshold`, `low_confidence_action`,
`disabled_rules`) are consumed by both real CLI commands: `scan` and
`gate`. The fourth (`completeness_enforcement`) is consumed by `gate`
only -- see the [CLI reference](cli.md#scan) / [CLI
reference](cli.md#gate).

## What this is

[`FindingSeverity`](finding-model.md#severity-a-minimal-disclosed-placeholder-scale-deliberate-disclosed)
 is a field shape only: five members in ascending order,
no ranking, no threshold. `controlloop.policy.thresholds`
is the deterministic decision core that turns a resolved configuration and a
tuple of already-built `Finding`s into a pass/fail verdict: which findings
block, which findings only warn, and the effective policy configuration and
its source.

## The model

```python
class LowConfidenceAction(StrEnum):    # controlloop.policy.thresholds
    BLOCK = "block"                    # default
    WARN = "warn"

class CompletenessEnforcement(StrEnum):  # controlloop.policy.thresholds
    WARN = "warn"                        # default
    ENFORCE = "enforce"

class GateStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"

class RuleMetadata:                    # a frozen dataclass
    id: str
    mandatory: bool

class PolicyConfig:                    # a frozen dataclass
    severity_threshold: FindingSeverity
    severity_threshold_source: ConfigSource
    low_confidence_action: LowConfidenceAction
    low_confidence_action_source: ConfigSource
    disabled_rule_ids: frozenset[str]
    disabled_rule_ids_source: ConfigSource
    completeness_enforcement: CompletenessEnforcement
    completeness_enforcement_source: ConfigSource

class PolicyConfigError(ValueError):   # exit_code = ExitCode.INVALID_INPUT

def resolve_policy_config(resolved: ResolvedConfig) -> PolicyConfig: ...
def validate_disabled_rules(policy_config: PolicyConfig, catalog: tuple[RuleMetadata, ...]) -> None: ...

class GateVerdict:                     # a frozen dataclass
    status: GateStatus
    blocking_findings: tuple[Finding, ...]
    warning_findings: tuple[Finding, ...]
    policy_config: PolicyConfig
    scanner_version: str                # added with rule pack versioning
    rule_pack_name: str                  # added with rule pack versioning
    rule_pack_version: str               # added with rule pack versioning
    rule_pack_fingerprint: str           # added with rule pack versioning

def evaluate_gate(
    findings: tuple[Finding, ...],
    policy_config: PolicyConfig,
    *,
    scanner_version: str,          # added with rule pack versioning
    rule_pack_name: str,           # added with rule pack versioning
    rule_pack_version: str,        # added with rule pack versioning
    rule_pack_fingerprint: str,    # added with rule pack versioning
) -> GateVerdict: ...

def severity_rank(severity: FindingSeverity) -> int: ...
def severity_at_least(severity: FindingSeverity, threshold: FindingSeverity) -> bool: ...
```

## Four `controlloop.toml` keys

Resolved through the identical four-tier precedence
[`controlloop.config`](configuration.md) already established (defaults <
repository file < environment < flags):

| Key | Allowed values | Default |
| --- | --- | --- |
| `severity_threshold` | `info`, `low`, `medium`, `high`, `critical` | `high` |
| `low_confidence_action` | `block`, `warn` | `block` |
| `disabled_rules` | array of rule-ID strings | (empty) |
| `completeness_enforcement` | `warn`, `enforce` | `warn` |

See [Configuration loading and precedence](configuration.md) for the full
loading mechanics, hard-error behavior, and `--show-config` output.

## Completeness enforcement

`completeness_enforcement` decides whether incomplete analysis alone can
produce `gate`'s `review_required`/exit-`3` outcome. Under the default
`CompletenessEnforcement.WARN`, incomplete analysis with no blocking
finding maps to the already-existing `Verdict.PASSED_WITH_WARNINGS` /
exit `0` instead -- the same "surfaced, never hidden, never blocking"
treatment a low-confidence finding already gets under
`low_confidence_action = warn` (a warning and exit 0 by default, so a
first run is never a wall). `CompletenessEnforcement.ENFORCE`
restores `Verdict.REVIEW_REQUIRED` / exit `3`. A blocking finding
always wins regardless of completeness or this setting -- unchanged
ordering.

This decision lives in `controlloop.cli`'s `_gate_classify`, not in
`evaluate_gate` itself: `analysis_incomplete` is computed from
`controlloop.acbom.completeness.completeness_summary` and
`EvaluationResult.is_incomplete`, neither of which `evaluate_gate` reads
today, so `_gate_classify` is the one place both a `GateVerdict` and the
completeness state are already in scope together. `completeness_enforcement`
never changes *which* diagnostics are reported: `completeness_summary`'s
own computation, and therefore `EvidenceArtifact.completeness`, is
identical regardless of the setting -- only the verdict/exit-code mapping
changes. The resolved setting itself is stated on every `EvidenceArtifact`
(`completeness_enforcement`/`completeness_enforcement_source`) -- see [Evidence artifact format](evidence-artifact-format.md).

**Disclosed scope boundary:** `gate` alone consumes this key. `scan`'s
own inline verdict/exit-code classification is deliberately separate
code from `_gate_classify` and keeps its prior, unconditional
incomplete-analysis-always-exit-3 behavior unchanged; extending `scan`
to the identical toggle was deliberately left out.

## Why `high`/`block` (deliberate, disclosed, overridable)

Neither default is an approved business SLA or pricing-adjacent
threshold, and none was invented. Both follow the exact precedent
`controlloop.policy.models.EvaluationBounds` already established for
this codebase: a "generous, disclosed starting point," not a business
decision, overridable by any repository at any time.
`severity_threshold = "high"` (block only `high`/`critical`) was chosen
before any rule was registered, and a low false-positive burden counsels
starting conservative. `low_confidence_action = "block"` reads "can be
configured to warn rather than block" as an opt-in override of an
implicit baseline (an ordinary finding, confidence notwithstanding), not
the baseline itself.

## `RuleMetadata`/`mandatory`: a new, separate concept from `Rule` (deliberate, disclosed)

`controlloop.policy.models.Rule` pairs an `id` with an *execution*
callable. "Mandatory" is a *policy-governance* fact about a rule,
orthogonal to execution. `RuleMetadata` is deliberately a separate,
minimal dataclass rather than a widening of `Rule`, so `Rule`'s
already-shipped shape does not change for a concern it never claimed.
The real catalog is `CURRENT_RULE_PACK.metadata` (see [Rule pack
versioning](rule-pack-versioning.md)); tests also exercise
`validate_disabled_rules` with a synthetic `tuple[RuleMetadata, ...]`.

## Enforcement

`validate_disabled_rules(policy_config, catalog)` raises `PolicyConfigError`
(`exit_code = ExitCode.INVALID_INPUT`, exit `2` once a caller translates it)
naming the offending rule ID when `disabled_rule_ids` names a rule the
catalog marks `mandatory=True`, or a rule ID the catalog does not recognize
at all -- a repository cannot disable a rule it never declared. Call this
once per resolved policy, before any rule executes.
`evaluate_gate` also drops any finding whose `rule_id` is in
`disabled_rule_ids` before classifying the rest, a disclosed defense-in-depth
safety net; `validate_disabled_rules` is the primary enforcement point.

## Low-confidence handling

A finding is "low-confidence" when its `confidence` is `Confidence.LOW` or
`Confidence.UNKNOWN`; `Confidence.HIGH`/`.MEDIUM` are never downgraded
regardless of `low_confidence_action`. When `low_confidence_action` is
`warn` and a low-confidence finding meets the severity threshold, it is
placed in `warning_findings` -- surfaced, never hidden -- instead of
`blocking_findings`, and does not affect `GateStatus`. Under the `block`
default, a low-confidence finding is treated identically to any other
finding.

A finding below the severity threshold appears in neither list, regardless
of confidence -- `GateVerdict` is a gate decision, not a findings report; a
full report listing every finding regardless of disposition is a
separate concern.

## Determinism and the effective configuration

`GateStatus.FAIL` exactly when `blocking_findings` is non-empty.
`blocking_findings`/`warning_findings` are both sorted by `Finding.id`
before being returned, independent of input order. `GateVerdict.policy_config`
carries every resolved value **and** which of the four precedence tiers
supplied it -- the same `ConfigSource` enum
[`configuration.md`](configuration.md) already documents.

## Privacy and offline

`controlloop.policy.thresholds` only classifies already-sanitized
`Finding`/`ConfigValue` data a caller passes in; it never reads a file or
reaches the network. Proven by the same `ast`-based structural check
`tests/test_redaction.py` already established for
`controlloop.findings.*` (`test_policy_thresholds_module_never_reads_raw_content`),
and covered by `tests/conftest.py`'s autouse offline harness like every
other test under `tests/`.

## Known limitations

- **Both real CLI commands consume this now.** `scan` and
  `gate` both call `evaluate_gate` (see the [CLI
  reference](cli.md)). `PolicyConfigError.exit_code` translates directly
  into both commands' documented exit-2 contract, mirroring
  `controlloop.config.ConfigError`'s already-established relationship to
  `--show-config`.
- A rule pack, rule-pack version, and CI-enforced version-bump check
  now exist -- see [Rule pack versioning](rule-pack-versioning.md),
  which also added `GateVerdict.scanner_version`/`rule_pack_name`/
  `rule_pack_version`/`rule_pack_fingerprint` and the matching four
  required keyword arguments on `evaluate_gate`, shown above.
- Concrete rules exist in `controlloop.policy.rules.ALL_RULES` (see
  [Concrete policy rules](policy-rules.md)). Expiring repo-local
  suppressions are implemented, but are a suppression mechanism applied
  before this classification, not a registered rule -- see [Expiring
  repo-local suppressions](suppressions.md). `CURRENT_RULE_PACK`
  carries every rule with a decided `RuleMetadata.mandatory` flag per
  rule -- see [Rule pack versioning](rule-pack-versioning.md).
- No CLI flag exists yet for any of the four configuration keys; they are
  set through `controlloop.toml` and their environment variables only.
- `completeness_enforcement` is consumed by `gate`
  only. `scan`'s own separate inline classification keeps its prior,
  unconditional incomplete-analysis behavior -- a disclosed asymmetry
  between the two commands, not an oversight; see "Completeness
  enforcement" above.
- `GateVerdict` remains a plain, not-independently-serialized dataclass.
  `gate` does not serialize `GateVerdict` itself -- it reads
  `blocking_findings`/`warning_findings` to compute its own four-word
  verdict, then serializes the separate, already-approved
  `EvidenceArtifact` instead. See [Evidence artifact
  format](evidence-artifact-format.md) and [CLI reference](cli.md#gate).

## Next steps

- Review [Finding model](finding-model.md) for `Finding` and
  `FindingSeverity`, the types this module classifies.
- Review [Configuration loading and precedence](configuration.md) for the
  four-tier mechanism these four keys resolve through.
- Review [Deterministic rule engine](rule-engine.md) for
  `controlloop.policy.models.Rule`, the execution concept `RuleMetadata`
  deliberately does not extend.
- Review [Rule pack versioning](rule-pack-versioning.md) for `RulePack`,
  which pairs `Rule` and `RuleMetadata` into a versioned, fingerprinted
  collection, and for the scanner/rule-pack identity fields it added to
  `GateVerdict`.
- Review the [CLI reference](cli.md) for what is available today.
