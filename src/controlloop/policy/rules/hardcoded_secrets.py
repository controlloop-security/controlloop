"""Rule: hardcoded secret material.

The design decisions, in short:

- **Where the content scanning happens.** `controlloop.policy.engine`
  structurally forbids a `Rule.evaluate` from touching the filesystem.
  Detecting a secret needs a scan of raw file content, which this rule
  therefore never does: `controlloop.secret_scan`
  (`scan_repository_for_secrets`, wired into
  `controlloop.bom.build_acbom_document`) does that reading once, during
  ACBOM construction, and records each detection as a `Diagnostic` on
  `ACBOMDocument.diagnostics` -- `SECRET-CREDENTIAL-SHAPE-DETECTED` for a
  known signature match, `SECRET-HIGH-ENTROPY-VALUE-DETECTED` for the
  heuristic tier -- carrying a pattern/heuristic name, a location, and a
  confidence, **never the matched value**. This rule's entire job is to
  read those two diagnostic codes back out of `context.acbom.diagnostics`
  (already-validated canonical evidence, exactly what a `Rule` is allowed
  to read) and promote each to a `RuleObservation`/`Finding` -- the same
  "surface an already-present diagnostic as a policy-level finding" shape
  `controlloop.policy.rules.unresolved_dynamic_registration` already
  established for a different diagnostic code.
- **Repository-scoped findings.** A hardcoded secret in a shared file has
  no natural single-agent attribution, so
  `Finding.affected_agent`/`capability_path` are optional
  (`controlloop.findings.models`). Every `Finding` this rule produces omits
  both -- it is repository-scoped by construction, never fabricating an
  agent attribution the underlying evidence does not support.
- **`change_state` is always `not-compared`.** Every other rule in this
  package derives `change_state` from `RuleContext.diff` via
  `controlloop.policy.rules._shared.node_change_state`, which requires a
  concrete node ID to look up in the diff. This rule has no node to
  attribute a finding to at all (repository-scoped, by design above), so
  that lookup is structurally unavailable here, not merely unimplemented
  -- `FindingChangeState.NOT_COMPARED` is used unconditionally, an
  honest statement that this rule does not yet participate in baseline
  comparison, rather than a fabricated `unknown`/`unchanged` guess.
- **Severity is derived from detection confidence**, this rule's own
  disclosed judgment call (not dictated by the finding's field list):
  `high` confidence -> `critical` severity, `medium` -> `high`, `low`
  -> `medium`. A hardcoded secret is treated as at least a
  high-severity concern even at reduced detection confidence, since
  the cost of a missed real credential is asymmetric with the cost of
  a lower-confidence false positive still being surfaced for human
  review.
"""

from __future__ import annotations

from controlloop.acbom.models import Confidence, Diagnostic
from controlloop.findings.models import (
    Finding,
    FindingChangeState,
    FindingSeverity,
    finding_from_observation,
)
from controlloop.policy.models import Rule, RuleContext, RuleObservation
from controlloop.policy.rules._shared import documentation_url
from controlloop.secret_scan import detection_kind

RULE_ID = "policy.hardcoded-secrets"
_RULE_VERSION = "1.0.0"
_DOCUMENTATION_URL = documentation_url(RULE_ID)

_SHAPE_CODE = "SECRET-CREDENTIAL-SHAPE-DETECTED"
_ENTROPY_CODE = "SECRET-HIGH-ENTROPY-VALUE-DETECTED"
_DETECTION_CODES = frozenset({_SHAPE_CODE, _ENTROPY_CODE})
_BOUND_EXCEEDED_CODE = "INCOMPLETE-BOUND-EXCEEDED"
_SECRET_SCAN_ADAPTER_NAME = "secret-scan"

_REMEDIATION = (
    "Remove the credential from source control, rotate it immediately, and "
    "load it at runtime from a secret manager or environment variable "
    "instead."
)

_SEVERITY_BY_CONFIDENCE: dict[Confidence, FindingSeverity] = {
    Confidence.HIGH: FindingSeverity.CRITICAL,
    Confidence.MEDIUM: FindingSeverity.HIGH,
    Confidence.LOW: FindingSeverity.MEDIUM,
    Confidence.UNKNOWN: FindingSeverity.MEDIUM,
}


def _detection_diagnostics(context: RuleContext) -> tuple[Diagnostic, ...]:
    """Every `controlloop.secret_scan` detection diagnostic already
    present in `context.acbom.diagnostics`, deterministically ordered
    by location regardless of the order adapters/passes ran in."""

    return tuple(
        sorted(
            (
                diagnostic
                for diagnostic in context.acbom.diagnostics
                if diagnostic.code in _DETECTION_CODES
            ),
            key=lambda diagnostic: (
                diagnostic.evidence[0].path or "",
                diagnostic.evidence[0].line_start or 0,
                diagnostic.code,
            ),
        )
    )


def _secret_scan_bound_exceeded(context: RuleContext) -> tuple[Diagnostic, ...]:
    """`controlloop.secret_scan`'s own `INCOMPLETE-BOUND-EXCEEDED`
    diagnostics, identified by their evidence's `adapter` name -- the
    same bound-exceeded code the rule engine and repository walker also
    mint, disambiguated here by source rather than assumed to belong to
    this pass."""

    return tuple(
        diagnostic
        for diagnostic in context.acbom.diagnostics
        if diagnostic.code == _BOUND_EXCEEDED_CODE
        and any(
            evidence.adapter == _SECRET_SCAN_ADAPTER_NAME
            for evidence in diagnostic.evidence
        )
    )


def _with_occurrences(
    diagnostics: tuple[Diagnostic, ...],
) -> tuple[tuple[Diagnostic, str], ...]:
    """Pair each detection with its identity occurrence: the credential
    kind plus its ordinal among detections of that kind in the same file,
    for example `aws-access-key-id#2`. `diagnostics` is already in
    location order, so the ordinal is stable while the file is unchanged
    above the detection, and two detections in one file never share a
    finding ID."""

    seen: dict[tuple[str, str], int] = {}
    paired: list[tuple[Diagnostic, str]] = []
    for diagnostic in diagnostics:
        kind = detection_kind(diagnostic) or diagnostic.code
        key = (diagnostic.evidence[0].path or "", kind)
        seen[key] = seen.get(key, 0) + 1
        paired.append((diagnostic, f"{kind}#{seen[key]}"))
    return tuple(paired)


def evaluate(context: RuleContext) -> tuple[RuleObservation, ...]:
    """Engine-compatible entry point: one `RuleObservation` per
    secret-shaped-content detection diagnostic already present in
    `context.acbom.diagnostics`, plus one advisory observation if
    `controlloop.secret_scan`'s own detection bound was exceeded
    (never silently dropped, per this codebase's "unknown, never
    omitted" invariant)."""

    observations = [
        RuleObservation(
            rule_id=RULE_ID, message=diagnostic.message, evidence=diagnostic.evidence
        )
        for diagnostic in _detection_diagnostics(context)
    ]

    bound_exceeded = _secret_scan_bound_exceeded(context)
    if bound_exceeded:
        observations.append(
            RuleObservation(
                rule_id=RULE_ID,
                message=(
                    "secret-shaped-content scanning stopped before covering "
                    "the entire repository; some hardcoded credentials may "
                    "not have been considered"
                ),
                evidence=bound_exceeded[0].evidence,
            )
        )

    return tuple(observations)


RULE = Rule(id=RULE_ID, evaluate=evaluate)


def findings(
    context: RuleContext,
    *,
    rule_version: str = _RULE_VERSION,
    documentation_url_value: str = _DOCUMENTATION_URL,
) -> tuple[Finding, ...]:
    """The `Finding`-producing counterpart to `evaluate()` (see this
    module's own docstring for why every finding here is repository-
    scoped, with no `affected_agent`/`capability_path`)."""

    results = [
        finding_from_observation(
            RuleObservation(
                rule_id=RULE_ID,
                message=diagnostic.message,
                evidence=diagnostic.evidence,
            ),
            rule_version=rule_version,
            severity=_SEVERITY_BY_CONFIDENCE[diagnostic.confidence],
            confidence=diagnostic.confidence,
            change_state=FindingChangeState.NOT_COMPARED,
            remediation=_REMEDIATION,
            documentation_url=documentation_url_value,
            identity_occurrence=occurrence,
        )
        for diagnostic, occurrence in _with_occurrences(_detection_diagnostics(context))
    ]

    return tuple(sorted(results, key=lambda finding: finding.id))


__all__ = [
    "RULE",
    "RULE_ID",
    "evaluate",
    "findings",
]
