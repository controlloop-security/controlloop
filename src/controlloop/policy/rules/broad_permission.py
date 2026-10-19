"""Rule: broad or wildcard permission.

Wildcard and overly broad permission grants are reported with the breadth
they actually confer, whether discovered via IAM, MCP, or OpenAPI.

## A generic canonical-model rule, not an IAM-specific one

This rule only ever reads `NodeType.PERMISSION` nodes'
`SecurityAttributes.permission_scopes` -- nothing IAM-specific. It happens
that only `controlloop.adapters.iam` currently populates that
field with the exact tokens this rule looks for, but this rule has no
adapter-name branch and no IAM-specific import.

## The `WILDCARD` token and the `condition:present` marker (disclosed
duplication)

`controlloop.adapters.iam._encode_scope` replaces a literal `*` with the
token `WILDCARD` inside a scope string (`SecurityAttributes.permission_scopes`
is `SafeIdentifier`-typed and cannot hold a literal `*`), and appends the
private literal `"condition:present"` when a statement carries an
unevaluated `Condition` block -- both confirmed by reading `iam.py` in
full. Both are private, adapter-internal constants, not a published
canonical vocabulary. This rule duplicates the two literal checks rather
than importing anything from `controlloop.adapters.iam`, matching this
codebase's own accepted precedent for this kind of duplication
(`controlloop.capability.compute`'s own docstring on `_TRANSITIVE_EDGE_TYPES`:
"each module stays self-contained"). If this vocabulary ever changes in
`iam.py`, this rule's detection silently stops matching it -- a real,
disclosed coupling risk; promoting these two tokens to a shared, public
constant is recommended follow-up.

## Unattributed broad permissions are not silently dropped

A `Permission` node discovered with no agent yet connected to it (a
realistic state for IAM discovery before an identity chain links it to a
specific agent) is reported as an advisory `RuleObservation` via
`evaluate()`, naming the permission and its breadth, but never promoted to
a `Finding` through `findings()` -- `Finding.affected_agent` has no honest
value to hold for it. The same "unknown, never omitted" posture the
undeclared-tools rule's no-manifest case already established.
"""

from __future__ import annotations

from dataclasses import dataclass

from controlloop.acbom.models import Confidence, EvidenceCollection, NodeType
from controlloop.capability.compute import (
    compute_direct_capability_paths,
    compute_transitive_capability_paths,
)
from controlloop.capability.models import CapabilityPath
from controlloop.findings.models import (
    Finding,
    FindingChangeState,
    FindingSeverity,
    finding_from_observation,
)
from controlloop.policy.models import Rule, RuleContext, RuleObservation
from controlloop.policy.rules._shared import documentation_url

RULE_ID = "policy.broad-permission"
RULE_VERSION = "1.0.0"

_DOCUMENTATION_URL = documentation_url(RULE_ID)

#: Substring token `controlloop.adapters.iam._encode_scope` uses in place
#: of a literal `*` -- see this module's own docstring for why this is a
#: disclosed duplication, not a shared canonical constant.
_WILDCARD_TOKEN = "WILDCARD"
#: Exact-member literal `controlloop.adapters.iam._CONDITION_MARKER` uses.
_CONDITION_MARKER = "condition:present"

_WILDCARD_SEVERITY = FindingSeverity.HIGH
_WILDCARD_CONFIDENCE = Confidence.HIGH
_CONDITION_ONLY_SEVERITY = FindingSeverity.MEDIUM
_CONDITION_ONLY_CONFIDENCE = Confidence.MEDIUM

_WILDCARD_REMEDIATION = (
    "Narrow this grant to explicit, minimal actions and resources instead "
    "of a wildcard."
)
_CONDITION_ONLY_REMEDIATION = (
    "Review whether the attached condition genuinely narrows this grant; "
    "document or tighten it so the actual breadth is explicit."
)


@dataclass(frozen=True, slots=True)
class _Breadth:
    """What made one `Permission` node's grant broad, and how certain
    that is."""

    wildcard_scopes: tuple[str, ...]
    has_unevaluated_condition: bool
    severity: FindingSeverity
    confidence: Confidence
    remediation: str

    def message(self, permission_name: str) -> str:
        if self.wildcard_scopes:
            scopes = ", ".join(sorted(self.wildcard_scopes))
            base = (
                f"Permission '{permission_name}' grants a wildcard scope "
                f"({scopes}), which in the worst case permits any action "
                "or resource matching that pattern."
            )
            if self.has_unevaluated_condition:
                base += (
                    " It is also restricted by a condition this scan did not evaluate."
                )
            return base
        return (
            f"Permission '{permission_name}' is restricted only by a "
            "condition this scan did not evaluate; it is reported as "
            "potentially broad since the actual breadth depends on that "
            "condition."
        )


def _breadth(permission_scopes: tuple[str, ...]) -> _Breadth | None:
    wildcard_scopes = tuple(
        scope for scope in permission_scopes if _WILDCARD_TOKEN in scope
    )
    has_condition = _CONDITION_MARKER in permission_scopes

    if wildcard_scopes:
        return _Breadth(
            wildcard_scopes=wildcard_scopes,
            has_unevaluated_condition=has_condition,
            severity=_WILDCARD_SEVERITY,
            confidence=_WILDCARD_CONFIDENCE,
            remediation=_WILDCARD_REMEDIATION,
        )
    if has_condition:
        return _Breadth(
            wildcard_scopes=(),
            has_unevaluated_condition=True,
            severity=_CONDITION_ONLY_SEVERITY,
            confidence=_CONDITION_ONLY_CONFIDENCE,
            remediation=_CONDITION_ONLY_REMEDIATION,
        )
    return None


@dataclass(frozen=True, slots=True)
class _Detection:
    """One broad permission grant reachable by a specific agent --
    everything `evaluate()` and `findings()` both need."""

    message: str
    evidence: EvidenceCollection
    affected_agent: str
    capability_path: CapabilityPath
    severity: FindingSeverity
    confidence: Confidence
    remediation: str


@dataclass(frozen=True, slots=True)
class _UnattributedBreadth:
    """One broad `Permission` node no path in the current graph reaches
    from any agent -- reported only as an advisory `RuleObservation`."""

    message: str
    evidence: EvidenceCollection


def _permission_paths(context: RuleContext) -> dict[str, list[CapabilityPath]]:
    nodes = context.acbom.nodes
    edges = context.acbom.edges
    direct = compute_direct_capability_paths(nodes, edges)
    transitive, _incomplete = compute_transitive_capability_paths(nodes, edges)

    by_target: dict[str, list[CapabilityPath]] = {}
    for path in (*direct, *transitive):
        if path.target_type is NodeType.PERMISSION:
            by_target.setdefault(path.target_id, []).append(path)
    return by_target


def _detect(
    context: RuleContext,
) -> tuple[tuple[_Detection, ...], tuple[_UnattributedBreadth, ...]]:
    permission_nodes = [
        node for node in context.acbom.nodes if node.type is NodeType.PERMISSION
    ]
    paths_by_target = _permission_paths(context)

    attributed: list[_Detection] = []
    unattributed: list[_UnattributedBreadth] = []

    for node in permission_nodes:
        breadth = _breadth(node.security_attributes.permission_scopes)
        if breadth is None:
            continue

        reaching_paths = paths_by_target.get(node.id, [])
        if not reaching_paths:
            unattributed.append(
                _UnattributedBreadth(
                    message=breadth.message(node.name), evidence=node.evidence
                )
            )
            continue

        for path in reaching_paths:
            attributed.append(
                _Detection(
                    message=breadth.message(node.name),
                    evidence=node.evidence,
                    affected_agent=path.agent_id,
                    capability_path=path,
                    severity=breadth.severity,
                    confidence=breadth.confidence,
                    remediation=breadth.remediation,
                )
            )

    return tuple(attributed), tuple(unattributed)


def evaluate(context: RuleContext) -> tuple[RuleObservation, ...]:
    """Engine-compatible entry point: `Rule.evaluate`'s fixed signature."""

    attributed, unattributed = _detect(context)
    observations = [
        RuleObservation(
            rule_id=RULE_ID, message=detection.message, evidence=detection.evidence
        )
        for detection in attributed
    ]
    observations.extend(
        RuleObservation(rule_id=RULE_ID, message=item.message, evidence=item.evidence)
        for item in unattributed
    )
    return tuple(observations)


def findings(context: RuleContext) -> tuple[Finding, ...]:
    """A disclosed convenience bridge -- see
    `src/controlloop/policy/rules/__init__.py`'s docstring. Only
    attributed detections are ever promoted; see this module's own
    docstring for why an unattributed broad permission is not."""

    attributed, _unattributed = _detect(context)
    return tuple(
        finding_from_observation(
            RuleObservation(
                rule_id=RULE_ID,
                message=detection.message,
                evidence=detection.evidence,
            ),
            rule_version=RULE_VERSION,
            severity=detection.severity,
            confidence=detection.confidence,
            affected_agent=detection.affected_agent,
            capability_path=detection.capability_path,
            change_state=FindingChangeState.NOT_COMPARED,
            remediation=detection.remediation,
            documentation_url=_DOCUMENTATION_URL,
        )
        for detection in attributed
    )


RULE = Rule(id=RULE_ID, evaluate=evaluate)
