"""Rule: sensitive write without declared approval.

A write to a resource carrying a sensitive data class, with no
corresponding approval in the manifest, is reported. An approval that has
expired does not suppress the finding.

## Two real sources

A resource is sensitive when *either* source says so: the manifest's
`ManifestDocument.data_classification` (`DataClassificationDeclaration`,
matched by resource name, only `confidential`/`restricted` count) or the
resource node's own adapter-supplied
`SecurityAttributes.sensitivity`/`.data_classifications`, read through
`controlloop.capability.taxonomy.classify_material_capability`'s
`SENSITIVE_DATA_ACCESS` class -- the same taxonomy every other rule in
this package reuses rather than a second, parallel judgment.

## "Declared approval" reuses the undeclared-tools rule's convention

A write is suppressed when `Approval.capability` in
`context.manifest.approvals` matches the written resource's `Node.name` --
the same reading the undeclared-tools rule already established for
"declared tools," reused here for one consistent pattern.

## Expiry is never evaluated inside this rule

`controlloop.manifest.approvals.active_approvals` exists precisely so
this rule never has to read a clock -- see that module's own docstring
for the full rationale (the engine's documented determinism guarantee,
and avoiding a `RuleContext` extension). This rule only ever inspects
whatever `context.manifest.approvals` it is given; whether an expired
approval has already been filtered out is entirely the caller's
responsibility.

## Direct writes only

This rule considers a direct `writes` edge from an agent to a resource
only -- the same "smallest coherent behavior" scoping the
destructive-or-financial-action rule applied to its own direct case, and
a disclosed limitation: a sensitive write reached only transitively (an
agent invokes a tool that itself writes the resource) is not detected by
this rule.
"""

from __future__ import annotations

from dataclasses import dataclass

from controlloop.acbom.models import (
    Confidence,
    EdgeType,
    EvidenceCollection,
    NodeType,
    SecurityAttributes,
    Sensitivity,
)
from controlloop.capability.models import CapabilityPath, PathHop
from controlloop.capability.taxonomy import (
    MaterialCapabilityClass,
    classify_material_capability,
)
from controlloop.findings.models import (
    Finding,
    FindingChangeState,
    FindingSeverity,
    finding_from_observation,
)
from controlloop.policy.models import Rule, RuleContext, RuleObservation
from controlloop.policy.rules._shared import documentation_url

RULE_ID = "policy.sensitive-write-without-approval"
RULE_VERSION = "1.0.0"

_DOCUMENTATION_URL = documentation_url(RULE_ID)
_SEVERITY = FindingSeverity.HIGH
_CONFIDENCE = Confidence.HIGH
_REMEDIATION = (
    "Add an approval in controlloop.yaml naming this resource as its "
    "capability, or revoke the write if it was not intentional."
)
#: Mirrors `controlloop.capability.taxonomy`'s own private
#: `_SENSITIVE_LEVELS` -- the same self-containment precedent the other
#: rules in this package already accept for a private constant elsewhere.
_MANIFEST_SENSITIVE_LEVELS = frozenset(
    {Sensitivity.CONFIDENTIAL, Sensitivity.RESTRICTED}
)


@dataclass(frozen=True, slots=True)
class _Detection:
    """One sensitive write with no matching declared approval --
    everything `evaluate()` and `findings()` both need."""

    message: str
    evidence: EvidenceCollection
    affected_agent: str
    capability_path: CapabilityPath


def _manifest_declares_sensitive(context: RuleContext, resource_name: str) -> bool:
    if context.manifest is None:
        return False
    return any(
        declaration.resource == resource_name
        and declaration.sensitivity in _MANIFEST_SENSITIVE_LEVELS
        for declaration in context.manifest.data_classification
    )


def _adapter_declares_sensitive(
    resource_security_attributes: SecurityAttributes,
) -> bool:
    return (
        MaterialCapabilityClass.SENSITIVE_DATA_ACCESS
        in classify_material_capability(resource_security_attributes)
    )


def _has_declared_approval(context: RuleContext, resource_name: str) -> bool:
    if context.manifest is None:
        return False
    return any(
        approval.capability == resource_name for approval in context.manifest.approvals
    )


def _detect(context: RuleContext) -> tuple[_Detection, ...]:
    node_by_id = {node.id: node for node in context.acbom.nodes}

    detections: list[_Detection] = []
    for edge in context.acbom.edges:
        if edge.type is not EdgeType.WRITES:
            continue

        agent = node_by_id.get(edge.source)
        resource = node_by_id.get(edge.target)
        if agent is None or resource is None:
            continue
        if agent.type is not NodeType.AGENT or resource.type is not NodeType.RESOURCE:
            continue

        sensitive = _adapter_declares_sensitive(
            resource.security_attributes
        ) or _manifest_declares_sensitive(context, resource.name)
        if not sensitive:
            continue

        if _has_declared_approval(context, resource.name):
            continue

        path = CapabilityPath(
            schema_version="1.0.0",
            agent_id=agent.id,
            target_id=resource.id,
            target_type=resource.type,
            hops=(
                PathHop(
                    edge_id=edge.id,
                    edge_type=edge.type,
                    source_id=edge.source,
                    target_id=edge.target,
                    evidence=edge.evidence,
                ),
            ),
            confidence=edge.confidence,
        )
        detections.append(
            _Detection(
                message=(
                    f"Agent writes to '{resource.name}', a resource carrying "
                    "a sensitive data class, with no declared approval in "
                    "controlloop.yaml."
                ),
                evidence=edge.evidence,
                affected_agent=agent.id,
                capability_path=path,
            )
        )
    return tuple(detections)


def evaluate(context: RuleContext) -> tuple[RuleObservation, ...]:
    """Engine-compatible entry point: `Rule.evaluate`'s fixed signature."""

    return tuple(
        RuleObservation(
            rule_id=RULE_ID, message=detection.message, evidence=detection.evidence
        )
        for detection in _detect(context)
    )


def findings(context: RuleContext) -> tuple[Finding, ...]:
    """The package's disclosed convenience bridge -- see
    `src/controlloop/policy/rules/__init__.py`'s docstring."""

    return tuple(
        finding_from_observation(
            RuleObservation(
                rule_id=RULE_ID,
                message=detection.message,
                evidence=detection.evidence,
            ),
            rule_version=RULE_VERSION,
            severity=_SEVERITY,
            confidence=_CONFIDENCE,
            affected_agent=detection.affected_agent,
            capability_path=detection.capability_path,
            change_state=FindingChangeState.NOT_COMPARED,
            remediation=_REMEDIATION,
            documentation_url=_DOCUMENTATION_URL,
        )
        for detection in _detect(context)
    )


RULE = Rule(id=RULE_ID, evaluate=evaluate)
