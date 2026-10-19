"""Rule: newly introduced destructive or financial action.

A change that gives an agent a destructive or financial action it did not
previously have -- directly, or transitively through a newly added
relationship edge -- is reported at high severity, with the path that
delivers it. The transitive-detection heuristic (see "Transitive case"
below) is not a straightforward application of one existing function.

## Taxonomy, not a keyword list

Uses `controlloop.capability.taxonomy.classify_material_capability`
unmodified. Per that module's own docstring and the reference fixture in
`tests/concepts/reference_fixture.py` (`BILLING_DB` carries
`destructive=True` on the *resource node*; the connecting `WRITES` edge
itself carries an empty `SecurityAttributes()`), this rule classifies
using the **target node's** `security_attributes` plus the actioning
edge's `type` -- the one place in this codebase this exact pattern is
already demonstrated.

## Direct case

`RuleContext.diff.effective_authority_changes` already
classifies every direct agent-to-resource action against a baseline.
Only `kind is ChangeKind.ADDED` entries are considered. With
`RuleContext.diff is None`, this rule reports nothing: "newly gained...
against an unchanged baseline" has no meaning without a baseline, and
reporting every existing destructive/financial capability with no
baseline would be exactly the noisy behavior this codebase's "low
false-positive burden" principle warns against.

## Transitive case

`EffectiveAuthorityChange`/`EffectiveAuthorityEntry` are only ever direct,
one-hop facts by construction -- a destructive resource reached *through*
an intermediate tool never appears there. `DiffResult` has no
`capability_path_changes` field, and `RuleContext` exposes no baseline
graph. This rule cannot literally diff two sets of transitive paths --
that data does not exist anywhere it can reach. Instead: for every edge in
`context.diff.edge_changes` that is newly `ADDED` and whose type is one of
the four a transitive walk chains through (mirroring
`controlloop.capability.compute`'s own private `_TRANSITIVE_EDGE_TYPES`),
this rule recomputes `compute_transitive_capability_paths` over the
*current* graph and reports every resulting path whose hop chain includes
that newly-added edge and whose target classifies as destructive or
financial. Because the edge is confirmed new, any path that necessarily
traverses it represents reach that did not exist by that route before --
conservative and non-fabricated, though it may under-report a case where
new reach arises from a combination of edges none of which individually
qualifies.

**Empirically confirmed while implementing this rule** (by reading
`controlloop.capability.compute.compute_transitive_capability_paths` in
full, then reproducing it in a test): that walk only ever chains through
`invokes`, `delegates-to`, `authenticates-as`, and `permitted-by` edges --
a `reads`/`writes` action edge is never part of any transitive path,
including its own final hop. A resource reached only by a direct write is
therefore always a *direct* fact (the direct case's territory, via
`EffectiveAuthorityChange`), never a transitive one in this codebase's
current model; a genuinely transitive destructive/financial finding
requires the target itself -- typically a tool -- to carry the
classifying `security_attributes`, reached through a delegation or
invocation chain. `tests/policy/rules/test_destructive_or_financial_action.py`'s
`TestTransitiveAuthority` class demonstrates this against a real
destructive *tool* reached through delegation, not a resource.
"""

from __future__ import annotations

from dataclasses import dataclass

from controlloop.acbom.models import Confidence, Edge, EdgeType, EvidenceCollection
from controlloop.capability.compute import compute_transitive_capability_paths
from controlloop.capability.models import CapabilityPath, PathHop
from controlloop.capability.taxonomy import (
    MaterialCapabilityClass,
    classify_material_capability,
)
from controlloop.diff.models import ChangeKind
from controlloop.findings.models import (
    Finding,
    FindingChangeState,
    FindingSeverity,
    finding_from_observation,
)
from controlloop.policy.models import Rule, RuleContext, RuleObservation
from controlloop.policy.rules._shared import documentation_url

RULE_ID = "policy.destructive-or-financial-action"
RULE_VERSION = "1.0.0"

_DOCUMENTATION_URL = documentation_url(RULE_ID)
_SEVERITY = FindingSeverity.HIGH
_REMEDIATION = (
    "Confirm this newly granted destructive or financial capability is "
    "intentional. If it was not, revoke the underlying permission, edge, "
    "or delegation that grants it."
)
_MATERIAL_CLASSES = frozenset(
    {
        MaterialCapabilityClass.DESTRUCTIVE_ACTION,
        MaterialCapabilityClass.FINANCIAL_ACTION,
    }
)
#: Mirrors `controlloop.capability.compute`'s own private
#: `_TRANSITIVE_EDGE_TYPES` -- duplicated here by the same
#: self-containment precedent that module already accepts for
#: `_ACTION_EDGE_TYPES`.
_TRANSITIVE_EDGE_TYPES = frozenset(
    {
        EdgeType.INVOKES,
        EdgeType.DELEGATES_TO,
        EdgeType.AUTHENTICATES_AS,
        EdgeType.PERMITTED_BY,
    }
)


@dataclass(frozen=True, slots=True)
class _Detection:
    """One newly gained destructive/financial capability -- everything
    `evaluate()` and `findings()` both need, computed once by `_detect`."""

    message: str
    evidence: EvidenceCollection
    affected_agent: str
    capability_path: CapabilityPath
    confidence: Confidence


def _material_class_names(classes: frozenset[MaterialCapabilityClass]) -> str:
    return " and ".join(sorted(member.value for member in classes))


def _direct_detections(context: RuleContext) -> tuple[_Detection, ...]:
    if context.diff is None:
        return ()

    node_by_id = {node.id: node for node in context.acbom.nodes}
    edges_by_agent_resource_action: dict[tuple[str, str, EdgeType], Edge] = {}
    for edge in context.acbom.edges:
        edges_by_agent_resource_action[(edge.source, edge.target, edge.type)] = edge

    detections: list[_Detection] = []
    for change in context.diff.effective_authority_changes:
        if change.kind is not ChangeKind.ADDED or change.after is None:
            continue

        resource = node_by_id.get(change.resource_id)
        if resource is None:
            continue

        material = (
            classify_material_capability(
                resource.security_attributes, edge_type=change.action
            )
            & _MATERIAL_CLASSES
        )
        if not material:
            continue

        action_edge = edges_by_agent_resource_action.get(
            (change.agent_id, change.resource_id, change.action)
        )
        if action_edge is None:
            continue

        path = CapabilityPath(
            schema_version="1.0.0",
            agent_id=change.agent_id,
            target_id=change.resource_id,
            target_type=resource.type,
            hops=(
                PathHop(
                    edge_id=action_edge.id,
                    edge_type=action_edge.type,
                    source_id=action_edge.source,
                    target_id=action_edge.target,
                    evidence=action_edge.evidence,
                ),
            ),
            confidence=change.after.confidence,
        )
        detections.append(
            _Detection(
                message=(
                    f"Agent gained new direct {change.action.value} access to "
                    f"'{resource.name}', classified as "
                    f"{_material_class_names(material)}."
                ),
                evidence=change.after.evidence,
                affected_agent=change.agent_id,
                capability_path=path,
                confidence=change.after.confidence,
            )
        )
    return tuple(detections)


def _transitive_detections(context: RuleContext) -> tuple[_Detection, ...]:
    if context.diff is None:
        return ()

    added_edge_ids = {
        change.edge_id
        for change in context.diff.edge_changes
        if change.kind is ChangeKind.ADDED
        and change.after is not None
        and change.after.type in _TRANSITIVE_EDGE_TYPES
    }
    if not added_edge_ids:
        return ()

    node_by_id = {node.id: node for node in context.acbom.nodes}
    paths, _incomplete = compute_transitive_capability_paths(
        context.acbom.nodes, context.acbom.edges
    )

    detections: list[_Detection] = []
    for path in paths:
        if not any(hop.edge_id in added_edge_ids for hop in path.hops):
            continue

        target = node_by_id.get(path.target_id)
        if target is None:
            continue

        last_hop = path.hops[-1]
        material = (
            classify_material_capability(
                target.security_attributes, edge_type=last_hop.edge_type
            )
            & _MATERIAL_CLASSES
        )
        if not material:
            continue

        detections.append(
            _Detection(
                message=(
                    "Agent gained new transitive reach to "
                    f"'{target.name}' through a newly added relationship, "
                    f"classified as {_material_class_names(material)}."
                ),
                evidence=last_hop.evidence,
                affected_agent=path.agent_id,
                capability_path=path,
                confidence=path.confidence,
            )
        )
    return tuple(detections)


def _detect(context: RuleContext) -> tuple[_Detection, ...]:
    return _direct_detections(context) + _transitive_detections(context)


def evaluate(context: RuleContext) -> tuple[RuleObservation, ...]:
    """Engine-compatible entry point: `Rule.evaluate`'s fixed signature."""

    return tuple(
        RuleObservation(
            rule_id=RULE_ID, message=detection.message, evidence=detection.evidence
        )
        for detection in _detect(context)
    )


def findings(context: RuleContext) -> tuple[Finding, ...]:
    """A disclosed convenience bridge -- see
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
            confidence=detection.confidence,
            affected_agent=detection.affected_agent,
            capability_path=detection.capability_path,
            change_state=FindingChangeState.ADDED,
            remediation=_REMEDIATION,
            documentation_url=_DOCUMENTATION_URL,
        )
        for detection in _detect(context)
    )


RULE = Rule(id=RULE_ID, evaluate=evaluate)
