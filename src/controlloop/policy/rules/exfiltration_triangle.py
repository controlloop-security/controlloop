"""Rule: exfiltration triangle detection.

When one agent combines sensitive-data access, untrusted input, and
outbound communication, this rule names it as a single top-severity
finding rather than three unrelated ones -- provable structurally from
the graph, never by pattern-matching content or names. The most
important design decisions are summarized below.

## Three legs, two taxonomy members and one structural edge type

`controlloop.capability.taxonomy.MaterialCapabilityClass` has
direct members for two of the three legs: `SENSITIVE_DATA_ACCESS` (from
`SecurityAttributes.sensitivity`/`data_classifications`) and
`EXTERNAL_COMMUNICATION` (from `SecurityAttributes.external_communication`).
It has no member for "untrusted input" at all. This rule represents that
third leg structurally, via `EdgeType.RECEIVES_FROM` -- an agent
receiving from any other node at all -- mirroring `classify_material_capability`'s
own documented precedent that `writes`/`delegates-to` are pure,
unconditional edge-type checks with no `SecurityAttributes` gate. This
is grounded further in this codebase's own "all input is hostile"
invariant: receiving input through a `receives-from` edge is
definitionally the untrusted case in this graph model today; nothing
represents "trusted input" as a separately asserted fact. No new
adapter, node type, or edge type is introduced -- `RECEIVES_FROM` is
already declared, already schema-published, and already exercised by
`tests/concepts/reference_fixture.py`.

## Declared and inferred input

Two sources produce that edge for a real repository today. A
declaration in `controlloop.yaml` (`external_inputs`, applied by
`controlloop.manifest.inputs`) is authoritative: the repository states
that the agent takes input from a named external source, the edge
carries `untrusted_input=True`, and the leg is PRESENT. An A2A card's
`url` is an inference by `controlloop.adapters.a2a`: the agent accepts
requests, from whom the card cannot say, so the edge carries the
literal `untrusted_input="unknown"` and the leg is UNKNOWN -- with the
other two legs present that is a qualified finding at `medium`, below
the default gate threshold, naming what was inferred and how to
confirm or rule it out. A confirmed edge always outranks an inferred
one on the same agent. Agent-running workflows produce a confirmed
edge from the event that starts them (`controlloop.adapters.workflows`).

## Untrusted-input transitivity is deliberately direct-only

`compute_transitive_capability_paths`'s own `_TRANSITIVE_EDGE_TYPES`
(`invokes`, `delegates-to`, `authenticates-as`, `permitted-by`) does not
include `receives-from`, and `CapabilityPath.target_type` is closed to
`{tool, resource, identity, permission, data-class}`, excluding
`trigger` -- confirmed by reading both `capability/compute.py` and
`capability/models.py` in full. Extending either would mean altering
established, explicitly protected contracts this rule does not touch.
The untrusted-input leg is therefore evaluated only on the origin
agent's own direct `receives-from` edges; the "reachable only
transitively" fixture is demonstrated instead
through the external-communication leg, which routes cleanly through
the reused, unmodified `compute_transitive_capability_paths`.

## One `Finding`, one `capability_path`, tri-state legs

`Finding.capability_path` is singular and closed to the same
five node types `CapabilityPath` already allows -- it cannot hold three
paths, and the untrusted-input leg (a `receives-from` edge, typically
targeting a `trigger` node) is never itself a valid `capability_path`.
This rule's message names and describes all three legs and their own
paths; `Finding.evidence` combines and deduplicates evidence from all
three; `Finding.capability_path` is deterministically the
external-communication leg's path when present (worse than
sensitive-data-access per `taxonomy._SEVERITY_RANK`, and the actual
"exfiltration step"), falling back to the sensitive-data-access leg's
path otherwise.

Each of the two classifiable legs is evaluated tri-state
(present/unknown/absent) by calling `classify_material_capability`
(the taxonomy itself, unmodified) for the present determination,
and separately reading the exact one `SecurityAttributes` field that
taxonomy member itself reads (`sensitivity`/`external_communication`)
for the unknown determination -- never `classify_material_capability`'s
own `UNCLASSIFIED` marker directly, which aggregates unknown-ness across
several unrelated fields and would not say which of *this* rule's two
legs was the unproven one.

This rule fires only when at least two of the three legs are
definitively present: all three present is the full, top-severity
finding; exactly two present plus exactly one unknown is the qualified
finding; anything else is silent, including the two-of-three negative
case. `change_state` is always
`FindingChangeState.NOT_COMPARED` -- this rule detects a structural
pattern on the current graph, not a change against a baseline, the same
choice `broad_permission.py`/`undeclared_tools.py` already made for
their own non-diff-based detections.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import StrEnum

from controlloop.acbom.models import (
    Confidence,
    Edge,
    EdgeType,
    Evidence,
    EvidenceCollection,
    Node,
    NodeType,
    SecurityAttributes,
    Sensitivity,
)
from controlloop.capability.compute import (
    compute_direct_capability_paths,
    compute_transitive_capability_paths,
)
from controlloop.capability.models import CapabilityPath
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

RULE_ID = "policy.exfiltration-triangle"
RULE_VERSION = "1.1.0"

_DOCUMENTATION_URL = documentation_url(RULE_ID)

#: The taxonomy's own actual highest declared member, matching the
#: rule's "top-severity" wording exactly.
_FULL_SEVERITY = FindingSeverity.CRITICAL
#: Serious, but deliberately below the confident top tier --
#: this claim is, by definition, unproven.
_QUALIFIED_SEVERITY = FindingSeverity.HIGH
#: Lower again when the unproven leg is the untrusted-input one and it
#: was *inferred* (an A2A card's endpoint, `untrusted_input="unknown"`)
#: rather than declared: below the default gate threshold, so an
#: inference alone never blocks; the repository confirms or rules it out
#: by declaring the agent's inputs in `controlloop.yaml`.
_INFERRED_INPUT_SEVERITY = FindingSeverity.MEDIUM

_FULL_REMEDIATION = (
    "This agent structurally combines sensitive-data access, untrusted "
    "input, and external communication -- the precondition for data "
    "exfiltration. Confirm all three are genuinely required together; "
    "if so, add human approval, output filtering, or a policy boundary "
    "before the external-communication step."
)
_QUALIFIED_REMEDIATION = (
    "Two of the three exfiltration-triangle legs are confirmed and the "
    "third could not be classified from available evidence. Resolve the "
    "unproven leg's security attributes so this can be confidently "
    "confirmed or ruled out, rather than left unknown."
)
_INFERRED_INPUT_REMEDIATION = (
    "This agent confirms sensitive-data access and external "
    "communication, and discovery inferred that it accepts inbound "
    "requests, without being able to tell whether they come from an "
    "untrusted source. Declare the agent's inputs in controlloop.yaml "
    "(`external_inputs`): a declared external input confirms the "
    "triangle at full severity; an agent with no external input needs "
    "no declaration, and this finding then records what was inferred."
)

#: Mirrors `controlloop.capability.compute`'s own private
#: `_CONFIDENCE_RANK` -- duplicated here by the same self-containment
#: precedent that module already accepts for `_TRANSITIVE_EDGE_TYPES`
#: (see `destructive_or_financial_action.py` for the same duplication).
_CONFIDENCE_RANK: dict[Confidence, int] = {
    Confidence.UNKNOWN: 0,
    Confidence.LOW: 1,
    Confidence.MEDIUM: 2,
    Confidence.HIGH: 3,
}
_MAX_EVIDENCE = 32


class _LegStatus(StrEnum):
    """One leg's tri-state classification, evaluated per agent."""

    PRESENT = "present"
    UNKNOWN = "unknown"
    ABSENT = "absent"


class _Leg(StrEnum):
    """The exfiltration triangle's three named legs."""

    SENSITIVE_DATA_ACCESS = "sensitive-data-access"
    UNTRUSTED_INPUT = "untrusted-input"
    EXTERNAL_COMMUNICATION = "external-communication"


@dataclass(frozen=True, slots=True)
class _LegFinding:
    """One leg's evaluated status for one agent: its tri-state
    (`status`), a human description of its path for the finding
    message, its own evidence, and -- for the two legs that produce a
    real `CapabilityPath` -- that path. `path` is always `None` for the
    untrusted-input leg (see this module's own docstring)
    and for any leg whose status is `ABSENT`."""

    status: _LegStatus
    description: str
    evidence: tuple[Evidence, ...]
    path: CapabilityPath | None
    confidence: Confidence


_ABSENT_LEG = _LegFinding(
    status=_LegStatus.ABSENT,
    description="",
    evidence=(),
    path=None,
    confidence=Confidence.UNKNOWN,
)


@dataclass(frozen=True, slots=True)
class _Detection:
    """One triangle (full or qualified) on one agent -- everything
    `evaluate()` and `findings()` both need, computed once by
    `_detect`."""

    message: str
    evidence: EvidenceCollection
    affected_agent: str
    capability_path: CapabilityPath
    severity: FindingSeverity
    confidence: Confidence
    remediation: str


def _weakest(confidences: Iterable[Confidence]) -> Confidence:
    return min(confidences, key=lambda confidence: _CONFIDENCE_RANK[confidence])


def _combined_evidence(*groups: tuple[Evidence, ...]) -> tuple[Evidence, ...]:
    combined: list[Evidence] = []
    for group in groups:
        combined.extend(group)
    return tuple(dict.fromkeys(combined))[:_MAX_EVIDENCE]


def _path_description(path: CapabilityPath, target_name: str) -> str:
    hop_count = len(path.hops)
    reach = "direct" if hop_count == 1 else f"transitive, {hop_count} hops"
    return f"'{target_name}' ({reach})"


def _paths_by_agent(
    nodes: tuple[Node, ...], edges: tuple[Edge, ...]
) -> dict[str, list[CapabilityPath]]:
    """Every direct and bounded-transitive capability path, grouped by
    origin agent, in one fixed, deterministic order (direct paths --
    already deterministically ordered -- followed by transitive paths,
    also already deterministically ordered): reuses
    `compute_direct_capability_paths`/`compute_transitive_capability_paths`
    unmodified rather than reimplementing graph traversal."""

    direct = compute_direct_capability_paths(nodes, edges)
    transitive, _diagnostics = compute_transitive_capability_paths(nodes, edges)

    by_agent: dict[str, list[CapabilityPath]] = {}
    for path in (*direct, *transitive):
        by_agent.setdefault(path.agent_id, []).append(path)
    return by_agent


_UnknownCheck = Callable[[SecurityAttributes], bool]


def _classify_leg_for_path(
    path: CapabilityPath,
    node_by_id: dict[str, Node],
    material_class: MaterialCapabilityClass,
    is_unknown: _UnknownCheck,
) -> _LegFinding | None:
    """`None` when `path`'s target does not classify as `material_class`
    and is not `unknown` for the one field that class depends on --
    i.e. this path says nothing about this leg at all."""

    target = node_by_id.get(path.target_id)
    if target is None:  # pragma: no cover -- ACBOMDocument's own graph-
        # integrity validator already guarantees every edge endpoint,
        # and therefore every path.target_id, resolves to a real node;
        # kept as defense-in-depth against a malformed graph rather than
        # assumed, per this repository's "all input is hostile" rule.
        return None

    last_hop = path.hops[-1]
    classes = classify_material_capability(
        target.security_attributes, edge_type=last_hop.edge_type
    )
    evidence = _combined_evidence(target.evidence, last_hop.evidence)
    description = _path_description(path, target.name)

    if material_class in classes:
        return _LegFinding(
            status=_LegStatus.PRESENT,
            description=description,
            evidence=evidence,
            path=path,
            confidence=path.confidence,
        )
    if is_unknown(target.security_attributes):
        return _LegFinding(
            status=_LegStatus.UNKNOWN,
            description=description,
            evidence=evidence,
            path=path,
            confidence=path.confidence,
        )
    return None


def _best_leg(
    paths: list[CapabilityPath],
    node_by_id: dict[str, Node],
    material_class: MaterialCapabilityClass,
    is_unknown: _UnknownCheck,
) -> _LegFinding:
    """The strongest classification of `material_class` reachable by
    any of `paths` (deterministically ordered): a `PRESENT` result wins
    immediately over an `UNKNOWN` one, since `paths` is already in a
    fixed order regardless of input order."""

    best_unknown: _LegFinding | None = None
    for path in paths:
        candidate = _classify_leg_for_path(path, node_by_id, material_class, is_unknown)
        if candidate is None:
            continue
        if candidate.status is _LegStatus.PRESENT:
            return candidate
        if best_unknown is None:
            best_unknown = candidate
    return best_unknown or _ABSENT_LEG


def _is_sensitivity_unknown(security_attributes: SecurityAttributes) -> bool:
    return security_attributes.sensitivity is Sensitivity.UNKNOWN


def _is_external_communication_unknown(security_attributes: SecurityAttributes) -> bool:
    return security_attributes.external_communication == "unknown"


def _untrusted_input_leg(
    edges: tuple[Edge, ...], agent_id: str, node_by_id: dict[str, Node]
) -> _LegFinding:
    """Structural -- any `receives-from` edge sourced at
    `agent_id`, regardless of its target's node type or
    `SecurityAttributes`. See this module's own docstring for why. When
    more than one such edge exists, the one with the lexicographically
    smallest edge ID is chosen, so the result never depends on input
    order (the shuffled-order determinism case)."""

    def _inferred(edge: Edge) -> bool:
        # An inferred input (an A2A endpoint) carries the literal
        # `"unknown"` on the edge; a declared or discovered one does not.
        return edge.security_attributes.untrusted_input == "unknown"

    # A confirmed edge always outranks an inferred one; among equals the
    # lexicographically smallest edge ID wins, so the result never
    # depends on input order (the shuffled-order determinism case).
    candidates = sorted(
        (
            edge
            for edge in edges
            if edge.type is EdgeType.RECEIVES_FROM and edge.source == agent_id
        ),
        key=lambda edge: (_inferred(edge), edge.id),
    )
    if not candidates:
        return _ABSENT_LEG

    edge = candidates[0]
    target = node_by_id.get(edge.target)
    target_name = target.name if target is not None else edge.target
    if _inferred(edge):
        return _LegFinding(
            status=_LegStatus.UNKNOWN,
            description=f"'{target_name}' (inferred, receives-from)",
            evidence=tuple(edge.evidence),
            path=None,
            confidence=edge.confidence,
        )
    return _LegFinding(
        status=_LegStatus.PRESENT,
        description=f"'{target_name}' (direct, receives-from)",
        evidence=tuple(edge.evidence),
        path=None,
        confidence=edge.confidence,
    )


def _canonical_path(legs: dict[_Leg, _LegFinding]) -> CapabilityPath | None:
    """The one `CapabilityPath` a `Finding` from this rule
    carries -- deterministically the external-communication leg's path
    when that leg is definitively `PRESENT` (see this module's own
    docstring), falling back to the sensitive-data-access leg's path
    when it, not external-communication, is the one `PRESENT`. Checks
    `.status`, not merely whether `.path` is set -- an `UNKNOWN` leg
    also carries a `path` (the path that could not be
    confidently classified), which must never be mistaken for a
    confirmed leg's path. `None` only when neither classifiable leg is
    `PRESENT`, which never happens for a `_Detection` this module
    actually builds (guarded by `_detect`'s own firing threshold: at
    least two of the three legs -- of which at most one is
    untrusted-input, whose own `path` is always `None` -- are always
    `PRESENT`)."""

    comm = legs[_Leg.EXTERNAL_COMMUNICATION]
    if comm.status is _LegStatus.PRESENT:
        return comm.path
    sensitive = legs[_Leg.SENSITIVE_DATA_ACCESS]
    if sensitive.status is _LegStatus.PRESENT:
        return sensitive.path
    return None  # pragma: no cover -- unreachable given _detect's own
    # firing threshold: only invoked with at least two of the three legs
    # PRESENT, of which untrusted-input (whose own path is always None)
    # is at most one, so at least one of comm/sensitive is always
    # PRESENT here.


def _full_detection(agent_id: str, legs: dict[_Leg, _LegFinding]) -> _Detection | None:
    canonical = _canonical_path(legs)
    if canonical is None:  # pragma: no cover -- see _canonical_path's own
        # docstring; unreachable when all three legs are PRESENT.
        return None

    sensitive = legs[_Leg.SENSITIVE_DATA_ACCESS]
    untrusted = legs[_Leg.UNTRUSTED_INPUT]
    comm = legs[_Leg.EXTERNAL_COMMUNICATION]

    message = (
        "Agent forms an exfiltration triangle, combining all three legs: "
        f"sensitive-data-access to {sensitive.description}, "
        f"untrusted-input from {untrusted.description}, and "
        f"external-communication to {comm.description}."
    )
    evidence = _combined_evidence(sensitive.evidence, untrusted.evidence, comm.evidence)
    confidence = _weakest((sensitive.confidence, untrusted.confidence, comm.confidence))
    return _Detection(
        message=message,
        evidence=evidence,
        affected_agent=agent_id,
        capability_path=canonical,
        severity=_FULL_SEVERITY,
        confidence=confidence,
        remediation=_FULL_REMEDIATION,
    )


def _qualified_detection(
    agent_id: str,
    legs: dict[_Leg, _LegFinding],
    present: list[_Leg],
    unknown_leg: _Leg,
) -> _Detection | None:
    canonical = _canonical_path(legs)
    if canonical is None:  # pragma: no cover -- see _canonical_path's own
        # docstring; unreachable when two of the three legs are PRESENT.
        return None

    unknown_lf = legs[unknown_leg]
    present_description = "; ".join(
        f"{leg.value}: {legs[leg].description}" for leg in present
    )
    if unknown_leg is _Leg.UNTRUSTED_INPUT:
        message = (
            "Agent confirms two of three exfiltration-triangle legs "
            f"({present_description}), and its untrusted-input leg is "
            f"inferred, not declared: {unknown_lf.description}; reported "
            "at reduced severity until controlloop.yaml declares the "
            "agent's external inputs or their absence."
        )
        severity = _INFERRED_INPUT_SEVERITY
        remediation = _INFERRED_INPUT_REMEDIATION
    else:
        message = (
            "Agent confirms two of three exfiltration-triangle legs "
            f"({present_description}), but the {unknown_leg.value} leg could "
            "not be classified from available evidence (marked 'unknown'); "
            "reported as a qualified finding rather than silence or a "
            "confident claim."
        )
        severity = _QUALIFIED_SEVERITY
        remediation = _QUALIFIED_REMEDIATION
    evidence = _combined_evidence(
        *(legs[leg].evidence for leg in present), unknown_lf.evidence
    )
    return _Detection(
        message=message,
        evidence=evidence,
        affected_agent=agent_id,
        capability_path=canonical,
        severity=severity,
        confidence=Confidence.UNKNOWN,
        remediation=remediation,
    )


def _detect(context: RuleContext) -> tuple[_Detection, ...]:
    nodes = context.acbom.nodes
    edges = context.acbom.edges
    node_by_id = {node.id: node for node in nodes}
    agent_ids = sorted(node.id for node in nodes if node.type is NodeType.AGENT)

    paths_by_agent = _paths_by_agent(nodes, edges)

    detections: list[_Detection] = []
    for agent_id in agent_ids:
        agent_paths = paths_by_agent.get(agent_id, [])

        legs: dict[_Leg, _LegFinding] = {
            _Leg.SENSITIVE_DATA_ACCESS: _best_leg(
                agent_paths,
                node_by_id,
                MaterialCapabilityClass.SENSITIVE_DATA_ACCESS,
                _is_sensitivity_unknown,
            ),
            _Leg.UNTRUSTED_INPUT: _untrusted_input_leg(edges, agent_id, node_by_id),
            _Leg.EXTERNAL_COMMUNICATION: _best_leg(
                agent_paths,
                node_by_id,
                MaterialCapabilityClass.EXTERNAL_COMMUNICATION,
                _is_external_communication_unknown,
            ),
        }

        present = [leg for leg, lf in legs.items() if lf.status is _LegStatus.PRESENT]
        unknown = [leg for leg, lf in legs.items() if lf.status is _LegStatus.UNKNOWN]

        detection: _Detection | None = None
        if len(present) == 3:
            detection = _full_detection(agent_id, legs)
        elif len(present) == 2 and len(unknown) == 1:
            detection = _qualified_detection(agent_id, legs, present, unknown[0])

        if detection is not None:
            detections.append(detection)

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
    """The `Finding`-producing counterpart to `evaluate()` -- see this
    package's own `__init__.py` docstring for why both exist."""

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
        for detection in _detect(context)
    )


RULE = Rule(id=RULE_ID, evaluate=evaluate)

__all__ = [
    "RULE",
    "RULE_ID",
    "evaluate",
    "findings",
]
