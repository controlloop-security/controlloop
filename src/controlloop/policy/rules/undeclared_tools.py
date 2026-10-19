"""Rule: undeclared tools.

A tool an agent can reach, directly or transitively, that is not declared
anywhere in the repository's `controlloop.yaml` manifest produces a
finding naming the tool and where it was discovered. A declared tool
produces no finding. With no manifest present, the rule reports the
count of reachable tools without failing, and says a manifest would
improve the result, as one `RuleObservation` rather than a
`Finding` -- see this module's own design-decision docstring below.

See `src/controlloop/policy/rules/__init__.py`'s own docstring for the
`evaluate()`/`findings()` split these rules follow.

## What counts as "declared" (`ManifestDocument` has no dedicated
declared-tools field)

`ManifestDocument.approvals` (`Approval(capability, approver)`) is the only
manifest field expressing "the owner has recorded this named capability."
A discovered tool is treated as declared when its `Node.name` exactly
matches some `Approval.capability`. This is a narrow, considered reading
of an existing field, not a new one; a dedicated `declared_tools` field
would fit more precisely and is recommended as separate follow-up
scope.

## Reachability

"A tool an agent can reach" covers both a direct, one-hop path
(`compute_direct_capability_paths`) and a bounded transitive path of two
or more hops, for example through delegation
(`compute_transitive_capability_paths`) -- both existing, pure
functions over the current ACBOM's own nodes and edges. Missing a
transitively-reachable undeclared tool would be exactly the "silently
dropped capability produces a confident pass" failure this product
treats as its worst failure mode.
If the bounded transitive walk itself could not fully explore the graph,
that incompleteness is surfaced as its own `RuleObservation` (never
silently dropped) rather than folded into a false "no undeclared tools
found."
"""

from __future__ import annotations

from dataclasses import dataclass

from controlloop.acbom.models import Confidence, Evidence, EvidenceCollection, NodeType
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

RULE_ID = "policy.undeclared-tools"
RULE_VERSION = "1.0.0"

_DOCUMENTATION_URL = documentation_url(RULE_ID)
_SEVERITY = FindingSeverity.MEDIUM
_CONFIDENCE = Confidence.HIGH
_REMEDIATION = (
    "Declare this tool in controlloop.yaml (for example, an approvals entry "
    "naming its capability), or remove the agent's access to it if it was "
    "not intentional."
)
_NO_EVIDENCE_MARKER = "<no-manifest>"
_ADAPTER_NAME = "policy.undeclared-tools"


@dataclass(frozen=True, slots=True)
class _Detection:
    """One undeclared, reachable tool -- everything `evaluate()` and
    `findings()` both need, computed once by `_detect`."""

    message: str
    evidence: EvidenceCollection
    affected_agent: str
    capability_path: CapabilityPath


def _declared_tool_names(context: RuleContext) -> frozenset[str] | None:
    """`None` means no manifest was supplied at all; an empty
    `frozenset` means a manifest exists but declares no capabilities."""

    if context.manifest is None:
        return None
    return frozenset(approval.capability for approval in context.manifest.approvals)


def _reachable_tool_paths(
    context: RuleContext,
) -> tuple[tuple[CapabilityPath, ...], tuple[Evidence, ...]]:
    """Every path from an agent to a tool node, direct or bounded
    transitive, deduplicated by `(agent_id, target_id)` so a tool reached
    by more than one route is reported once. Returns the paths plus any
    evidence describing where the bounded transitive walk itself could not
    fully explore the graph (empty when it completed cleanly)."""

    nodes = context.acbom.nodes
    edges = context.acbom.edges

    direct = compute_direct_capability_paths(nodes, edges)
    transitive, incomplete_diagnostics = compute_transitive_capability_paths(
        nodes, edges
    )

    seen: dict[tuple[str, str], CapabilityPath] = {}
    for path in (*direct, *transitive):
        if path.target_type is not NodeType.TOOL:
            continue
        key = (path.agent_id, path.target_id)
        seen.setdefault(key, path)

    incomplete_evidence = tuple(
        evidence
        for diagnostic in incomplete_diagnostics
        for evidence in diagnostic.evidence
    )
    return tuple(seen.values()), incomplete_evidence


def _detect(
    context: RuleContext,
) -> tuple[tuple[_Detection, ...], tuple[Evidence, ...]]:
    """Returns undeclared-tool detections plus any evidence describing
    where the bounded transitive walk could not fully explore the graph.
    Empty detections with `declared is None` (no manifest) are the
    no-manifest case, handled entirely by `evaluate()` since it has no
    natural single affected agent and is never promoted to a
    `Finding`."""

    declared = _declared_tool_names(context)
    if declared is None:
        return (), ()

    node_by_id = {node.id: node for node in context.acbom.nodes}
    paths, incomplete_evidence = _reachable_tool_paths(context)

    detections: list[_Detection] = []
    for path in paths:
        tool = node_by_id.get(path.target_id)
        if tool is None or tool.name in declared:
            continue
        detections.append(
            _Detection(
                message=(
                    f"Tool '{tool.name}' is reachable but not declared in "
                    "controlloop.yaml."
                ),
                evidence=tool.evidence,
                affected_agent=path.agent_id,
                capability_path=path,
            )
        )
    return tuple(detections), incomplete_evidence


def evaluate(context: RuleContext) -> tuple[RuleObservation, ...]:
    """Engine-compatible entry point: `Rule.evaluate`'s fixed signature.
    Returns one `RuleObservation` per undeclared reachable tool, or,
    with no manifest present, one advisory count-only observation, plus
    one observation if the bounded transitive walk itself
    could not fully explore the graph."""

    if _declared_tool_names(context) is None:
        paths, incomplete_evidence = _reachable_tool_paths(context)
        count = len({path.target_id for path in paths})
        evidence = incomplete_evidence or (
            Evidence(adapter=_ADAPTER_NAME, path=_NO_EVIDENCE_MARKER),
        )
        message = (
            f"{count} tool(s) are reachable by agents in this repository. "
            "No controlloop.yaml manifest was found, so undeclared-tool "
            "detection did not run. Adding a manifest declaring known "
            "tools as approved capabilities would improve this result."
        )
        return (RuleObservation(rule_id=RULE_ID, message=message, evidence=evidence),)

    detections, incomplete_evidence = _detect(context)
    observations = [
        RuleObservation(
            rule_id=RULE_ID, message=detection.message, evidence=detection.evidence
        )
        for detection in detections
    ]

    if incomplete_evidence:
        observations.append(
            RuleObservation(
                rule_id=RULE_ID,
                message=(
                    "The bounded transitive reachability walk this rule "
                    "depends on could not fully explore the capability "
                    "graph; some reachable tools may not have been "
                    "considered."
                ),
                evidence=incomplete_evidence,
            )
        )
    return tuple(observations)


def findings(context: RuleContext) -> tuple[Finding, ...]:
    """A disclosed convenience bridge (not part of the
    engine contract, not wired into any CLI command): the same `_detect`
    computation as `evaluate()`, promoted to real `Finding`s via
    `finding_from_observation`. The no-manifest advisory has no
    natural single affected agent and is never promoted here -- it exists
    only as a `RuleObservation` via `evaluate()`."""

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
        for detection in _detect(context)[0]
    )


RULE = Rule(id=RULE_ID, evaluate=evaluate)
