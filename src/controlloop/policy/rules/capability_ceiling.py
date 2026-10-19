"""Rule: capability ceiling evaluation.

**Outcome (the MVP's own differentiator):** any effective authority
outside the declared ceiling fails, including expansion no pattern rule
anticipated. Every other rule in this package (`undeclared_tools`,
`broad_permission`, and the rest) is a denylist -- it catches a
specific, named shape of risk. `controlloop.manifest.ceiling` already
lets an owner declare an allowlist *boundary* instead: the maximum
authority an agent may ever hold. That module deliberately does not
decide whether a specific discovered capability actually violates an
effective ceiling. This module does.

## Why this rule reads capability paths, not `compute_effective_authority`

`compute_direct_capability_paths`/`compute_transitive_capability_paths`
already subsume everything
`compute_effective_authority` reports (one-hop `reads`/`writes`/`invokes`
facts) *and* add the full hop chain, multi-hop reach, and every other
capability-path target category (`identity`, `permission`, `data-class`)
a `CapabilityCeiling`'s five prohibition fields can name. Calling both
functions here would recompute overlapping work for no benefit -- "a
breach reachable only transitively is caught, with its full path
reported" is satisfied directly by scanning every hop of every direct
and transitive `CapabilityPath`, never a bare one-hop fact.

## How each `CapabilityCeiling` field is matched (a disclosed design
decision, since the ceiling model names five prohibition categories
nothing else resolves against real capability paths)

- `prohibited_actions` (a set of `EdgeType`): a breach when **any** hop
  anywhere in a path -- not only the final one -- carries a prohibited
  edge type. An agent whose ceiling prohibits `writes` breaches it by
  writing partway through a longer chain, even if the chain's ultimate
  target is not itself prohibited.
- `prohibited_resources` / `prohibited_external_destinations`: matched
  against a path's **final target node's own `name`**. Both fields are
  free-form `SafeIdentifier` strings with no distinct canonical node
  type of their own (`CapabilityCeiling`'s own docstring: "external
  destinations have no existing canonical shape to reuse"), so both are
  matched the identical way -- by name, against a `CapabilityPath`
  target of any of the five reachable categories. Nothing in this
  codebase currently distinguishes "a resource" from "an external
  destination" at the graph level; the two ceiling fields exist for a
  human author's own intent, not a technical distinction this rule can
  observe.
- `prohibited_data_classes` (a set of `Sensitivity`): a breach when a
  path's final target node's `security_attributes.sensitivity` is in
  the set. Checked only at the target, not every hop, since sensitivity
  is a property of the data being reached, not of an intermediate
  action.
- `prohibited_delegation_targets`: a breach when any hop is a
  `delegates-to` edge whose target is an `AGENT` node named in the set
  -- the same two-tier `evaluate()`/`findings()` split
  `unauthorized_delegation.py` already established and disclosed for
  the identical `CapabilityPath.target_type` gap (excludes `agent`):
  `evaluate()` covers every disallowed `delegates-to` edge
  unconditionally, including a bare delegation with no further
  discovered capability; `findings()` covers only chains that reach a
  real capability beyond the disallowed agent, since only those have a
  valid `CapabilityPath` to attach a `Finding` to.

## Independent of every other rule, not merely "not disabled"

This rule reads only `context.acbom`/`context.manifest` and
`controlloop.manifest.ceiling.effective_ceiling` -- it imports no other
rule module and calls no other rule's detection function, so a breach
this rule finds is structurally unrelated to whether any pattern rule
in this package is registered or enabled at all. The engine's own
`RuleMetadata.mandatory` governance flag is this codebase's existing
"cannot be disabled by policy configuration" primitive, and
`controlloop.policy.rulepack` marks this rule `mandatory=True` -- this
module's own scope stops at exposing the deterministic evaluation this
rule performs, not that governance decision.

## Unknown is reported as unverifiable, never as compliant

Two distinct sources of "this scan cannot prove compliance," both
surfaced as advisory `RuleObservation`s (never a `Finding` -- there is
no specific breached capability to attach one to) rather than silently
producing no observation at all, which this codebase's "Unknown, never
omitted" invariant treats as the worst failure mode:

1. Any diagnostic `compute_transitive_capability_paths` itself produced
   (`INCOMPLETE-BOUND-EXCEEDED`/`INCOMPLETE-CYCLE-DETECTED`) means more
   of the graph may exist beyond what this scan actually explored --
   every agent with a declared ceiling gets one "verification
   incomplete" observation when this happens, since the unexplored
   region could contain a real breach this scan structurally could not
   see.
2. A reachable `CapabilityPath` at `Confidence.UNKNOWN` that is not
   already a detected breach is reported as unverifiable rather than
   silently passed -- the same reasoning
   `EffectiveAuthorityEntry.confidence`'s own docstring already applies
   to an action with no resolvable permitting identity ("never that no
   identity grants the action").

## No declared ceiling is disclosed, never treated as a failure

`evaluate()` returns exactly one informational `RuleObservation` when
`context.manifest` is `None` or declares no ceilings at all --
`"no capability ceiling is declared for this repository"` -- and
otherwise proceeds with real breach/unverifiable detection. This is not
a breach and is never promoted to a `Finding`; it is a structural
signal a future `gate` command's own report can surface (`scan`/`gate`
remain argument-free stubs; no CLI command consumes this rule yet).
"""

from __future__ import annotations

from dataclasses import dataclass

from controlloop.acbom.models import (
    Confidence,
    Diagnostic,
    EdgeType,
    EvidenceCollection,
    Node,
    NodeType,
)
from controlloop.capability.compute import (
    compute_direct_capability_paths,
    compute_transitive_capability_paths,
)
from controlloop.capability.models import CapabilityPath, PathHop
from controlloop.findings.models import (
    Finding,
    FindingSeverity,
    finding_from_observation,
)
from controlloop.manifest.ceiling import effective_ceiling
from controlloop.manifest.models import CapabilityCeiling, ManifestDocument
from controlloop.manifest.reconciliation import manifest_evidence
from controlloop.policy.models import Rule, RuleContext, RuleObservation
from controlloop.policy.rules._shared import documentation_url, node_change_state

RULE_ID = "policy.capability-ceiling"
RULE_VERSION = "1.0.0"
_DOCUMENTATION_URL = documentation_url(RULE_ID)

_NO_CEILING_MESSAGE = (
    "no capability ceiling is declared for this repository; effective "
    "authority was not evaluated against a ceiling"
)

#: `RuleObservation.evidence` requires at least one item -- the
#: no-ceiling informational observation has no specific offending
#: capability to point at, so it points at the manifest file itself (the
#: place a ceiling would be declared, whether or not one currently is),
#: reusing `controlloop.manifest.reconciliation.manifest_evidence`'s own
#: default path rather than inventing a second convention.
_NO_CEILING_EVIDENCE = manifest_evidence("controlloop.yaml")


@dataclass(frozen=True, slots=True)
class _Breach:
    """One capability that crosses its agent's declared ceiling --
    everything `evaluate()` and `findings()` both need. `capability_path`
    is `None` only for a bare disallowed `delegates-to` edge with no
    further discovered capability (the `unauthorized_delegation` rule's
    precedent for the identical `CapabilityPath.target_type` gap)."""

    message: str
    evidence: EvidenceCollection
    affected_agent: str
    capability_path: CapabilityPath | None
    remediation: str


@dataclass(frozen=True, slots=True)
class _Unverifiable:
    """A signal that this scan could not prove an agent's
    capabilities are within its declared ceiling -- reported, never
    silently treated as compliant."""

    message: str
    evidence: EvidenceCollection


def _agents_with_declared_ceiling(
    context: RuleContext, manifest: ManifestDocument
) -> tuple[tuple[Node, CapabilityCeiling], ...]:
    """`manifest` is taken as its own non-optional parameter, not read
    from `context.manifest` (`ManifestDocument | None`) -- the only
    caller, `_detect`, is itself only ever reached after `evaluate`/
    `findings` have already confirmed `context.manifest` is not `None`
    and declares at least one ceiling. Threading the already-narrowed
    value through avoids a redundant `None` guard here that would be
    structurally unreachable and therefore untestable, the same
    precedent `unauthorized_delegation._shares_a_declared_trust_boundary`
    already established for an identical situation."""

    result = []
    for node in context.acbom.nodes:
        if node.type is not NodeType.AGENT:
            continue
        ceiling = effective_ceiling(node.name, manifest)
        if (
            ceiling.prohibited_resources
            or ceiling.prohibited_actions
            or ceiling.prohibited_external_destinations
            or ceiling.prohibited_data_classes
            or ceiling.prohibited_delegation_targets
        ):
            result.append((node, ceiling))
    return tuple(sorted(result, key=lambda item: item[0].id))


def _breach_reason(
    path: CapabilityPath,
    ceiling: CapabilityCeiling,
    node_by_id: dict[str, Node],
) -> tuple[PathHop | None, str] | None:
    """The first reason (closest to the origin agent) `path` breaches
    `ceiling`, or `None` if it does not. Checked in a
    fixed priority order (action, delegation, resource/destination
    name, data class) purely for deterministic tie-breaking when a
    single path breaches more than one category; every real breach is
    still reported once, whichever category is found first."""

    for hop in path.hops:
        if hop.edge_type in ceiling.prohibited_actions:
            target = node_by_id.get(hop.target_id)
            target_name = target.name if target is not None else hop.target_id
            return hop, (
                f"a {hop.edge_type.value!r} action reaches {target_name!r}, "
                "which is a prohibited action type under its capability ceiling"
            )
        if hop.edge_type is EdgeType.DELEGATES_TO:
            target = node_by_id.get(hop.target_id)
            if (
                target is not None
                and target.type is NodeType.AGENT
                and target.name in ceiling.prohibited_delegation_targets
            ):
                return hop, (
                    f"delegates to {target.name!r}, which is a prohibited "
                    "delegation target under its capability ceiling"
                )

    target_node = node_by_id.get(path.target_id)
    if target_node is not None:
        if (
            target_node.name in ceiling.prohibited_resources
            or target_node.name in ceiling.prohibited_external_destinations
        ):
            return None, (
                f"reaches {target_node.name!r}, which is a prohibited resource "
                "or external destination under its capability ceiling"
            )
        sensitivity = target_node.security_attributes.sensitivity
        if sensitivity is not None and sensitivity in ceiling.prohibited_data_classes:
            return None, (
                f"reaches {target_node.name!r}, classified {sensitivity.value!r}, "
                "which is a prohibited data class under its capability ceiling"
            )

    return None


def _all_capability_paths(
    context: RuleContext,
) -> tuple[tuple[CapabilityPath, ...], tuple[Diagnostic, ...]]:
    nodes, edges = context.acbom.nodes, context.acbom.edges
    direct = compute_direct_capability_paths(nodes, edges)
    transitive, diagnostics = compute_transitive_capability_paths(nodes, edges)
    return (*direct, *transitive), diagnostics


def _path_breaches(
    context: RuleContext,
    paths: tuple[CapabilityPath, ...],
    agents_with_ceiling: tuple[tuple[Node, CapabilityCeiling], ...],
) -> tuple[_Breach, ...]:
    node_by_id = {node.id: node for node in context.acbom.nodes}
    ceiling_by_agent_id = {agent.id: ceiling for agent, ceiling in agents_with_ceiling}

    breaches: list[_Breach] = []
    for path in sorted(
        paths, key=lambda p: (p.agent_id, p.target_id, p.hops[-1].edge_id)
    ):
        ceiling = ceiling_by_agent_id.get(path.agent_id)
        if ceiling is None:
            continue
        reason = _breach_reason(path, ceiling, node_by_id)
        if reason is None:
            continue
        offending_hop, message = reason
        agent_name = node_by_id[path.agent_id].name
        evidence = (offending_hop or path.hops[-1]).evidence
        breaches.append(
            _Breach(
                message=f"agent {agent_name!r} {message}",
                evidence=evidence,
                affected_agent=path.agent_id,
                capability_path=path,
                remediation=(
                    "narrow the discovered capability, or update the declared "
                    "capability ceiling in controlloop.yaml if this authority "
                    "is intended"
                ),
            )
        )
    return tuple(breaches)


def _bare_delegation_breaches(
    context: RuleContext,
    agents_with_ceiling: tuple[tuple[Node, CapabilityCeiling], ...],
    covered_edge_ids: frozenset[str],
) -> tuple[_Breach, ...]:
    """A disallowed `delegates-to` edge to an agent with no
    further discovered capability -- not covered by any `CapabilityPath`
    (`target_type` excludes `agent`), so `_path_breaches` above never
    sees it. Mirrors `unauthorized_delegation._disallowed_delegation_edges`'s
    identical disclosed scope boundary. `evaluate()`-only: `findings()`
    never promotes one, since there is no valid `CapabilityPath`."""

    node_by_id = {node.id: node for node in context.acbom.nodes}
    ceiling_by_agent_id = {agent.id: ceiling for agent, ceiling in agents_with_ceiling}

    breaches: list[_Breach] = []
    for edge in sorted(context.acbom.edges, key=lambda e: e.id):
        if edge.type is not EdgeType.DELEGATES_TO or edge.id in covered_edge_ids:
            continue
        ceiling = ceiling_by_agent_id.get(edge.source)
        if ceiling is None:
            continue
        target = node_by_id.get(edge.target)
        if (
            target is None
            or target.type is not NodeType.AGENT
            or target.name not in ceiling.prohibited_delegation_targets
        ):
            continue
        source_name = node_by_id[edge.source].name
        breaches.append(
            _Breach(
                message=(
                    f"agent {source_name!r} delegates to {target.name!r}, "
                    "which is a prohibited delegation target under its "
                    "capability ceiling"
                ),
                evidence=edge.evidence,
                affected_agent=edge.source,
                capability_path=None,
                remediation=(
                    "remove the delegation, or update the declared capability "
                    "ceiling in controlloop.yaml if this delegation is intended"
                ),
            )
        )
    return tuple(breaches)


def _unverifiable(
    context: RuleContext,
    paths: tuple[CapabilityPath, ...],
    diagnostics: tuple[Diagnostic, ...],
    agents_with_ceiling: tuple[tuple[Node, CapabilityCeiling], ...],
    breached_path_keys: frozenset[tuple[str, str]],
) -> tuple[_Unverifiable, ...]:
    """Every signal that this scan could not prove an agent stays
    within its declared ceiling."""

    results: list[_Unverifiable] = []

    if diagnostics:
        shared_evidence = diagnostics[0].evidence
        for agent, _ceiling in agents_with_ceiling:
            results.append(
                _Unverifiable(
                    message=(
                        f"agent {agent.name!r}'s capability ceiling could not "
                        "be fully verified: the transitive capability walk hit "
                        "a bound, so more of the graph may be unexplored"
                    ),
                    evidence=shared_evidence,
                )
            )

    ceiling_agent_ids = {agent.id for agent, _ceiling in agents_with_ceiling}
    node_by_id = {node.id: node for node in context.acbom.nodes}
    for path in paths:
        if path.agent_id not in ceiling_agent_ids:
            continue
        if (path.agent_id, path.target_id) in breached_path_keys:
            continue
        if path.confidence is not Confidence.UNKNOWN:
            continue
        agent_name = node_by_id[path.agent_id].name
        target = node_by_id.get(path.target_id)
        target_name = target.name if target is not None else path.target_id
        results.append(
            _Unverifiable(
                message=(
                    f"agent {agent_name!r}'s reach of {target_name!r} has "
                    "unknown confidence and cannot be proven within or "
                    "outside its capability ceiling"
                ),
                evidence=path.hops[-1].evidence,
            )
        )

    return tuple(results)


def _detect(
    context: RuleContext, manifest: ManifestDocument
) -> tuple[tuple[_Breach, ...], tuple[_Unverifiable, ...]]:
    agents_with_ceiling = _agents_with_declared_ceiling(context, manifest)
    if not agents_with_ceiling:
        return (), ()

    paths, diagnostics = _all_capability_paths(context)
    path_breaches = _path_breaches(context, paths, agents_with_ceiling)
    covered_edge_ids = frozenset(
        hop.edge_id
        for breach in path_breaches
        if breach.capability_path is not None
        for hop in breach.capability_path.hops
    )
    bare_breaches = _bare_delegation_breaches(
        context, agents_with_ceiling, covered_edge_ids
    )
    breaches = tuple(
        sorted(
            (*path_breaches, *bare_breaches),
            key=lambda b: (
                b.affected_agent,
                b.capability_path.target_id if b.capability_path else "",
                b.message,
            ),
        )
    )
    breached_path_keys = frozenset(
        (b.affected_agent, b.capability_path.target_id)
        for b in breaches
        if b.capability_path is not None
    )
    unverifiable = _unverifiable(
        context, paths, diagnostics, agents_with_ceiling, breached_path_keys
    )
    return breaches, unverifiable


def evaluate(context: RuleContext) -> tuple[RuleObservation, ...]:
    """Engine-compatible entry point."""

    manifest = context.manifest
    if manifest is None or not manifest.ceilings:
        return (
            RuleObservation(
                rule_id=RULE_ID,
                message=_NO_CEILING_MESSAGE,
                evidence=_NO_CEILING_EVIDENCE,
            ),
        )

    breaches, unverifiable = _detect(context, manifest)
    observations = [
        RuleObservation(rule_id=RULE_ID, message=b.message, evidence=b.evidence)
        for b in breaches
    ]
    observations.extend(
        RuleObservation(rule_id=RULE_ID, message=u.message, evidence=u.evidence)
        for u in unverifiable
    )
    return tuple(observations)


RULE = Rule(id=RULE_ID, evaluate=evaluate)


def findings(
    context: RuleContext,
    *,
    rule_version: str = RULE_VERSION,
    documentation_url_value: str = _DOCUMENTATION_URL,
) -> tuple[Finding, ...]:
    """The `Finding`-producing counterpart to `evaluate()`. Only
    breaches backed by a real `CapabilityPath` are ever promoted -- see
    `_bare_delegation_breaches`'s own docstring for the one disclosed
    gap, and this module's own docstring for why its unverifiable
    signals are never promoted (no specific breached capability)."""

    manifest = context.manifest
    if manifest is None or not manifest.ceilings:
        return ()

    breaches, _unverifiable = _detect(context, manifest)
    results: list[Finding] = []
    for b in breaches:
        path = b.capability_path
        if path is None:
            continue
        results.append(
            finding_from_observation(
                RuleObservation(
                    rule_id=RULE_ID, message=b.message, evidence=b.evidence
                ),
                rule_version=rule_version,
                severity=FindingSeverity.CRITICAL,
                confidence=path.confidence,
                affected_agent=b.affected_agent,
                capability_path=path,
                change_state=node_change_state(context.diff, path.target_id),
                remediation=b.remediation,
                documentation_url=documentation_url_value,
            )
        )
    return tuple(sorted(results, key=lambda finding: finding.id))


__all__ = [
    "RULE",
    "RULE_ID",
    "evaluate",
    "findings",
]
