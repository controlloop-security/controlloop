"""Rule: unauthorized delegation.

Depends on A2A delegation edges (the `delegates-to` edge type, exercised
by discovery), the `controlloop.yaml` manifest's
`allowed_delegation`/`trust_boundaries` fields, and the finding model.
See this package's own `missing_action_logging` module docstring for the
shared two-layer `evaluate()`/`findings()` design these rules use.

**`controlloop.manifest.reconciliation.reconcile_manifest` already flags
an `allowed_delegation` entry an agent *has* that discovery contradicts,
as a `MANIFEST-CONTRADICTS-DISCOVERY` diagnostic.** This rule is
deliberately broader and produces a different artifact: it also flags a
`delegates-to` edge from an agent with **no** `allowed_delegation` entry
at all (reconciliation stays silent in that case, since it only ever
compares against an explicit declaration), it adds
trust-boundary-crossing severity elevation (which reconciliation has no
concept of), and it reports through the policy/finding layer rather than
a bare `Diagnostic`. The two are independent, non-duplicative checks
over the same manifest fields.

**Disclosed scope boundary (`findings()` only, not `evaluate()`):**
`Finding.capability_path` is `controlloop.capability.models.
CapabilityPath`, whose `target_type` is closed to `tool`, `resource`,
`identity`, `permission`, and `data-class` -- deliberately excluding
`agent`. A bare `delegates-to` edge to a disallowed agent that itself
has **no** further discovered capability therefore has no valid
`CapabilityPath` to attach a `Finding` to under the current,
already-shipped schema. `evaluate()`'s `RuleObservation`s cover every
disallowed `delegates-to` edge unconditionally (no `CapabilityPath`
required); `findings()` covers exactly the delegation chains that reach
a real capability beyond the disallowed target (the realistic,
materially risky case -- an agent with zero further capabilities is not
yet a capability expansion), via `compute_transitive_capability_paths`.
This gap is recorded once here; closing it fully would mean widening
`CapabilityPath.target_type`, an architecture change.
"""

from __future__ import annotations

from controlloop.acbom.models import Edge, EdgeType, Node, NodeType
from controlloop.capability.compute import compute_transitive_capability_paths
from controlloop.capability.models import PathHop
from controlloop.findings.models import (
    Finding,
    FindingSeverity,
    finding_from_observation,
)
from controlloop.manifest.models import ManifestDocument
from controlloop.policy.models import Rule, RuleContext, RuleObservation
from controlloop.policy.rules._shared import documentation_url, node_change_state

RULE_ID = "policy.unauthorized-delegation"
_RULE_VERSION = "1.0.0"
_DOCUMENTATION_URL = documentation_url(RULE_ID)


def _allowed_targets(
    manifest: ManifestDocument | None, agent_name: str
) -> frozenset[str]:
    """The delegation targets `agent_name` is affirmatively allowed to
    reach, per `manifest.allowed_delegation`. Empty when no manifest is
    supplied, or when the agent has no entry at all -- absence of a
    declared allowed set is never treated as "everything is allowed"
    (this codebase's "evidence over declarations" invariant); it means
    every discovered `delegates-to` edge from that agent is reported,
    without this rule raising or otherwise failing."""

    if manifest is None:
        return frozenset()
    for allowed in manifest.allowed_delegation:
        if allowed.agent == agent_name:
            return frozenset(allowed.targets)
    return frozenset()


def _shares_a_declared_trust_boundary(
    manifest: ManifestDocument, source_name: str, target_name: str
) -> bool:
    """Only ever called by `_is_elevated` below, after it has already
    confirmed `manifest` is not `None` -- no redundant `None` guard
    here, since that branch would be structurally unreachable and
    therefore untestable."""

    return any(
        source_name in boundary.agents and target_name in boundary.agents
        for boundary in manifest.trust_boundaries
    )


def _disallowed_delegation_edges(
    context: RuleContext,
) -> tuple[tuple[Edge, Node, Node], ...]:
    """Every `delegates-to` edge whose source is an `AGENT` node and
    whose target -- by name -- is outside that agent's allowed
    delegation set. Deterministically ordered by edge ID."""

    nodes_by_id = {node.id: node for node in context.acbom.nodes}
    agent_ids = {node.id for node in context.acbom.nodes if node.type is NodeType.AGENT}

    results: list[tuple[Edge, Node, Node]] = []
    for edge in context.acbom.edges:
        if edge.type is not EdgeType.DELEGATES_TO:
            continue
        if edge.source not in agent_ids or edge.target not in nodes_by_id:
            continue
        source = nodes_by_id[edge.source]
        target = nodes_by_id[edge.target]
        if target.name in _allowed_targets(context.manifest, source.name):
            continue
        results.append((edge, source, target))

    return tuple(sorted(results, key=lambda item: item[0].id))


def _is_elevated(context: RuleContext, source: Node, target: Node) -> bool:
    """Elevated when trust boundaries are declared at all and the
    delegating and target agent do not share one. With no trust
    boundary declared anywhere, "outside a declared trust boundary" is
    not a meaningful claim, so severity is never elevated on that basis
    alone."""

    manifest = context.manifest
    if manifest is None or not manifest.trust_boundaries:
        return False
    return not _shares_a_declared_trust_boundary(manifest, source.name, target.name)


def _observation_message(source: Node, target: Node, elevated: bool) -> str:
    boundary_clause = " and crosses a declared trust boundary" if elevated else ""
    return (
        f"agent {source.name!r} delegates to {target.name!r}, which is not in "
        f"its declared allowed-delegation set{boundary_clause}; add "
        f"{target.name!r} to {source.name!r}'s `allowed_delegation` targets in "
        "controlloop.yaml if this delegation is intended"
    )


def evaluate(context: RuleContext) -> tuple[RuleObservation, ...]:
    """One `RuleObservation` per disallowed `delegates-to` edge,
    evidenced by the edge's own evidence."""

    observations = []
    for edge, source, target in _disallowed_delegation_edges(context):
        elevated = _is_elevated(context, source, target)
        observations.append(
            RuleObservation(
                rule_id=RULE_ID,
                message=_observation_message(source, target, elevated),
                evidence=edge.evidence,
            )
        )
    return tuple(observations)


RULE = Rule(id=RULE_ID, evaluate=evaluate)


def _offending_hop(
    path_hops: tuple[PathHop, ...],
    disallowed_by_edge_id: dict[str, tuple[Edge, Node, Node]],
) -> tuple[Edge, Node, Node] | None:
    for hop in path_hops:
        if hop.edge_id in disallowed_by_edge_id:
            return disallowed_by_edge_id[hop.edge_id]
    return None


def findings(
    context: RuleContext,
    *,
    rule_version: str = _RULE_VERSION,
    documentation_url_value: str = _DOCUMENTATION_URL,
) -> tuple[Finding, ...]:
    """The `Finding`-producing counterpart to `evaluate()` (the "full
    chain," this module's own docstring): every bounded transitive
    capability path whose hop chain contains at least one disallowed
    `delegates-to` edge produces one `Finding`, `capability_path.hops`
    carrying the complete chain from the origin agent through the
    disallowed delegate to the real capability reached. When a chain
    contains more than one disallowed hop, the first (closest to the
    origin agent) names the finding's own message and remediation; the
    full chain is still reported via `capability_path`."""

    disallowed = _disallowed_delegation_edges(context)
    if not disallowed:
        return ()
    disallowed_by_edge_id = {
        edge.id: (edge, source, target) for edge, source, target in disallowed
    }

    paths, _diagnostics = compute_transitive_capability_paths(
        context.acbom.nodes, context.acbom.edges
    )

    results: list[Finding] = []
    for path in paths:
        offending = _offending_hop(path.hops, disallowed_by_edge_id)
        if offending is None:
            continue
        _edge, source, target = offending
        elevated = _is_elevated(context, source, target)
        severity = FindingSeverity.HIGH if elevated else FindingSeverity.MEDIUM
        observation = RuleObservation(
            rule_id=RULE_ID,
            message=_observation_message(source, target, elevated),
            evidence=path.hops[-1].evidence,
        )
        results.append(
            finding_from_observation(
                observation,
                rule_version=rule_version,
                severity=severity,
                confidence=path.confidence,
                affected_agent=path.agent_id,
                capability_path=path,
                change_state=node_change_state(context.diff, path.target_id),
                remediation=(
                    f"add {target.name!r} to {source.name!r}'s "
                    "`allowed_delegation` targets in controlloop.yaml if this "
                    "delegation is intended, or remove the delegation"
                ),
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
