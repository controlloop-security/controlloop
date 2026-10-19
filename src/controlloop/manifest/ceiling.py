"""Capability ceiling evaluation semantics and ACBOM projection.

A separate module from `reconciliation.py`, which compares a manifest
against discovery and only ever returns diagnostics; this module
*projects* a declared ceiling into real ACBOM graph content
(`policy-boundary` nodes and `constrained-by` edges), a materially
different responsibility. The evaluation semantics, documented before
implementation rather than described after the fact:

1. At most one `CapabilityCeiling` may declare a given `agent`, and at
   most one may be repository-wide (`agent` unset) -- enforced
   structurally by `ManifestDocument`'s own model validator, so
   `effective_ceiling` below never has to resolve an ambiguity itself.
2. `effective_ceiling` is the *union* of the repository-wide and the
   agent-specific ceiling's prohibitions, never an override: a
   prohibition is a floor no narrower scope can loosen.
3. `ceiling_policy_boundary_nodes_and_edges` projects the effective
   ceiling of every agent an owner actually named (via an agent-scoped
   ceiling, or implicitly via a repository-wide one) into the graph --
   but only for agents already discovered elsewhere. A ceiling naming
   an agent discovery never found produces an
   `INCOMPLETE-UNVERIFIED-DECLARATION` diagnostic instead of a
   fabricated node, reusing `reconciliation.py`'s existing diagnostic
   rather than inventing a second "unverified" concept.
4. This module stops at representing the ceiling. Deciding whether a
   specific discovered capability actually violates an effective
   ceiling, and blocking on that decision, is the capability-ceiling
   policy rule's separate job.

`propose_starter_ceiling` adds a fifth, additive responsibility:
constructing a *proposed* starter ceiling from already-discovered
nodes/edges -- the inverse direction of (3) above, which only ever
projects an already-*declared* ceiling. See that function's own
docstring for the derivation rules; see `manifest.draft` for how the
proposal is rendered into `controlloop.yaml`'s hand-commented YAML.
"""

from __future__ import annotations

from dataclasses import dataclass

from controlloop.acbom import (
    Confidence,
    Diagnostic,
    Edge,
    EdgeIdentityMaterial,
    EdgeStatus,
    EdgeType,
    Evidence,
    Node,
    NodeIdentityMaterial,
    NodeType,
    SecurityAttributes,
    SemanticIdentity,
    edge_id,
    node_id,
)
from controlloop.capability.compute import compute_effective_authority
from controlloop.manifest.models import CapabilityCeiling, ManifestDocument
from controlloop.manifest.reconciliation import manifest_evidence, unverified_diagnostic

_NAMESPACE = "manifest.ceiling"

#: The three `EffectiveAuthorityEntry.action` values a starter ceiling
#: can propose prohibiting -- a fixed, closed universe, iterated in this
#: constant order rather than accumulated from input, so the proposal is
#: deterministic regardless of node/edge order.
_PROPOSABLE_ACTIONS: tuple[EdgeType, ...] = (
    EdgeType.READS,
    EdgeType.WRITES,
    EdgeType.INVOKES,
)

#: `EffectiveAuthorityEntry`/edge confidence levels a starter proposal
#: surfaces separately rather than silently granting.
_LOW_CONFIDENCE: frozenset[Confidence] = frozenset({Confidence.LOW, Confidence.UNKNOWN})

#: (field name on CapabilityCeiling, node subtype it projects to)
_CATEGORY_SUBTYPES: tuple[tuple[str, str], ...] = (
    ("prohibited_resources", "ceiling-prohibited-resources"),
    ("prohibited_actions", "ceiling-prohibited-actions"),
    ("prohibited_external_destinations", "ceiling-prohibited-external-destinations"),
    ("prohibited_data_classes", "ceiling-prohibited-data-classes"),
    ("prohibited_delegation_targets", "ceiling-prohibited-delegation-targets"),
)


def _union[T: str](left: tuple[T, ...], right: tuple[T, ...]) -> tuple[T, ...]:
    return tuple(sorted(set(left) | set(right)))


def effective_ceiling(agent_name: str, manifest: ManifestDocument) -> CapabilityCeiling:
    """The ceiling that actually applies to `agent_name`: the union of
    the repository-wide ceiling's prohibitions (if declared) and that
    agent's own ceiling's prohibitions (if declared)."""

    repository_wide = next((c for c in manifest.ceilings if c.agent is None), None)
    agent_specific = next((c for c in manifest.ceilings if c.agent == agent_name), None)
    repository_wide = repository_wide or CapabilityCeiling()
    agent_specific = agent_specific or CapabilityCeiling()

    return CapabilityCeiling(
        agent=agent_name,
        prohibited_resources=_union(
            repository_wide.prohibited_resources, agent_specific.prohibited_resources
        ),
        prohibited_actions=_union(
            repository_wide.prohibited_actions, agent_specific.prohibited_actions
        ),
        prohibited_external_destinations=_union(
            repository_wide.prohibited_external_destinations,
            agent_specific.prohibited_external_destinations,
        ),
        prohibited_data_classes=_union(
            repository_wide.prohibited_data_classes,
            agent_specific.prohibited_data_classes,
        ),
        prohibited_delegation_targets=_union(
            repository_wide.prohibited_delegation_targets,
            agent_specific.prohibited_delegation_targets,
        ),
    )


def _policy_boundary_node(
    agent_node: Node,
    field_name: str,
    subtype: str,
    manifest_path: str,
    evidence: tuple[Evidence, ...],
) -> Node:
    identity_material = NodeIdentityMaterial(
        node_type=NodeType.POLICY_BOUNDARY,
        namespace=_NAMESPACE,
        semantic_identity=SemanticIdentity(
            source_path=manifest_path,
            in_document_key=f"ceiling:{agent_node.name}:{field_name}",
        ),
    )
    return Node(
        id=node_id(identity_material),
        type=NodeType.POLICY_BOUNDARY,
        subtype=subtype,
        name=f"{agent_node.name}: {field_name}",
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=evidence,
    )


def _constrained_by_edge(
    agent_node: Node,
    boundary_node: Node,
    field_name: str,
    evidence: tuple[Evidence, ...],
) -> Edge:
    edge_material = EdgeIdentityMaterial(
        relationship_type=EdgeType.CONSTRAINED_BY,
        source_id=agent_node.id,
        target_id=boundary_node.id,
        relationship_discriminator=f"ceiling:{field_name}",
    )
    return Edge(
        id=edge_id(edge_material),
        source=agent_node.id,
        target=boundary_node.id,
        type=EdgeType.CONSTRAINED_BY,
        status=EdgeStatus.DIRECT,
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=evidence,
    )


def ceiling_policy_boundary_nodes_and_edges(
    manifest: ManifestDocument,
    nodes: tuple[Node, ...],
    *,
    manifest_path: str = "controlloop.yaml",
) -> tuple[tuple[Node, ...], tuple[Edge, ...], tuple[Diagnostic, ...]]:
    """Projects every agent's effective ceiling into `policy-boundary`
    nodes and `constrained-by` edges: one node/edge pair per non-empty
    prohibition category, for every agent named by an agent-scoped
    ceiling plus -- if a repository-wide ceiling is declared -- every
    already-discovered agent. An agent named by a ceiling but never
    discovered produces a diagnostic instead of a fabricated node."""

    if not manifest.ceilings:
        return (), (), ()

    evidence = manifest_evidence(manifest_path)
    agents_by_name = {node.name: node for node in nodes if node.type is NodeType.AGENT}
    named_agents = {
        ceiling.agent for ceiling in manifest.ceilings if ceiling.agent is not None
    }
    repository_wide_declared = any(
        ceiling.agent is None for ceiling in manifest.ceilings
    )

    target_agent_names = set(named_agents)
    if repository_wide_declared:
        target_agent_names |= set(agents_by_name)

    boundary_nodes: list[Node] = []
    boundary_edges: list[Edge] = []
    diagnostics: list[Diagnostic] = []

    for agent_name in sorted(target_agent_names):
        agent_node = agents_by_name.get(agent_name)
        if agent_node is None:
            diagnostics.append(
                unverified_diagnostic(
                    evidence,
                    "a capability ceiling names an agent discovery did not find",
                )
            )
            continue

        ceiling = effective_ceiling(agent_name, manifest)
        for field_name, subtype in _CATEGORY_SUBTYPES:
            if not getattr(ceiling, field_name):
                continue
            boundary_node = _policy_boundary_node(
                agent_node, field_name, subtype, manifest_path, evidence
            )
            boundary_nodes.append(boundary_node)
            boundary_edges.append(
                _constrained_by_edge(agent_node, boundary_node, field_name, evidence)
            )

    return tuple(boundary_nodes), tuple(boundary_edges), tuple(diagnostics)


@dataclass(frozen=True, slots=True)
class LowConfidenceAction:
    """One direct action (`reads`/`writes`/`invokes`) the starter
    ceiling proposal observed only at `Confidence.LOW` or
    `Confidence.UNKNOWN` -- excluded from `prohibited_actions`
    (prohibiting something this scan actually observed, even at low
    confidence, could immediately conflict with this same scan) and
    never silently treated as a confidently reviewed grant either.
    Carried separately so `manifest.draft` can disclose it for human
    review."""

    agent_name: str
    action: EdgeType
    resource_name: str
    confidence: Confidence


@dataclass(frozen=True, slots=True)
class LowConfidenceDelegation:
    """One `delegates-to` edge the starter ceiling proposal observed
    only at `Confidence.LOW` or `Confidence.UNKNOWN` -- same treatment
    as `LowConfidenceAction`, for delegation targets instead of
    actions."""

    agent_name: str
    target_name: str
    confidence: Confidence


@dataclass(frozen=True, slots=True)
class StarterCeilingProposal:
    """A starter capability ceiling proposal derived from current direct
    effective authority. `ceilings` are real, schema-valid
    `CapabilityCeiling` entries. Every value in them names something
    this scan found *zero* evidence of, at any confidence, so adopting
    `ceilings` unchanged cannot conflict with anything this same scan
    observed. `low_confidence_actions`/`low_confidence_delegations` are
    the separately-disclosed, not-silently-granted low-confidence
    observations. `manifest.ceiling` never proposes
    `prohibited_resources`, `prohibited_external_destinations`, or
    `prohibited_data_classes` -- see `propose_starter_ceiling`'s own
    docstring for why those three categories are structurally different
    from the two this proposal does derive."""

    ceilings: tuple[CapabilityCeiling, ...]
    low_confidence_actions: tuple[LowConfidenceAction, ...]
    low_confidence_delegations: tuple[LowConfidenceDelegation, ...]


def propose_starter_ceiling(
    agent_nodes: tuple[Node, ...],
    nodes: tuple[Node, ...],
    edges: tuple[Edge, ...],
) -> StarterCeilingProposal:
    """Propose a starter capability ceiling from already-discovered
    `nodes`/`edges` -- the same discovery `init` already gathered,
    exactly like `manifest.draft`'s own trust-boundary pre-fill.
    `agent_nodes` must already be filtered to the `AGENT` nodes whose
    `Node.name` satisfies the manifest's `SafeIdentifier` character
    class (the same filter `render_draft_manifest` applies before it can
    use a name as a real `agents:` value) -- a ceiling's own `agent`
    field carries that same constraint, so this function never
    re-derives the filter itself; the caller is expected to pass the
    identical already-filtered list it uses for `trust_boundaries`.

    For each such agent, proposes:

    - `prohibited_actions`: every one of `reads`/`writes`/`invokes`
      `compute_effective_authority` found *no* direct evidence this
      agent takes, at any confidence. An action is only proposed as
      prohibited when this scan observed zero evidence of it, so
      adopting the proposal unchanged cannot conflict with anything this
      scan actually found.
    - `prohibited_delegation_targets`: every other discovered,
      safely-identified agent this agent was not observed
      (`delegates-to`, any confidence) to delegate to. Same reasoning as
      above, restricted to the finite, closed universe of
      already-discovered agents.

    An agent for which both proposed categories are empty (it already
    exercises every tracked action type, and there is no other agent to
    restrict delegation to) gets no `CapabilityCeiling` entry at all --
    an entry with nothing in it would be noise, not a proposal.

    `prohibited_resources`, `prohibited_external_destinations`, and
    `prohibited_data_classes` are never proposed: unlike the two
    categories above, whose universe is the closed, finite set of action
    types or already-discovered agents, these three describe an
    open-world "everything that is not this" -- a resource never
    touched, a domain never contacted, a data class never seen -- that
    static repository discovery has no way to enumerate. Leaving them
    unset here is not this function's silent choice to omit them:
    `manifest.draft` renders them with an explicit comment disclosing
    that this analysis could not cover them, so the gap reads as
    incomplete, not as a considered "nothing to prohibit" answer.

    An action or delegation edge found only at `Confidence.LOW` or
    `Confidence.UNKNOWN` is excluded from both
    `prohibited_actions`/`prohibited_delegation_targets` (prohibiting it
    could immediately conflict with an unchanged repository) and from
    being silently treated as a confidently reviewed grant: it is
    instead returned in
    `low_confidence_actions`/`low_confidence_delegations` for separate
    human review.

    Deterministic: every collection here is built from sorted keys or a
    fixed constant iteration order, independent of `nodes`/`edges` input
    order, mirroring `render_draft_manifest`'s own determinism.
    """

    if not agent_nodes:
        return StarterCeilingProposal((), (), ())

    agent_names = {node.name for node in agent_nodes}
    agent_ids = {node.id for node in agent_nodes}
    agent_name_by_id = {node.id: node.name for node in agent_nodes}
    node_name_by_id = {node.id: node.name for node in nodes}

    observed_actions: dict[str, set[EdgeType]] = {}
    low_confidence_actions: list[LowConfidenceAction] = []
    for entry in compute_effective_authority(nodes, edges):
        agent_name = agent_name_by_id.get(entry.agent_id)
        if agent_name is None:
            continue
        observed_actions.setdefault(agent_name, set()).add(entry.action)
        if entry.confidence in _LOW_CONFIDENCE:
            low_confidence_actions.append(
                LowConfidenceAction(
                    agent_name=agent_name,
                    action=entry.action,
                    resource_name=node_name_by_id.get(
                        entry.resource_id, entry.resource_id
                    ),
                    confidence=entry.confidence,
                )
            )

    observed_delegations: dict[str, set[str]] = {}
    low_confidence_delegations: list[LowConfidenceDelegation] = []
    for edge in edges:
        if edge.type is not EdgeType.DELEGATES_TO or edge.source not in agent_ids:
            continue
        target_name = agent_name_by_id.get(edge.target)
        if target_name is None:
            continue
        source_name = agent_name_by_id[edge.source]
        observed_delegations.setdefault(source_name, set()).add(target_name)
        if edge.confidence in _LOW_CONFIDENCE:
            low_confidence_delegations.append(
                LowConfidenceDelegation(
                    agent_name=source_name,
                    target_name=target_name,
                    confidence=edge.confidence,
                )
            )

    ceilings: list[CapabilityCeiling] = []
    for agent_name in sorted(agent_names):
        prohibited_actions = tuple(
            action
            for action in _PROPOSABLE_ACTIONS
            if action not in observed_actions.get(agent_name, set())
        )
        prohibited_delegation_targets = tuple(
            sorted(
                other
                for other in agent_names
                if other != agent_name
                and other not in observed_delegations.get(agent_name, set())
            )
        )
        if prohibited_actions or prohibited_delegation_targets:
            ceilings.append(
                CapabilityCeiling(
                    agent=agent_name,
                    prohibited_actions=prohibited_actions,
                    prohibited_delegation_targets=prohibited_delegation_targets,
                )
            )

    return StarterCeilingProposal(
        ceilings=tuple(ceilings),
        low_confidence_actions=tuple(
            sorted(
                low_confidence_actions,
                key=lambda observation: (
                    observation.agent_name,
                    str(observation.action),
                    observation.resource_name,
                ),
            )
        ),
        low_confidence_delegations=tuple(
            sorted(
                low_confidence_delegations,
                key=lambda observation: (
                    observation.agent_name,
                    observation.target_name,
                ),
            )
        ),
    )
