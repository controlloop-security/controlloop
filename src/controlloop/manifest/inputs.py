"""Applies `ManifestDocument.external_inputs` onto discovered agent nodes.

## Why this exists

The exfiltration-triangle rule (`controlloop.policy.rules.
exfiltration_triangle`) reads an agent's untrusted-input leg from a
`receives-from` edge. Discovery can produce that edge for an
agent-running workflow (the event that starts it) and, as an inference,
for an A2A card that publishes an endpoint. Nothing in a repository
states that a support agent is wired to a public inbox, a webhook or a
chat channel: that is a fact only the repository's authors know, the
same way nothing states that issuing a refund moves money
(`annotation.py`). So, as with `tool_capabilities`, the repository
declares it, and the declaration is authoritative.

## What it does and does not do

- For each declaration, every `NodeType.AGENT` node whose `name` equals
  `declaration.agent` gains one `NodeType.TRIGGER` node (subtype
  `declared-external-input`, named after the source) and one
  `receives-from` edge from the agent to it. The trigger carries
  `untrusted_input=True` and `trusted=False`: a declared external input
  is untrusted by definition, which is what the declaration means.
- Matching is by `Node.name`, the same human-writable identifier
  `tool_capabilities`, `logged_tools` and the capability-ceiling rule
  already match on.
- A declaration naming an agent discovery did not find yields an
  `unverified` diagnostic, never a silent no-op.
- Node and edge IDs are content-addressed from the manifest path and the
  declaration itself, so the same declaration always produces the same
  IDs and two scans of the same commit agree byte for byte.
- Discovered nodes and edges are never changed or removed: this module
  only ever adds, exactly like `annotation.py`.

Pure and deterministic: no clock, no filesystem, no network, no
randomness. `controlloop.bom.build_acbom_document` is the only caller.
"""

from __future__ import annotations

from controlloop.acbom import (
    Confidence,
    Diagnostic,
    Edge,
    EdgeStatus,
    EdgeType,
    Evidence,
    Node,
    NodeType,
    SecurityAttributes,
)
from controlloop.acbom.identity import (
    EdgeIdentityMaterial,
    NodeIdentityMaterial,
    SemanticIdentity,
    edge_id,
    node_id,
)
from controlloop.manifest.models import ExternalInputDeclaration, ManifestDocument
from controlloop.manifest.reconciliation import unverified_diagnostic

#: Identity namespace for nodes the manifest declares into existence,
#: distinct from every adapter's namespace so a declared trigger can
#: never collide with a discovered one.
_NAMESPACE = "manifest"
_SUBTYPE = "declared-external-input"
_DISCRIMINATOR = "declared-external-input"


def _trigger_node(
    declaration: ExternalInputDeclaration,
    manifest_path: str,
    evidence: tuple[Evidence, ...],
) -> Node:
    material = NodeIdentityMaterial(
        node_type=NodeType.TRIGGER,
        namespace=_NAMESPACE,
        semantic_identity=SemanticIdentity(
            source_path=manifest_path,
            in_document_key=f"external_inputs:{declaration.agent}:{declaration.source}",
        ),
    )
    return Node(
        id=node_id(material),
        type=NodeType.TRIGGER,
        subtype=_SUBTYPE,
        name=declaration.source,
        security_attributes=SecurityAttributes(untrusted_input=True, trusted=False),
        confidence=Confidence.HIGH,
        evidence=evidence,
    )


def _receives_from_edge(
    agent: Node, trigger: Node, evidence: tuple[Evidence, ...]
) -> Edge:
    material = EdgeIdentityMaterial(
        relationship_type=EdgeType.RECEIVES_FROM,
        source_id=agent.id,
        target_id=trigger.id,
        relationship_discriminator=_DISCRIMINATOR,
    )
    return Edge(
        id=edge_id(material),
        source=agent.id,
        target=trigger.id,
        type=EdgeType.RECEIVES_FROM,
        status=EdgeStatus.DIRECT,
        security_attributes=SecurityAttributes(untrusted_input=True, trusted=False),
        confidence=Confidence.HIGH,
        evidence=evidence,
    )


def declare_external_inputs(
    nodes: tuple[Node, ...],
    edges: tuple[Edge, ...],
    manifest: ManifestDocument | None,
    manifest_path: str,
    evidence: tuple[Evidence, ...],
) -> tuple[tuple[Node, ...], tuple[Edge, ...], tuple[Diagnostic, ...]]:
    """Return `nodes` and `edges` extended with one trigger node and one
    `receives-from` edge per (declaration, matching agent) pair, plus one
    `unverified` diagnostic per declaration naming an agent discovery
    did not find.

    `manifest` of `None`, or a manifest declaring no external inputs,
    returns both tuples unchanged and no diagnostics, so a repository
    that declares nothing produces a byte-identical ACBOM to one built
    before this feature existed.
    """

    if manifest is None or not manifest.external_inputs:
        return nodes, edges, ()

    agents_by_name: dict[str, list[Node]] = {}
    for node in nodes:
        if node.type is NodeType.AGENT:
            agents_by_name.setdefault(node.name, []).append(node)

    added_nodes: list[Node] = []
    added_edges: list[Edge] = []
    seen_nodes: set[str] = {node.id for node in nodes}
    seen_edges: set[str] = {edge.id for edge in edges}
    unmatched: list[str] = []
    for declaration in manifest.external_inputs:
        agents = agents_by_name.get(declaration.agent)
        if not agents:
            unmatched.append(declaration.agent)
            continue
        trigger = _trigger_node(declaration, manifest_path, evidence)
        if trigger.id not in seen_nodes:
            seen_nodes.add(trigger.id)
            added_nodes.append(trigger)
        for agent in agents:
            edge = _receives_from_edge(agent, trigger, evidence)
            if edge.id not in seen_edges:
                seen_edges.add(edge.id)
                added_edges.append(edge)

    diagnostics = tuple(
        unverified_diagnostic(
            evidence,
            "a declared external input names an agent discovery did not find",
        )
        for _ in sorted(set(unmatched))
    )
    return (*nodes, *added_nodes), (*edges, *added_edges), diagnostics
