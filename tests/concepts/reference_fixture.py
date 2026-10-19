"""Reference ACBOM fixture and text generators for
`docs/concepts/acbom.md`.

`docs/concepts/acbom.md` used to describe every node type, every edge
type, a direct capability path, and a transitive capability path with
hand-typed example text. Hand-typed examples drift from the real model
constraints and the real traversal algorithms silently -- nothing would
fail if a field name, an edge direction, or a hop count in the doc
stopped matching what the code actually does.

This module builds one connected, real `Node`/`Edge` fixture -- a
`refund-agent` reference scenario continuing the naming the project's
other worked examples already established -- covering every `NodeType`
and every `EdgeType`
at least once (`TestFixtureCoverage` in
`tests/concepts/test_acbom_concepts_doc.py` asserts this), and renders
each generated fragment of the doc directly from
that fixture and from real calls to
`compute_direct_capability_paths`/`compute_transitive_capability_paths`
-- never hand-typed prose.

Each `render_*` function below produces exactly one fragment embedded
in `docs/concepts/acbom.md` between a matching pair of
`<!-- BEGIN GENERATED: <name> -->`/`<!-- END GENERATED: <name> -->`
markers. `tests/concepts/test_acbom_concepts_doc.py` asserts every
marked region stays byte-for-byte identical to a fresh call to its
generator, the same "golden" discipline
`test_packaged_schema_matches_its_golden_digest` already established
for the packaged ACBOM schema.

Run directly to print every generated fragment by name, for example
when the fixture changes and the doc needs regenerating:

    uv run python tests/concepts/reference_fixture.py
"""

from __future__ import annotations

import re

from controlloop.acbom import (
    Confidence,
    Diagnostic,
    DiagnosticSeverity,
    Edge,
    EdgeStatus,
    EdgeType,
    Evidence,
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

_EVIDENCE = (Evidence(adapter="mcp", path="agents/refund-agent.json"),)


def _node(
    node_id: str,
    node_type: NodeType,
    name: str,
    *,
    security_attributes: SecurityAttributes | None = None,
) -> Node:
    return Node(
        id=node_id,
        type=node_type,
        name=name,
        security_attributes=security_attributes or SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=_EVIDENCE,
    )


def _edge(edge_id: str, edge_type: EdgeType, source: str, target: str) -> Edge:
    return Edge(
        id=edge_id,
        source=source,
        target=target,
        type=edge_type,
        status=EdgeStatus.DIRECT,
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=_EVIDENCE,
    )


REFUND_AGENT = _node(f"clp:agent:sha256:{'a' * 64}", NodeType.AGENT, "refund-agent")
ESCALATION_AGENT = _node(
    f"clp:agent:sha256:{'b' * 64}", NodeType.AGENT, "escalation-agent"
)
REFUND_TOOL = _node(f"clp:tool:sha256:{'c' * 64}", NodeType.TOOL, "refund-tool")
BILLING_DB = _node(
    f"clp:resource:sha256:{'d' * 64}",
    NodeType.RESOURCE,
    "billing-db",
    security_attributes=SecurityAttributes(
        destructive=True, sensitivity=Sensitivity.RESTRICTED
    ),
)
SERVICE_ACCOUNT = _node(
    f"clp:identity:sha256:{'e' * 64}", NodeType.IDENTITY, "service-account"
)
REFUND_WRITE = _node(
    f"clp:permission:sha256:{'f' * 64}", NodeType.PERMISSION, "refund:write"
)
CUSTOMER_PII = _node(
    f"clp:data-class:sha256:{'1' * 64}", NodeType.DATA_CLASS, "customer-pii"
)
SUPPORT_TICKET_CREATED = _node(
    f"clp:trigger:sha256:{'2' * 64}", NodeType.TRIGGER, "support-ticket-created"
)
FINANCE_BOUNDARY = _node(
    f"clp:policy-boundary:sha256:{'3' * 64}",
    NodeType.POLICY_BOUNDARY,
    "finance-boundary",
)

NODES: tuple[Node, ...] = (
    REFUND_AGENT,
    ESCALATION_AGENT,
    REFUND_TOOL,
    BILLING_DB,
    SERVICE_ACCOUNT,
    REFUND_WRITE,
    CUSTOMER_PII,
    SUPPORT_TICKET_CREATED,
    FINANCE_BOUNDARY,
)

EDGES: tuple[Edge, ...] = (
    _edge(
        f"clp:edge:sha256:{'1' * 64}",
        EdgeType.INVOKES,
        REFUND_AGENT.id,
        REFUND_TOOL.id,
    ),
    _edge(
        f"clp:edge:sha256:{'2' * 64}",
        EdgeType.WRITES,
        REFUND_AGENT.id,
        BILLING_DB.id,
    ),
    _edge(
        f"clp:edge:sha256:{'3' * 64}",
        EdgeType.READS,
        REFUND_TOOL.id,
        CUSTOMER_PII.id,
    ),
    _edge(
        f"clp:edge:sha256:{'4' * 64}",
        EdgeType.AUTHENTICATES_AS,
        REFUND_AGENT.id,
        SERVICE_ACCOUNT.id,
    ),
    _edge(
        f"clp:edge:sha256:{'5' * 64}",
        EdgeType.PERMITTED_BY,
        SERVICE_ACCOUNT.id,
        REFUND_WRITE.id,
    ),
    _edge(
        f"clp:edge:sha256:{'6' * 64}",
        EdgeType.DELEGATES_TO,
        REFUND_AGENT.id,
        ESCALATION_AGENT.id,
    ),
    _edge(
        f"clp:edge:sha256:{'7' * 64}",
        EdgeType.RECEIVES_FROM,
        REFUND_AGENT.id,
        SUPPORT_TICKET_CREATED.id,
    ),
    _edge(
        f"clp:edge:sha256:{'8' * 64}",
        EdgeType.CONSTRAINED_BY,
        REFUND_AGENT.id,
        FINANCE_BOUNDARY.id,
    ),
)

#: One node per `NodeType`, in the same order `NodeType` itself declares
#: them, so "each node type explained with a concrete example"
#: is checked structurally, not just by eyeballing the fixture above.
_NODE_BY_TYPE: dict[NodeType, Node] = {}
for _node_instance in NODES:
    _NODE_BY_TYPE.setdefault(_node_instance.type, _node_instance)

#: One edge per `EdgeType`, same discipline as `_NODE_BY_TYPE` above.
_EDGE_BY_TYPE: dict[EdgeType, Edge] = {}
for _edge_instance in EDGES:
    _EDGE_BY_TYPE.setdefault(_edge_instance.type, _edge_instance)


_NODE_BY_ID: dict[str, Node] = {node.id: node for node in NODES}

#: One short, human blurb per node type naming the fixture node that
#: illustrates it, in `NodeType` declaration order.
_NODE_DESCRIPTIONS: dict[NodeType, str] = {
    NodeType.AGENT: "the agent that receives and processes refund requests",
    NodeType.TOOL: f"the tool `{REFUND_AGENT.name}` invokes to carry out a refund",
    NodeType.RESOURCE: (
        f"the destructive, `{Sensitivity.RESTRICTED.value}`-sensitivity resource "
        f"`{REFUND_AGENT.name}` writes to"
    ),
    NodeType.IDENTITY: f"the identity `{REFUND_AGENT.name}` authenticates as",
    NodeType.PERMISSION: (
        f"the permission scope `{SERVICE_ACCOUNT.name}` is permitted by"
    ),
    NodeType.DATA_CLASS: (
        f"the data classification `{REFUND_TOOL.name}` reads while looking up "
        "the account"
    ),
    NodeType.TRIGGER: f"the inbound event `{REFUND_AGENT.name}` receives from",
    NodeType.POLICY_BOUNDARY: (
        f"the policy boundary `{REFUND_AGENT.name}` is constrained by"
    ),
}


def render_node_examples() -> str:
    """Every node type, with a concrete example drawn from the
    real fixture above, in `NodeType` declaration order."""

    lines = [
        f"- **{node_type.value}**: `{_NODE_BY_TYPE[node_type].name}` -- "
        f"{_NODE_DESCRIPTIONS[node_type]}."
        for node_type in NodeType
    ]
    return "\n".join(lines)


def render_edge_examples() -> str:
    """Every edge type, rendered as `source -type-> target` directly
    from the real fixture `Edge`/`Node` objects, in `EdgeType`
    declaration order."""

    lines = []
    for edge_type in EdgeType:
        edge = _EDGE_BY_TYPE[edge_type]
        source_name = _NODE_BY_ID[edge.source].name
        target_name = _NODE_BY_ID[edge.target].name
        lines.append(f"- `{source_name}` -{edge_type.value}-> `{target_name}`")
    return "\n".join(lines)


def _render_hop_chain(agent_name: str, path: CapabilityPath) -> str:
    lines = [agent_name]
    for hop in path.hops:
        target_name = _NODE_BY_ID[hop.target_id].name
        lines.append(f"  -> {hop.edge_type.value} -> {target_name}")
    return "\n".join(lines)


def render_direct_path_example() -> str:
    """A real one-hop `CapabilityPath`, computed by
    `compute_direct_capability_paths` on the fixture above, not typed
    by hand."""

    paths = compute_direct_capability_paths(NODES, EDGES)
    (path,) = (
        path
        for path in paths
        if path.agent_id == REFUND_AGENT.id and path.target_id == REFUND_TOOL.id
    )
    return _render_hop_chain(REFUND_AGENT.name, path)


def render_transitive_path_example() -> str:
    """A real two-hop `CapabilityPath`, computed by
    `compute_transitive_capability_paths` on the fixture above.
    `refund-agent` has no direct edge to `refund:write`; the path below
    only exists because the transitive walk chains
    `authenticates-as` -> `permitted-by` across `service-account`."""

    paths, _diagnostics = compute_transitive_capability_paths(NODES, EDGES)
    (path,) = (
        path
        for path in paths
        if path.agent_id == REFUND_AGENT.id and path.target_id == REFUND_WRITE.id
    )
    return _render_hop_chain(REFUND_AGENT.name, path)


def render_unknown_example() -> str:
    """A real `Diagnostic` instance, not a hand-typed string,
    showing what an unresolved discovery looks like: `incomplete=True`
    and `confidence=unknown`, never a silently dropped capability."""

    diagnostic = Diagnostic(
        code="INCOMPLETE-DYNAMIC-REGISTRATION",
        severity=DiagnosticSeverity.WARNING,
        message=(
            "a dynamically registered tool could not be resolved to a concrete identity"
        ),
        confidence=Confidence.UNKNOWN,
        incomplete=True,
        evidence=_EVIDENCE,
    )
    return (
        f"{diagnostic.code} (confidence: {diagnostic.confidence.value})\n"
        f"  {diagnostic.message}"
    )


#: Every generated fragment, keyed by the marker name used in
#: `docs/concepts/acbom.md` (`<!-- BEGIN GENERATED: <key> -->`). The
#: single source of truth both the doc-sync test and the `__main__`
#: regeneration helper below iterate over.
GENERATED_FRAGMENTS: dict[str, str] = {
    "node-examples": render_node_examples(),
    "edge-examples": render_edge_examples(),
    "direct-path-example": render_direct_path_example(),
    "transitive-path-example": render_transitive_path_example(),
    "unknown-example": render_unknown_example(),
}


_MARKER_PATTERN = re.compile(
    r"<!-- BEGIN GENERATED: (?P<name>[a-z-]+) -->\n"
    r"(?P<body>.*?)"
    r"\n<!-- END GENERATED: (?P=name) -->",
    re.DOTALL,
)


def extract_generated_fragments(doc_text: str) -> dict[str, str]:
    """Every `<!-- BEGIN GENERATED: name -->`/`<!-- END GENERATED: name
    -->` region in `doc_text`, keyed by marker name, body exactly as
    written between the two marker lines -- compares directly against
    `GENERATED_FRAGMENTS`. Raises `ValueError` on a marker name repeated
    in the document, since that can only mean two fragments collapsed
    onto one name by mistake."""

    fragments: dict[str, str] = {}
    for match in _MARKER_PATTERN.finditer(doc_text):
        name = match.group("name")
        if name in fragments:
            raise ValueError(f"duplicate generated marker {name!r} in document")
        fragments[name] = match.group("body")
    return fragments


if __name__ == "__main__":
    for _name, _text in GENERATED_FRAGMENTS.items():
        print(f"--- {_name} ---")
        print(_text)
        print()
