"""CycloneDX 1.6 export.

Implements the reduced projection documented in
`docs/reference/cyclonedx-export-format.md`: the exported BOM never
carries `Evidence.path`/`line_start`/`line_end`/`parser`/`schema_id`,
`Diagnostic` records, or `Node`/`Edge` `confidence` grades -- this
module never reads those fields from the ACBOM at all, so the excluded
fields are absent by construction, not by a filtering step that could
regress.

CycloneDX 1.6 has no agent-specific component taxonomy:
`NodeType.AGENT` projects to `component.type: "application"`,
`NodeType.TOOL` to `"library"` (an invocable capability the agent
depends on), and `NodeType.RESOURCE` to `"data"`. Every other node
type (`identity`, `permission`, `data-class`, `trigger`,
`policy-boundary`) and every edge type other than a plain
dependency-shaped relationship (`invokes`, `reads`, `writes`,
`receives-from`) has no CycloneDX representation at all -- reported as
a lossy-export diagnostic string, never silently dropped.

No timestamp is embedded anywhere in the output: `metadata.timestamp`
is optional in the CycloneDX schema, and omitting it keeps identical
input producing an identical canonical digest, the same determinism
invariant every other `controlloop.reporting` module already
preserves.
"""

from __future__ import annotations

from controlloop.acbom.models import ACBOMDocument, EdgeType, NodeType

CYCLONEDX_SPEC_VERSION = "1.6"
CYCLONEDX_BOM_FORMAT = "CycloneDX"

_NODE_TYPE_TO_COMPONENT_TYPE: dict[NodeType, str] = {
    NodeType.AGENT: "application",
    NodeType.TOOL: "library",
    NodeType.RESOURCE: "data",
}

_EDGE_TYPES_AS_DEPENDENCY: frozenset[EdgeType] = frozenset(
    {EdgeType.INVOKES, EdgeType.READS, EdgeType.WRITES, EdgeType.RECEIVES_FROM}
)


def render_cyclonedx(
    document: ACBOMDocument,
) -> tuple[dict[str, object], tuple[str, ...]]:
    """Return `(bom, lossy_export_diagnostics)`.

    `bom` is a complete CycloneDX 1.6 BOM document. Every string in
    `lossy_export_diagnostics` names one node or edge from `document`
    that has no CycloneDX representation -- returned as data, not
    printed, so a caller decides how to surface it (the CLI reports a
    count on stderr, mirroring the existing completeness-summary
    precedent).
    """

    lossy: list[str] = []
    components: list[dict[str, object]] = []
    projected_ids: set[str] = set()

    for node in document.nodes:
        component_type = _NODE_TYPE_TO_COMPONENT_TYPE.get(node.type)
        if component_type is None:
            lossy.append(
                f"node {node.id} of type {node.type.value!r} has no "
                "CycloneDX component representation"
            )
            continue
        components.append(
            {"type": component_type, "bom-ref": node.id, "name": node.name}
        )
        projected_ids.add(node.id)

    dependencies_by_ref: dict[str, list[str]] = {}
    for edge in document.edges:
        if edge.type not in _EDGE_TYPES_AS_DEPENDENCY:
            lossy.append(
                f"edge {edge.id} of type {edge.type.value!r} has no "
                "CycloneDX dependency representation"
            )
            continue
        if edge.source not in projected_ids or edge.target not in projected_ids:
            lossy.append(
                f"edge {edge.id} connects a node with no CycloneDX "
                "component representation"
            )
            continue
        dependencies_by_ref.setdefault(edge.source, []).append(edge.target)

    bom: dict[str, object] = {
        "bomFormat": CYCLONEDX_BOM_FORMAT,
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "version": 1,
        "metadata": {
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": document.generator.name,
                        "version": document.generator.version,
                    }
                ]
            }
        },
    }
    if components:
        bom["components"] = components
    if dependencies_by_ref:
        bom["dependencies"] = [
            {"ref": ref, "dependsOn": sorted(set(targets))}
            for ref, targets in sorted(dependencies_by_ref.items())
        ]

    return bom, tuple(lossy)
