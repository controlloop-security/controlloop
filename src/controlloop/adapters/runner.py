"""Runs a set of adapters and aggregates their output deterministically.

An adapter that raises is isolated: the scan continues, and the
failure becomes an `INCOMPLETE-ADAPTER-FAILURE` diagnostic rather than
crashing the whole run. The aggregated result does not depend on adapter
execution order: `merge_duplicate_nodes`/`merge_duplicate_edges`
combine same-ID contributions from different adapters,
and this module explicitly sorts the merged output by `id` afterward,
since the merge functions themselves preserve first-seen input order,
not a sorted order.
"""

from __future__ import annotations

from collections.abc import Sequence

from controlloop.acbom import (
    Diagnostic,
    Evidence,
    Node,
    incomplete_diagnostic,
    merge_duplicate_edges,
    merge_duplicate_nodes,
)
from controlloop.adapters.agent_authority import is_host_reference
from controlloop.adapters.framework import (
    DiscoveryAdapter,
    DiscoveryResult,
    ScanContext,
)
from controlloop.adapters.sandbox import adapter_sandbox

_MAX_FAILURE_EVIDENCE = 32
_NO_CLAIM_MARKER = "<adapter-detect-failure>"


def _adapter_failure_diagnostic(
    adapter: DiscoveryAdapter,
    error: Exception,
    *,
    claimed_paths: Sequence[str],
) -> Diagnostic:
    """`claimed_paths` are the adapter's own already-validated claims
    when `discover` failed; the bracket marker (matching the escaping
    convention established for synthetic, non-repository-path
    evidence) is used when `detect` itself failed, before any claim was
    known."""

    paths = claimed_paths[:_MAX_FAILURE_EVIDENCE] or (_NO_CLAIM_MARKER,)
    return incomplete_diagnostic(
        code="INCOMPLETE-ADAPTER-FAILURE",
        message=(
            f"adapter {adapter.name!r} failed during detection or "
            f"discovery ({type(error).__name__})"
        ),
        evidence=tuple(Evidence(adapter=adapter.name, path=path) for path in paths),
    )


def _run_one_adapter(
    adapter: DiscoveryAdapter, context: ScanContext
) -> DiscoveryResult:
    try:
        with adapter_sandbox():
            detection = adapter.detect(context)
    except Exception as error:
        return DiscoveryResult(
            diagnostics=(_adapter_failure_diagnostic(adapter, error, claimed_paths=()),)
        )

    if not detection.claimed_paths:
        return DiscoveryResult()

    try:
        with adapter_sandbox():
            return adapter.discover(context)
    except Exception as error:
        return DiscoveryResult(
            diagnostics=(
                _adapter_failure_diagnostic(
                    adapter, error, claimed_paths=detection.claimed_paths
                ),
            )
        )


_MAX_NODE_EVIDENCE = 32


def _fold_host_references(nodes: list[Node]) -> list[Node]:
    """Fold host references into the full host node with the same ID.

    A host reference (`agent_authority.host_reference_node`) is emitted
    by an adapter that connects something to a host another adapter
    owns. Its evidence joins the full node's; when no full node exists,
    one reference is kept, with every reference's evidence.
    """

    references: dict[str, list[Node]] = {}
    full_ids: set[str] = set()
    for node in nodes:
        if is_host_reference(node):
            references.setdefault(node.id, []).append(node)
        elif node.subtype == "host":
            full_ids.add(node.id)
    if not references:
        return nodes

    def merged_evidence(*groups: tuple[Evidence, ...]) -> tuple[Evidence, ...]:
        combined = dict.fromkeys(item for group in groups for item in group)
        return tuple(combined)[:_MAX_NODE_EVIDENCE]

    folded: list[Node] = []
    kept_reference: set[str] = set()
    for node in nodes:
        if is_host_reference(node):
            if node.id in full_ids or node.id in kept_reference:
                continue
            kept_reference.add(node.id)
            group = references[node.id]
            folded.append(
                node.model_copy(
                    update={
                        "evidence": merged_evidence(*(item.evidence for item in group))
                    }
                )
            )
        elif node.subtype == "host" and node.id in references:
            folded.append(
                node.model_copy(
                    update={
                        "evidence": merged_evidence(
                            node.evidence,
                            *(item.evidence for item in references[node.id]),
                        )
                    }
                )
            )
        else:
            folded.append(node)
    return folded


def run_adapters(
    adapters: Sequence[DiscoveryAdapter], context: ScanContext
) -> DiscoveryResult:
    """Run every adapter, isolating failures, and return one deterministic
    aggregate result independent of `adapters`' order."""

    results = [_run_one_adapter(adapter, context) for adapter in adapters]

    all_nodes = [node for result in results for node in result.nodes]
    all_edges = [edge for result in results for edge in result.edges]
    all_diagnostics = [
        diagnostic for result in results for diagnostic in result.diagnostics
    ]

    merged_nodes = tuple(
        sorted(
            merge_duplicate_nodes(_fold_host_references(all_nodes)),
            key=lambda node: node.id,
        )
    )
    merged_edges = tuple(
        sorted(merge_duplicate_edges(all_edges), key=lambda edge: edge.id)
    )
    sorted_diagnostics = tuple(
        sorted(
            all_diagnostics,
            key=lambda diagnostic: (diagnostic.code, diagnostic.evidence[0].path or ""),
        )
    )

    return DiscoveryResult(
        nodes=merged_nodes,
        edges=merged_edges,
        diagnostics=sorted_diagnostics,
    )
