"""Keep coding-agent host authority away from rules that predate it.

The ACBOM records coding-agent hosts: Claude Code and its peers as
agents, with their hooks, helper commands, plugins, skills, subagents,
permission rules, and the CI workflows that run them. The rules written
before hosts were recorded were designed for the agents a repository
*ships*. Applied to a coding-agent host they misfire: every formatter
hook is a "privileged tool with no declared logging path", and a
repository's first scan would be blocked on authority it has always had.
That contradicts two design rules: a first scan is never blocked on
agent authority alone, and a benign corpus produces no blocked verdict.

So a rule sees agent-authority components only when it says it reads
them (`controlloop.policy.models.Rule.reads_agent_authority`). Every
other rule receives a view of the same evidence with those components,
the edges touching them, and the diff entries about them removed. A
document with no such components -- every document produced before
hosts were recorded -- is passed through unchanged, so existing
results are byte-identical.

Which components count is the canonical vocabulary,
`controlloop.acbom.AuthoritySubtype`, not anything format-specific. MCP
servers are not authority components: they predate host recording and
keep being evaluated as before. An MCP server reachable only from a
coding-agent host is, in the filtered view, reachable from nothing,
exactly as it was before the host was recorded.
"""

from __future__ import annotations

from dataclasses import replace

from controlloop.acbom import ACBOMDocument, AuthoritySubtype, Node
from controlloop.diff.models import DiffResult
from controlloop.policy.models import RuleContext

_AUTHORITY_SUBTYPES = frozenset(subtype.value for subtype in AuthoritySubtype)


def is_agent_authority_component(node: Node | None) -> bool:
    return node is not None and node.subtype in _AUTHORITY_SUBTYPES


def _filtered_document(document: ACBOMDocument, ids: set[str]) -> ACBOMDocument:
    return document.model_copy(
        update={
            "nodes": tuple(node for node in document.nodes if node.id not in ids),
            "edges": tuple(
                edge
                for edge in document.edges
                if edge.source not in ids and edge.target not in ids
            ),
        }
    )


def _filtered_diff(diff: DiffResult, ids: set[str]) -> DiffResult:
    def touches(edge: object) -> bool:
        return edge is not None and (
            getattr(edge, "source", None) in ids or getattr(edge, "target", None) in ids
        )

    return diff.model_copy(
        update={
            "node_changes": tuple(
                change for change in diff.node_changes if change.node_id not in ids
            ),
            "edge_changes": tuple(
                change
                for change in diff.edge_changes
                if not touches(change.before) and not touches(change.after)
            ),
            "effective_authority_changes": tuple(
                change
                for change in diff.effective_authority_changes
                if change.agent_id not in ids and change.resource_id not in ids
            ),
        }
    )


def without_agent_authority(context: RuleContext) -> RuleContext:
    """Return `context` with every agent-authority component removed, or
    `context` itself when there is none to remove."""

    ids = {
        node.id for node in context.acbom.nodes if is_agent_authority_component(node)
    }
    if context.diff is not None:
        for change in context.diff.node_changes:
            if is_agent_authority_component(
                change.before
            ) or is_agent_authority_component(change.after):
                ids.add(change.node_id)
    if not ids:
        return context
    return replace(
        context,
        acbom=_filtered_document(context.acbom, ids),
        diff=_filtered_diff(context.diff, ids) if context.diff is not None else None,
    )
