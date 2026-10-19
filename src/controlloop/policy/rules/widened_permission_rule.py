"""Rule: an agent's allow rules widened.

An allow rule is a standing pre-approval: the agent runs what it matches
without asking. A pull request that replaces `Bash(npm test)` with
`Bash(*)` reads as a one-line change and hands the agent every shell
command. This rule reports an added rule that is a wildcard or covers a
baseline rule it does not equal, and a rule changed to cover its old
pattern. A narrowed rule, a removed rule, a new `deny` or `ask`, and an
identical rule moved between files are silent. Severities are decisions
D3 and D4 (#434): widening `high`; on a first scan, wildcard rules
`low`. The owner amended D3 on 2026-10-17 after the E18.10 benign corpus
(#444): a rule for a read-only tool (`Read`, `Grep`, `Glob`, and the
Gemini CLI equivalents) is `medium`, since it cannot run, change, or send
anything. A shell rule stays `high` however narrow its prefix looks:
`Bash(npm run:*)` runs any script in a file the same pull request can
edit.
"""

from __future__ import annotations

from controlloop.acbom.models import Confidence, EdgeType, Node
from controlloop.findings.models import Finding, FindingChangeState, FindingSeverity
from controlloop.policy.models import Rule, RuleContext, RuleObservation
from controlloop.policy.rules import _authority as authority

RULE_ID = "policy.widened-permission-rule"
_RULE_VERSION = "1.0.0"
#: Rules held directly by these are standing pre-approvals. Grants a
#: skill or subagent makes itself are `policy.component-self-grant`'s.
_HOLDERS = frozenset({"host", "workflow-runtime"})
#: Tools that only read the workspace (decision D3 as amended, #444).
READ_ONLY_TOOLS = frozenset(
    {
        "Read",
        "Grep",
        "Glob",
        "LS",
        "NotebookRead",
        "read_file",
        "read_many_files",
        "glob",
        "search_file_content",
        "list_directory",
    }
)

_REMEDIATION = (
    "Narrow the rule to the specific commands or tools the agent needs "
    "(for example `Bash(npm test)` rather than `Bash(*)`)."
    " Once reviewed, an approval in controlloop.yaml naming the component "
    "keeps the finding at info, so it no longer blocks."
)


def _holder(context: RuleContext, node: Node) -> Node | None:
    by_id = {item.id: item for item in context.acbom.nodes}
    for edge in authority.edges_into(context, node.id):
        holder = by_id.get(edge.source)
        if (
            edge.type is EdgeType.PERMITTED_BY
            and holder is not None
            and holder.subtype in _HOLDERS
        ):
            return holder
    return None


def _baseline_allow_rules(context: RuleContext, holder_id: str) -> list[Node]:
    """Allow rules the holder had in the baseline: the current ones that
    did not change, plus the ones the diff shows as removed or changed."""

    changes = authority.node_changes(context)
    rules: list[Node] = []
    for node in authority.nodes_with_subtype(context, "permission-rule"):
        if node.attributes.get("effect") != "allow" or node.id in changes:
            continue
        holder = _holder(context, node)
        if holder is not None and holder.id == holder_id:
            rules.append(node)
    # A removed or changed rule's holder is not in the current graph; its
    # baseline form is compared whatever held it.
    for change in changes.values():
        before = change.before
        if (
            before is not None
            and before.subtype == "permission-rule"
            and before.attributes.get("effect") == "allow"
        ):
            rules.append(before)
    return rules


def findings(
    context: RuleContext,
    *,
    rule_version: str = _RULE_VERSION,
) -> tuple[Finding, ...]:
    results: list[Finding] = []
    removed_patterns = {
        (node.attributes.get("pattern"), node.attributes.get("tool"))
        for node in authority.removed_nodes(context, "permission-rule")
        if node.attributes.get("effect") == "allow"
    }
    for node in authority.nodes_with_subtype(context, "permission-rule"):
        if node.attributes.get("effect") != "allow":
            continue
        holder = _holder(context, node)
        if holder is None:
            continue
        state = authority.component_state(context, node)
        if state is None or state is FindingChangeState.REMOVED:
            continue
        pattern = node.attributes.get("pattern", "")
        wildcard = node.security_attributes.wildcard is True
        widening = (
            FindingSeverity.MEDIUM
            if node.attributes.get("tool") in READ_ONLY_TOOLS
            else FindingSeverity.HIGH
        )
        if state is FindingChangeState.NOT_COMPARED:
            if not wildcard:
                continue
            severity = FindingSeverity.LOW
            message = (
                f"Allow rule '{pattern}' for '{holder.name}' is a wildcard. "
                "Recorded on a scan with no baseline."
            )
        elif state is FindingChangeState.ADDED:
            if (pattern, node.attributes.get("tool")) in removed_patterns:
                continue  # the same rule moved between files
            covered = [
                rule.attributes.get("pattern", "")
                for rule in _baseline_allow_rules(context, holder.id)
                if rule.attributes.get("pattern") != pattern
                and authority.rule_covers(pattern, rule.attributes.get("pattern", ""))
            ]
            if not wildcard and not covered:
                continue
            severity = widening
            if covered:
                listed = authority.first_line(repr(item) for item in sorted(covered))
                message = (
                    f"Allow rule '{pattern}' for '{holder.name}' is a superset of the "
                    f"baseline's {listed}."
                )
            else:
                message = f"Allow rule '{pattern}' for '{holder.name}' is a wildcard."
        else:
            before = authority.baseline_node(context, node.id)
            old = before.attributes.get("pattern", "") if before is not None else ""
            if old == pattern or not authority.rule_covers(pattern, old):
                continue
            severity = widening
            message = (
                f"Allow rule for '{holder.name}' widened from '{old}' to '{pattern}'."
            )
        results.append(
            authority.build_finding(
                rule_id=RULE_ID,
                rule_version=rule_version,
                message=message,
                node=node,
                context=context,
                severity=severity,
                confidence=Confidence.HIGH,
                change_state=state,
                remediation=_REMEDIATION,
            )
        )
    return tuple(sorted(results, key=lambda finding: finding.id))


def evaluate(context: RuleContext) -> tuple[RuleObservation, ...]:
    return authority.observations(findings(context))


RULE = Rule(id=RULE_ID, evaluate=evaluate, reads_agent_authority=True)

__all__ = ["READ_ONLY_TOOLS", "RULE", "RULE_ID", "evaluate", "findings"]
