"""Rule: an agent host given read and write access outside the repository.

Claude Code's `permissions.additionalDirectories` adds directories the
agent may read and write as freely as the repository itself. An entry
for the home directory, the filesystem root, or any other directory
outside the repository hands the agent files the repository's review
never covers: other projects, shell profiles, credentials. The adapter
records such a path as `<outside-repository>` and never the path itself;
a relative path that climbs out with `..` counts as outside too.

Severities: an outside directory added, or an entry changed to one,
`high`; a directory inside the repository added `low` (it widens nothing
the host could not already reach, but it is recorded); an outside
directory present on a first scan `low`; removal, narrowing, and an
inside directory on a first scan silent.

Codex's `sandbox_workspace_write.writable_roots` is not recorded by the
adapter yet, so it is not read here.
"""

from __future__ import annotations

from controlloop.acbom.models import Confidence, Node
from controlloop.findings.models import Finding, FindingChangeState, FindingSeverity
from controlloop.policy.models import Rule, RuleContext, RuleObservation
from controlloop.policy.rules import _authority as authority

RULE_ID = "policy.workspace-scope-expansion"
_RULE_VERSION = "1.0.0"

#: The adapter's marker for an absolute or home-relative path
#: (`controlloop.adapters.agent_authority.OUTSIDE_REPOSITORY_PATH`).
OUTSIDE_REPOSITORY_PATH = "<outside-repository>"

_REMEDIATION = (
    "Remove the entry, or narrow it to a path inside the repository, and "
    "prefer the agent host's sandbox for anything it must reach outside it."
    " Once reviewed, an approval in controlloop.yaml naming the component "
    "keeps the finding at info, so it no longer blocks."
)


def is_outside(node: Node) -> bool:
    path = node.attributes.get("path", "")
    return (
        path == OUTSIDE_REPOSITORY_PATH
        or path == ".."
        or path.startswith(("../", "..\\"))
    )


def _host_name(context: RuleContext, node: Node) -> str:
    host = authority.owning_host(context, node.id)
    return host.name if host is not None else "An agent host"


def findings(
    context: RuleContext,
    *,
    rule_version: str = _RULE_VERSION,
) -> tuple[Finding, ...]:
    results: list[Finding] = []
    for node in authority.nodes_with_subtype(context, "additional-directory"):
        state = authority.component_state(context, node)
        if state is None or state is FindingChangeState.REMOVED:
            continue
        outside = is_outside(node)
        before = (
            authority.baseline_node(context, node.id)
            if state is FindingChangeState.CHANGED
            else None
        )
        if before is not None and is_outside(before):
            # Outside already, or narrowed to inside: nothing new.
            continue
        host = _host_name(context, node)
        if state is FindingChangeState.NOT_COMPARED:
            if not outside:
                continue
            severity = FindingSeverity.LOW
            message = (
                f"{host} can read and write a directory outside the repository. "
                "Recorded on a scan with no baseline."
            )
        elif outside:
            severity = FindingSeverity.HIGH
            message = (
                f"{host} can now read and write a directory outside the repository."
            )
        else:
            severity = FindingSeverity.LOW
            message = f"{host} adds a directory inside the repository to its workspace."
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

__all__ = [
    "OUTSIDE_REPOSITORY_PATH",
    "RULE",
    "RULE_ID",
    "evaluate",
    "findings",
    "is_outside",
]
