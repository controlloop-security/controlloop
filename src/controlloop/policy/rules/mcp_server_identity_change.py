"""Rule: an MCP server whose identity changed behind an unchanged name.

The postmark-mcp backdoor shipped in version 1.0.16 after fifteen clean
releases; the configuration that installed it named the same server
every time. A server node's ID is its declaring file and name, so a
changed package, command, or declaration keeps the ID and shows here as
changed. Severities: a changed package, version, or command `high`; any
other changed identity field `medium`; a newly added server `medium`;
no finding on a first scan.
"""

from __future__ import annotations

from controlloop.acbom.models import Confidence
from controlloop.findings.models import Finding, FindingChangeState, FindingSeverity
from controlloop.policy.models import Rule, RuleContext, RuleObservation
from controlloop.policy.rules import _authority as authority

RULE_ID = "policy.mcp-server-identity-change"
_RULE_VERSION = "1.0.0"
_SUBTYPES = ("mcp-server-stdio", "mcp-server-http")
_TOP_FIELDS = ("command", "package", "package_version", "package_registry")
_IDENTITY_FIELDS = (
    *_TOP_FIELDS,
    "args",
    "transport",
    "url_host",
    "env_names",
    "header_names",
    "declaration_digest",
    "tools_digest",
)

_REMEDIATION = (
    "Confirm the new package, version, or command is the one you intend to "
    "run and pin it to an exact version or digest, or revert the change."
    " Once reviewed, an approval in controlloop.yaml naming the component "
    "keeps the finding at info, so it no longer blocks."
)


def _value(node_attributes: dict[str, str], field: str) -> str:
    return node_attributes.get(field, "none")


def findings(
    context: RuleContext,
    *,
    rule_version: str = _RULE_VERSION,
) -> tuple[Finding, ...]:
    results: list[Finding] = []
    for node in authority.nodes_with_subtype(context, *_SUBTYPES):
        state = authority.component_state(context, node)
        if state is None or state in (
            FindingChangeState.NOT_COMPARED,
            FindingChangeState.REMOVED,
        ):
            continue
        package = node.attributes.get("package")
        version = node.attributes.get("package_version")
        launch = (
            f"{package}@{version}"
            if package and version
            else node.attributes.get("command", "a remote endpoint")
        )
        if state is FindingChangeState.ADDED:
            severity = FindingSeverity.MEDIUM
            message = f"Server '{node.name}' is new; it launches {launch}."
        else:
            before = authority.baseline_node(context, node.id)
            if before is None:
                continue
            changed = [
                field
                for field in _IDENTITY_FIELDS
                if _value(before.attributes, field) != _value(node.attributes, field)
            ]
            if not changed:
                continue
            severity = (
                FindingSeverity.HIGH
                if any(field in _TOP_FIELDS for field in changed)
                else FindingSeverity.MEDIUM
            )
            details = []
            for field in changed:
                if field in ("declaration_digest", "tools_digest"):
                    details.append(field.replace("_", " "))
                else:
                    details.append(
                        f"{field.replace('_', ' ')} from "
                        f"'{_value(before.attributes, field)}' to "
                        f"'{_value(node.attributes, field)}'"
                    )
            message = (
                f"Server '{node.name}' kept its name but its identity changed: "
                f"{authority.first_line(details)}."
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

__all__ = ["RULE", "RULE_ID", "evaluate", "findings"]
