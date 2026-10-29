"""Rule: a remote MCP server that carries a credential to an external host.

An HTTP or SSE MCP server declared with an `Authorization` header or a
token variable sends that credential to the server's host on every
request the agent makes. A pull request that adds such a server, adds a
credential to one, or points one at a new host decides where a
credential goes. `policy.mcp-server-identity-change` sees the same-name
swap; this rule says what the server carries.

A credential is recognized by its header or variable **name**, never its
value (the adapter never reads values): `authorization`,
`proxy-authorization`, `x-api-key`, `api-key`, or a name ending in
`_token`, `_secret`, `_key`, `_password`, `_credential`, or `_apikey`,
case-insensitively. A stdio server never fires here: its environment
goes to a local process, which `policy.mcp-server-identity-change`
covers.

Severities: a credentialed server added `medium`; a credentialed server
whose host changed `high` (the credential now goes somewhere else); a
credential name added to an existing server `medium`; first scan `low`;
removal and anything else silent. There is no allowlist of trusted
hosts; a reviewed server is approved in `controlloop.yaml`.
"""

from __future__ import annotations

from controlloop.acbom.models import Confidence, Node
from controlloop.findings.models import Finding, FindingChangeState, FindingSeverity
from controlloop.policy.models import Rule, RuleContext, RuleObservation
from controlloop.policy.rules import _authority as authority

RULE_ID = "policy.credentialed-remote-mcp-server"
_RULE_VERSION = "1.0.0"

#: Header or variable names that are a credential whatever their prefix.
CREDENTIAL_NAMES = frozenset(
    {"authorization", "proxy-authorization", "x-api-key", "api-key"}
)
#: Name endings that mark a credential.
CREDENTIAL_SUFFIXES = (
    "_token",
    "_secret",
    "_key",
    "_password",
    "_credential",
    "_apikey",
)

_REMEDIATION = (
    "Keep the credential in the agent host's own secret store rather than "
    "in the committed declaration, pin the server, and confirm the host is "
    "one you trust with it."
    " Once reviewed, an approval in controlloop.yaml naming the component "
    "keeps the finding at info, so it no longer blocks."
)


def is_credential_name(name: str) -> bool:
    lowered = name.strip().lower()
    return lowered in CREDENTIAL_NAMES or lowered.endswith(CREDENTIAL_SUFFIXES)


def credential_names(node: Node) -> list[str]:
    """The credential-shaped header and variable names `node` declares."""

    names: set[str] = set()
    for attribute in ("header_names", "env_names"):
        names.update(
            name.strip()
            for name in node.attributes.get(attribute, "").split(",")
            if is_credential_name(name)
        )
    return sorted(names)


def _host(node: Node) -> str:
    return node.attributes.get("url_host", "an unknown host")


def findings(
    context: RuleContext,
    *,
    rule_version: str = _RULE_VERSION,
) -> tuple[Finding, ...]:
    results: list[Finding] = []
    for node in authority.nodes_with_subtype(context, "mcp-server-http"):
        names = credential_names(node)
        if not names:
            continue
        state = authority.component_state(context, node)
        if state is None or state is FindingChangeState.REMOVED:
            continue
        host = _host(node)
        if state is FindingChangeState.NOT_COMPARED:
            severity = FindingSeverity.LOW
            message = (
                f"MCP server '{node.name}' sends {', '.join(names)} to {host}. "
                "Recorded on a scan with no baseline."
            )
        elif state is FindingChangeState.ADDED:
            severity = FindingSeverity.MEDIUM
            message = f"MCP server '{node.name}' sends {', '.join(names)} to {host}."
        else:
            before = authority.baseline_node(context, node.id)
            if before is None:
                continue
            before_names = set(credential_names(before))
            if before.attributes.get("url_host") != node.attributes.get("url_host"):
                severity = FindingSeverity.HIGH
                message = (
                    f"MCP server '{node.name}' now sends {', '.join(names)} to "
                    f"{host}, previously {_host(before)}."
                )
            else:
                added = [name for name in names if name not in before_names]
                if not added:
                    continue
                severity = FindingSeverity.MEDIUM
                message = (
                    f"MCP server '{node.name}' now also sends {', '.join(added)} "
                    f"to {host}."
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

__all__ = [
    "CREDENTIAL_NAMES",
    "CREDENTIAL_SUFFIXES",
    "RULE",
    "RULE_ID",
    "credential_names",
    "evaluate",
    "findings",
    "is_credential_name",
]
