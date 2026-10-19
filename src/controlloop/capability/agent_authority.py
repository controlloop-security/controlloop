"""Agent-authority facts the blast-radius statement and the policy rules
share.

A workflow runtime is over-privileged when the agent it runs holds a
write token (`contents`, `pull-requests`, or `id-token`) and skips its
permission prompts, or is triggered by untrusted input with no explicit
`permissions` block (so its token is whatever the repository default
grants). `policy.overprivileged-agent-workflow` reports the change;
`controlloop.capability.blast_radius` names the runtime in the worst
reachable action. One definition keeps the two from disagreeing.

The same goes for approvals: the authority statement says "Approval
recorded." for a component, and the agent-authority rules lower its
finding so it does not block, by one shared notion of which approval
names which component.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from controlloop.acbom.models import Confidence, Node
from controlloop.manifest.models import Approval

WRITE_SCOPES = (
    ("contents_write", "contents: write"),
    ("pull_requests_write", "pull-requests: write"),
    ("id_token_write", "id-token: write"),
)


def overprivileged_workflow_reason(
    attributes: Mapping[str, str],
) -> tuple[str, Confidence] | None:
    """Why a workflow runtime is over-privileged, with the confidence of
    that reading, or `None` when it is not."""

    writes = [label for key, label in WRITE_SCOPES if attributes.get(key) == "true"]
    skips = attributes.get("skip_permissions") == "true"
    untrusted = bool(attributes.get("untrusted_events"))
    unknown_permissions = attributes.get("job_permissions") == "unknown"
    if writes and skips:
        return (
            f"holds {', '.join(writes)} and skips permission prompts",
            Confidence.HIGH,
        )
    if untrusted and unknown_permissions:
        return (
            f"runs on untrusted input ({attributes['untrusted_events']}) with no "
            "explicit permissions block, so its token is the repository default",
            Confidence.MEDIUM,
        )
    return None


def component_label(node: Node) -> str:
    """The component's own name: adapters prefix skill, subagent, plugin,
    and marketplace names with their kind (`subagent fixer`)."""

    prefix = f"{node.subtype} "
    if node.subtype and node.name.startswith(prefix):
        return node.name[len(prefix) :]
    return node.name


def granting_path(node: Node) -> str:
    """The file that granted the power. A host node carries evidence from
    every file that mentions it; its own settings are the evidence its
    own adapter recorded."""

    paths = [item for item in node.evidence if item.path is not None]
    if node.subtype == "host":
        own = [item for item in paths if item.adapter == node.attributes.get("host")]
        paths = own or paths
    return str(paths[0].path) if paths else "unknown"


def approval_keys(node: Node) -> frozenset[str]:
    """Every `capability` value an approval may use to name this
    component: `<file>#<key path>`, its name with or without its kind,
    or its node ID."""

    key_path = node.attributes.get("key_path", node.name)
    return frozenset(
        {
            f"{granting_path(node)}#{key_path}",
            node.name,
            component_label(node),
            node.id,
        }
    )


def approval_for(node: Node, approvals: Iterable[Approval]) -> Approval | None:
    """The first approval in `approvals` that names `node`, or `None`.
    The caller passes only approvals active at evaluation time."""

    keys = approval_keys(node)
    return next(
        (approval for approval in approvals if str(approval.capability) in keys),
        None,
    )


__all__ = [
    "WRITE_SCOPES",
    "approval_for",
    "approval_keys",
    "component_label",
    "granting_path",
    "overprivileged_workflow_reason",
]
