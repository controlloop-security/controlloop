"""Shared building blocks for the environment adapters.

The devcontainer, pre-commit, and editor startup adapters read the files
that install tools and run commands when a repository is opened,
rebuilt, or committed to. None of those tools is a coding agent, but
what they install and run executes with the same authority on every
developer machine and CI runner, so they are recorded in the shapes the
agent-authority rules already read:

- a thing that is installed (an editor extension, a devcontainer
  feature, a pre-commit hook repository, a JetBrains plugin) is a
  `plugin` component whose `source_type` names its kind and whose
  `pinned` flag says whether the reference can change upstream without
  a change to this repository. `policy.unpinned-agent-component` reads
  it, and a changed version or digest is a changed `ref`;
- a command that runs is a `helper-command` with the setting that
  declares it, the command through `agent_authority.command_text`, and
  an `event` naming when it runs. `policy.agent-hook-command-change`
  reads it, and `script_digest` tracks a committed script it names, for
  `policy.hook-script-changed`.

Each tool is one host node, so a finding names the tool that runs the
command. Nothing is executed, fetched, or resolved: a reference is
recorded as written.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

from controlloop.acbom import (
    Diagnostic,
    Edge,
    EdgeType,
    Evidence,
    KnownBoolean,
    Node,
    NodeType,
    SecurityAttributes,
    host_node_id,
)
from controlloop.adapters import agent_authority as aa
from controlloop.adapters.claude_code import ComponentDiscovery
from controlloop.adapters.framework import DiscoveryResult

#: `major.minor.patch` with an optional semver pre-release and build
#: suffix: a version that names exactly one published build.
_EXACT_VERSION = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)


def is_exact_version(value: str) -> bool:
    """Whether `value` is a full three-part version, never a range, a
    floating major or minor, or a channel such as `latest`."""

    return _EXACT_VERSION.fullmatch(value) is not None


class EnvironmentHost:
    """One tool's accumulated discovery across the files that configure it.

    The host node is emitted only when at least one component or command
    was found, so a file with nothing to report adds nothing to the
    graph.
    """

    def __init__(self, key: str, display_name: str, adapter: str) -> None:
        self.key = key
        self.display_name = display_name
        self.adapter = adapter
        self.host_id = host_node_id(key)
        self.nodes: list[Node] = []
        self.edges: list[Edge] = []
        self.diagnostics: list[Diagnostic] = []
        self.evidence: list[Evidence] = []
        self.attributes: dict[str, str] = {}

    def file(self, relative_path: str) -> ComponentDiscovery:
        return ComponentDiscovery(relative_path, self.host_id, adapter=self.adapter)

    def take(self, found: ComponentDiscovery) -> None:
        if found.nodes:
            self.evidence.extend(found.evidence)
        self.nodes.extend(found.nodes)
        self.edges.extend(found.edges)
        self.diagnostics.extend(found.diagnostics)

    def note(self, found: ComponentDiscovery, key: str, values: list[str]) -> None:
        """Record `values` under the host attribute `key`, joined with
        those other files recorded, so the host carries them."""

        if not values:
            return
        existing = self.attributes.get(key, "")
        merged = sorted({*filter(None, existing.split(",")), *values})
        self.attributes[key] = aa.authority_text(",".join(merged))
        self.evidence.extend(found.evidence)

    def result(self) -> DiscoveryResult:
        if not self.nodes and not self.attributes:
            return DiscoveryResult(diagnostics=tuple(self.diagnostics))
        host = aa.host_node(
            host=self.key,
            display_name=self.display_name,
            evidence=self.evidence,
            attributes=self.attributes,
            bypass_mode=None,
        )
        return DiscoveryResult(
            nodes=(*self.nodes, host),
            edges=tuple(self.edges),
            diagnostics=tuple(self.diagnostics),
        )


def merge(*results: DiscoveryResult) -> DiscoveryResult:
    return DiscoveryResult(
        nodes=tuple(node for result in results for node in result.nodes),
        edges=tuple(edge for result in results for edge in result.edges),
        diagnostics=tuple(item for result in results for item in result.diagnostics),
    )


def installed_component(
    found: ComponentDiscovery,
    *,
    kind: str,
    namespace: str,
    component_key: str,
    name: str,
    pinned: KnownBoolean,
    attributes: Mapping[str, str],
    installs: bool = True,
) -> Node:
    """A thing the tool installs, as a `plugin` component.

    `kind` becomes `source_type`, which the unpinned rule prints and
    compares. `installs` is false for a recommendation the tool only
    suggests: the host `receives-from` it rather than `invokes` it, so it
    is held by the tool that suggests it without being reachable as a
    capability.
    """

    node = aa.component_node(
        node_type=NodeType.TOOL,
        subtype="plugin",
        namespace=namespace,
        declaring_path=found.path,
        component_key=component_key,
        name=name,
        attributes={"source_type": kind, **attributes},
        security_attributes=SecurityAttributes(pinned=pinned, code_execution="unknown"),
        evidence=found.evidence,
    )
    found.nodes.append(node)
    found.link(
        node.id, EdgeType.INVOKES if installs else EdgeType.RECEIVES_FROM, component_key
    )
    return node


def startup_command(
    found: ComponentDiscovery,
    *,
    namespace: str,
    setting: str,
    command: str,
    event: str,
    component_key: str,
    attributes: Mapping[str, str] | None = None,
) -> Node:
    """A command the tool runs, as a `helper-command` invoked by the host.

    `command` must already have been through
    `agent_authority.command_text` (or be a repository path).
    """

    node = aa.component_node(
        node_type=NodeType.TOOL,
        subtype="helper-command",
        namespace=namespace,
        declaring_path=found.path,
        component_key=component_key,
        name=f"{setting} command",
        attributes={
            "setting": aa.authority_text(setting),
            "command": command,
            "event": aa.authority_text(event),
            **(attributes or {}),
        },
        security_attributes=SecurityAttributes(code_execution=True),
        evidence=found.evidence,
    )
    found.nodes.append(node)
    found.link(node.id, EdgeType.INVOKES, component_key)
    return node


__all__ = [
    "EnvironmentHost",
    "installed_component",
    "is_exact_version",
    "merge",
    "startup_command",
]
