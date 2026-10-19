"""CrewAI discovery.

Every other adapter in this package reads a declarative document. This
one is the first to read **Python**, because CrewAI splits an agent
across two places: `config/agents.yaml` declares who the agents are, and
`crew.py` decides what they can do.

    config/agents.yaml     role, goal, backstory, allow_delegation
    crew.py                Agent(config=..., tools=[SomeTool()])

**Reading source is not executing it.** This module calls `ast.parse` on
file text and walks the resulting tree. It never imports, executes, or
evaluates the module, never resolves a name to a runtime object, and
never calls `eval`, `exec`, `compile` for execution, or `importlib`. A
structural test asserts those names do not appear here, and
`adapter_sandbox()` independently denies writes, subprocesses, and
sockets while this runs.

**The unknowns are the design, not an afterthought.** An adapter that
found agents from YAML and quietly missed tools attached in Python would
report `no material capability is reachable` over an agent holding a
file-writing tool -- the confident pass the constitution names as the
worst failure available. So every tool expression this module cannot
resolve becomes both a diagnostic *and* a node whose security attributes
are literally `"unknown"`. That second half matters: an `"unknown"`
attribute classifies as `MaterialCapabilityClass.UNCLASSIFIED`, which
`controlloop.capability.taxonomy` ranks **worst of all**, so an
unresolved tool cannot be silently absent from the blast-radius
statement. It is reported as the worst thing in the graph precisely
because nobody knows what it is.

Identity material is the source path plus a document key -- the YAML
key for an agent, the declared class name for a tool. Never a line
number, never the source text, never the display name.
"""

from __future__ import annotations

import ast
from typing import Any

import yaml

from controlloop.acbom import (
    Confidence,
    Diagnostic,
    Edge,
    EdgeStatus,
    EdgeType,
    Evidence,
    Node,
    NodeType,
    SecurityAttributes,
)
from controlloop.acbom.completeness import incomplete_diagnostic
from controlloop.acbom.identity import (
    EdgeIdentityMaterial,
    NodeIdentityMaterial,
    SemanticIdentity,
    edge_id,
    node_id,
)
from controlloop.adapters.framework import (
    DetectionResult,
    DiscoveryResult,
    ScanContext,
)
from controlloop.adapters.framework_versions import (
    UnsupportedFrameworkVersionError,
    declared_version,
    require_supported,
)
from controlloop.bounded_recursion import bounded_recursion

_NAME = "crewai"
_NAMESPACE = "crewai.agent"
_FRAMEWORK = "crewai"

#: CrewAI's scaffold writes `config/agents.yaml`. Both YAML suffixes are
#: accepted because `crewai create crew` has shipped both.
_AGENTS_CONFIG_PATHS = ("config/agents.yaml", "config/agents.yml")

#: `crewai create crew` puts the wiring in `crew.py`. Nested under
#: `src/<project>/` in a scaffolded project, so this matches by
#: basename rather than a fixed path.
_CREW_BASENAME = "crew.py"

_PYPROJECT = "pyproject.toml"

#: The attribute a `@agent` method reads to pull its YAML entry:
#: `Agent(config=self.agents_config['researcher'], ...)`.
_AGENTS_CONFIG_ATTRIBUTE = "agents_config"

#: Everything an unresolved tool is not known to be. Each `"unknown"`
#: contributes `UNCLASSIFIED`, the worst-ranked material class, so the
#: blast radius reports the tool rather than omitting it.
_UNKNOWN_CAPABILITY = SecurityAttributes(
    destructive="unknown",
    financial_action="unknown",
    external_communication="unknown",
    code_execution="unknown",
    read_only="unknown",
)


def _evidence(relative_path: str) -> tuple[Evidence, ...]:
    return (Evidence(adapter=_NAME, path=relative_path),)


def _malformed(evidence: tuple[Evidence, ...], reason: str) -> Diagnostic:
    return incomplete_diagnostic(
        code="INCOMPLETE-UNPARSED-REGION",
        message=f"CrewAI configuration could not be parsed: {reason}.",
        evidence=evidence,
    )


def _unresolved(evidence: tuple[Evidence, ...], reason: str) -> Diagnostic:
    return incomplete_diagnostic(
        code="INCOMPLETE-UNRESOLVED-REFERENCE",
        message=f"CrewAI capability could not be resolved statically: {reason}.",
        evidence=evidence,
    )


def _relative_paths(context: ScanContext) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return `(agents_config_paths, crew_module_paths)`."""

    configs: set[str] = set()
    crews: set[str] = set()
    for file in context.repository_files():
        relative = file.relative
        if relative in _AGENTS_CONFIG_PATHS or relative.endswith(
            tuple(f"/{name}" for name in _AGENTS_CONFIG_PATHS)
        ):
            configs.add(relative)
        elif file.path.name == _CREW_BASENAME:
            crews.add(relative)
    return tuple(sorted(configs)), tuple(sorted(crews))


def _claimed_paths(context: ScanContext) -> tuple[str, ...]:
    """Only claim anything when an agents config exists. A stray
    `crew.py` in a repository that is not a CrewAI project must not make
    this adapter claim it -- that is the false-positive the conformance
    suite's "similar negative" case checks for."""

    configs, crews = _relative_paths(context)
    if not configs:
        return ()
    return tuple(sorted(configs + crews))


# --------------------------------------------------------------------
# Version governance
# --------------------------------------------------------------------


def _project_dependencies(context: ScanContext) -> tuple[str, ...]:
    """Dependency strings from the nearest `pyproject.toml`.

    Parsed with the standard library's `tomllib`; a missing, unreadable,
    or malformed file yields no dependencies, which
    `require_supported` then refuses as undeterminable rather than
    assuming a current version.
    """

    import tomllib

    candidate = context.root.path / _PYPROJECT
    try:
        with bounded_recursion(margin=500):
            document = tomllib.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        return ()

    project = document.get("project")
    if not isinstance(project, dict):
        return ()
    dependencies = project.get("dependencies")
    if not isinstance(dependencies, list):
        return ()
    return tuple(item for item in dependencies if isinstance(item, str))


# --------------------------------------------------------------------
# Agents
# --------------------------------------------------------------------


def _agent_node(
    relative_path: str, key: str, entry: dict[str, Any], evidence: tuple[Evidence, ...]
) -> Node:
    """Named by `role`, identified by the YAML key.

    The split is deliberate: `role` is a display name a human edits, and
    a display label is never identity input.
    """

    role = entry.get("role")
    name = role if isinstance(role, str) and role.strip() else key
    identity = NodeIdentityMaterial(
        node_type=NodeType.AGENT,
        namespace=_NAMESPACE,
        semantic_identity=SemanticIdentity(
            source_path=relative_path, in_document_key=key
        ),
    )
    return Node(
        id=node_id(identity),
        type=NodeType.AGENT,
        subtype="crewai-agent",
        name=name,
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=evidence,
    )


def _delegation_edges(
    agents: dict[str, Node],
    delegating: tuple[str, ...],
    evidence: tuple[Evidence, ...],
) -> tuple[list[Edge], list[Diagnostic]]:
    """`allow_delegation: true` means the agent may hand work to any
    other agent in the crew. CrewAI does not let an agent name
    specific targets, so the honest representation is an edge to every
    other agent -- understating reach would be the more dangerous
    error.
    """

    edges: list[Edge] = []
    diagnostics: list[Diagnostic] = []
    for source_key in delegating:
        source = agents[source_key]
        for target_key, target in sorted(agents.items()):
            if target_key == source_key:
                continue
            try:
                material = EdgeIdentityMaterial(
                    relationship_type=EdgeType.DELEGATES_TO,
                    source_id=source.id,
                    target_id=target.id,
                    relationship_discriminator=f"crewai:allow-delegation:{target_key}",
                )
                edges.append(
                    Edge(
                        id=edge_id(material),
                        source=source.id,
                        target=target.id,
                        type=EdgeType.DELEGATES_TO,
                        status=EdgeStatus.DIRECT,
                        security_attributes=SecurityAttributes(),
                        confidence=Confidence.HIGH,
                        evidence=evidence,
                    )
                )
            except ValueError:
                diagnostics.append(
                    _malformed(evidence, "a delegation edge could not be represented")
                )
    return edges, diagnostics


def _discover_agents(
    context: ScanContext, relative_path: str
) -> tuple[dict[str, Node], list[Edge], list[Diagnostic]]:
    evidence = _evidence(relative_path)
    absolute = context.root.path / relative_path

    try:
        with bounded_recursion(margin=500):
            document = yaml.safe_load(absolute.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError, RecursionError):
        return (
            {},
            [],
            [_malformed(evidence, "the file could not be read as UTF-8 YAML")],
        )

    if not isinstance(document, dict):
        return {}, [], [_malformed(evidence, "the file's top level is not a mapping")]

    agents: dict[str, Node] = {}
    diagnostics: list[Diagnostic] = []
    delegating: list[str] = []

    for key, entry in document.items():
        if not isinstance(key, str) or not isinstance(entry, dict):
            diagnostics.append(_malformed(evidence, "an agent entry is not a mapping"))
            continue
        try:
            agents[key] = _agent_node(relative_path, key, entry, evidence)
        except ValueError:
            diagnostics.append(
                _malformed(evidence, "an agent entry could not be represented")
            )
            continue
        if entry.get("allow_delegation") is True:
            delegating.append(key)

    edges, edge_diagnostics = _delegation_edges(agents, tuple(delegating), evidence)
    return agents, edges, diagnostics + edge_diagnostics


# --------------------------------------------------------------------
# Tools and wiring
# --------------------------------------------------------------------


def _tool_node(
    relative_path: str,
    class_name: str,
    evidence: tuple[Evidence, ...],
    *,
    resolved: bool,
) -> Node:
    identity = NodeIdentityMaterial(
        node_type=NodeType.TOOL,
        namespace=_NAMESPACE,
        semantic_identity=SemanticIdentity(
            source_path=relative_path, in_document_key=f"tool:{class_name}"
        ),
    )
    return Node(
        id=node_id(identity),
        type=NodeType.TOOL,
        subtype="crewai-tool",
        name=class_name,
        # A recognized tool class is still a tool nobody has
        # classified: the adapter knows its name, not what it does.
        # Only `controlloop.yaml`'s `tool_capabilities` can say that,
        # exactly as for an A2A skill.
        security_attributes=SecurityAttributes() if resolved else _UNKNOWN_CAPABILITY,
        confidence=Confidence.HIGH if resolved else Confidence.LOW,
        evidence=evidence,
    )


def _config_key(node: ast.expr) -> str | None:
    """The YAML key in `self.agents_config['researcher']`, or `None`."""

    if not isinstance(node, ast.Subscript):
        return None
    value = node.value
    if not isinstance(value, ast.Attribute) or value.attr != _AGENTS_CONFIG_ATTRIBUTE:
        return None
    index = node.slice
    if isinstance(index, ast.Constant) and isinstance(index.value, str):
        return index.value
    return None


def _tool_class_name(element: ast.expr) -> str | None:
    """The class name of a literal tool reference.

    `SomeTool()` and `module.SomeTool()` resolve. A bare name, a call
    through a variable, or anything computed does not -- and `None` here
    routes to a diagnostic, never to silence.
    """

    if isinstance(element, ast.Call):
        func = element.func
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
    return None


class _CrewVisitor(ast.NodeVisitor):
    """Collects `Agent(...)` constructions and their tool wiring.

    Deliberately shallow: it recognizes the shape CrewAI's own scaffold
    writes and refuses everything else, rather than trying to be a
    partial Python interpreter. A partial interpreter is how a static
    analyzer starts silently guessing.
    """

    def __init__(self) -> None:
        self.wirings: list[tuple[str | None, list[ast.expr] | None]] = []
        self.overrides_config_path = False
        self.hierarchical = False

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        name = (
            func.id
            if isinstance(func, ast.Name)
            else func.attr
            if isinstance(func, ast.Attribute)
            else None
        )
        if name == "Agent":
            config_key: str | None = None
            tools: list[ast.expr] | None = None
            has_tools = False
            for keyword in node.keywords:
                if keyword.arg == "config":
                    config_key = _config_key(keyword.value)
                elif keyword.arg == "tools":
                    has_tools = True
                    if isinstance(keyword.value, ast.List):
                        tools = list(keyword.value.elts)
            if has_tools or config_key is not None:
                self.wirings.append((config_key, tools if has_tools else []))
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == _AGENTS_CONFIG_ATTRIBUTE:
                self.overrides_config_path = True
            if (
                isinstance(target, ast.Attribute)
                and target.attr == _AGENTS_CONFIG_ATTRIBUTE
            ):
                self.overrides_config_path = True
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr == "hierarchical":
            self.hierarchical = True
        self.generic_visit(node)


def _discover_tools(
    context: ScanContext,
    relative_path: str,
    agents: dict[str, Node],
) -> tuple[list[Node], list[Edge], list[Diagnostic]]:
    evidence = _evidence(relative_path)
    absolute = context.root.path / relative_path

    try:
        source = absolute.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return [], [], [_malformed(evidence, "the module could not be read as UTF-8")]

    try:
        with bounded_recursion(margin=500):
            tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return [], [], [_malformed(evidence, "the module is not parseable Python")]

    visitor = _CrewVisitor()
    visitor.visit(tree)

    nodes: dict[str, Node] = {}
    edges: list[Edge] = []
    diagnostics: list[Diagnostic] = []

    if visitor.overrides_config_path:
        diagnostics.append(
            _unresolved(
                evidence,
                "the crew overrides agents_config, so the agent definitions "
                "may not be the ones discovered",
            )
        )

    if visitor.hierarchical:
        diagnostics.append(
            _unresolved(
                evidence,
                "the crew uses the hierarchical process, whose manager agent "
                "may delegate to every agent in the crew",
            )
        )

    for config_key, tool_elements in visitor.wirings:
        agent = agents.get(config_key) if config_key is not None else None
        if agent is None or config_key is None:
            diagnostics.append(
                _unresolved(
                    evidence,
                    "an Agent construction could not be matched to a declared "
                    "agent, so its tools are attributed to nothing",
                )
            )
            continue
        if tool_elements is None:
            diagnostics.append(
                _unresolved(
                    evidence,
                    f"the tools argument for {config_key!r} is not a literal list",
                )
            )
            _attach_unknown(nodes, edges, relative_path, agent, config_key, evidence)
            continue
        for element in tool_elements:
            class_name = _tool_class_name(element)
            if class_name is None:
                diagnostics.append(
                    _unresolved(
                        evidence,
                        f"a tool in {config_key!r}'s list is not a literal "
                        "constructor call",
                    )
                )
                _attach_unknown(
                    nodes, edges, relative_path, agent, config_key, evidence
                )
                continue
            _attach(
                nodes,
                edges,
                diagnostics,
                relative_path,
                agent,
                class_name,
                evidence,
                resolved=True,
            )

    return list(nodes.values()), edges, diagnostics


def _attach_unknown(
    nodes: dict[str, Node],
    edges: list[Edge],
    relative_path: str,
    agent: Node,
    config_key: str,
    evidence: tuple[Evidence, ...],
) -> None:
    """Give an unresolved wiring a real node with `"unknown"` attributes.

    Without this the agent would simply have no tool edge, and a graph
    with no classified capability reports "no material capability is
    reachable" -- a confident pass over a tool nobody could read.
    `"unknown"` classifies as `UNCLASSIFIED`, which ranks worst, so the
    blast radius names it instead.
    """

    _attach(
        nodes,
        edges,
        [],
        relative_path,
        agent,
        f"unresolved-tools:{config_key}",
        evidence,
        resolved=False,
    )


def _attach(
    nodes: dict[str, Node],
    edges: list[Edge],
    diagnostics: list[Diagnostic],
    relative_path: str,
    agent: Node,
    class_name: str,
    evidence: tuple[Evidence, ...],
    *,
    resolved: bool,
) -> None:
    try:
        tool = nodes.get(class_name) or _tool_node(
            relative_path, class_name, evidence, resolved=resolved
        )
        nodes[class_name] = tool
        material = EdgeIdentityMaterial(
            relationship_type=EdgeType.INVOKES,
            source_id=agent.id,
            target_id=tool.id,
            relationship_discriminator=f"crewai:tool:{class_name}",
        )
        edge = Edge(
            id=edge_id(material),
            source=agent.id,
            target=tool.id,
            type=EdgeType.INVOKES,
            status=EdgeStatus.DIRECT,
            security_attributes=SecurityAttributes(),
            confidence=Confidence.HIGH if resolved else Confidence.LOW,
            evidence=evidence,
        )
    except ValueError:
        diagnostics.append(_malformed(evidence, "a tool could not be represented"))
        return
    if all(existing.id != edge.id for existing in edges):
        edges.append(edge)


class CrewAiAdapter:
    """Discovers CrewAI agents, delegation, and tool wiring from
    committed configuration and source, executing nothing."""

    name = _NAME
    supported_versions: tuple[str, ...] = ("crewai>=0.80,<1.0",)

    def detect(self, context: ScanContext) -> DetectionResult:
        return DetectionResult(adapter=self.name, claimed_paths=_claimed_paths(context))

    def discover(self, context: ScanContext) -> DiscoveryResult:
        configs, crews = _relative_paths(context)
        if not configs:
            return DiscoveryResult()

        version_evidence = _evidence(configs[0])
        try:
            require_supported(
                _FRAMEWORK,
                declared_version(_project_dependencies(context), _FRAMEWORK),
            )
        except UnsupportedFrameworkVersionError as error:
            return DiscoveryResult(
                diagnostics=(
                    incomplete_diagnostic(
                        code="INCOMPLETE-UNPARSED-REGION",
                        message=f"CrewAI project was not parsed: {error}.",
                        evidence=version_evidence,
                    ),
                )
            )

        agents: dict[str, Node] = {}
        nodes: list[Node] = []
        edges: list[Edge] = []
        diagnostics: list[Diagnostic] = []

        for relative_path in configs:
            found, delegation_edges, config_diagnostics = _discover_agents(
                context, relative_path
            )
            agents.update(found)
            nodes.extend(found.values())
            edges.extend(delegation_edges)
            diagnostics.extend(config_diagnostics)

        for relative_path in crews:
            tool_nodes, tool_edges, tool_diagnostics = _discover_tools(
                context, relative_path, agents
            )
            nodes.extend(tool_nodes)
            edges.extend(tool_edges)
            diagnostics.extend(tool_diagnostics)

        return DiscoveryResult(
            nodes=tuple(nodes), edges=tuple(edges), diagnostics=tuple(diagnostics)
        )
