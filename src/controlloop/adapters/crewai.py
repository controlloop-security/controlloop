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

**Agents built in code count too.** A project with no
`config/agents.yaml` builds `Agent(role=..., tools=[...])` in Python.
Any module that imports `crewai` is read for those, and an `Agent(...)`
with no YAML `config` becomes an agent of that module, so its tools --
and a list built at runtime -- are reported exactly as a YAML agent's
are.

Identity material is the source path plus a document key -- the YAML
key for a YAML agent; for an agent built in code, its `@agent` method,
else the variable it is assigned to, else its literal `role`; the
declared class name for a tool. Never a line number, never the source
text, never the display name.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
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
from controlloop.adapters.python_registration import (
    appended_agent_tools,
    dynamic_element_shape,
    dynamic_shape,
    located,
    mark_dynamic,
    runtime_built_names,
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

#: A cheap byte-level gate before parsing, as in the OpenAI Agents
#: adapter: a module that imports CrewAI necessarily contains this.
_IMPORT_MARKER = b"crewai"

#: The decorator CrewAI's `CrewBase` classes put on agent factories.
_AGENT_DECORATOR = "agent"

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


def _dynamic(evidence: tuple[Evidence, ...], reason: str) -> Diagnostic:
    return incomplete_diagnostic(
        code="INCOMPLETE-DYNAMIC-REGISTRATION",
        message=f"CrewAI tools are registered at runtime: {reason}.",
        evidence=evidence,
    )


def _imports_crewai(path: Path) -> bool:
    """Whether the module imports `crewai`, on real import syntax. The
    byte gate only decides what is worth parsing."""

    try:
        raw = path.read_bytes()
    except OSError:
        return False
    if _IMPORT_MARKER not in raw:
        return False
    try:
        with bounded_recursion(margin=500):
            tree = ast.parse(raw.decode("utf-8"))
    except (UnicodeDecodeError, SyntaxError, ValueError, RecursionError):
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(alias.name.split(".")[0] == _FRAMEWORK for alias in node.names):
                return True
        elif (
            isinstance(node, ast.ImportFrom)
            and node.module
            and node.module.split(".")[0] == _FRAMEWORK
        ):
            return True
    return False


def _relative_paths(context: ScanContext) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return `(agents_config_paths, module_paths)`.

    The modules are every `crew.py` when an agents config exists, plus
    every module that imports `crewai`. A stray `crew.py` in a
    repository that is not a CrewAI project is not read -- that is the
    false-positive the conformance suite's "similar negative" case
    checks for.
    """

    configs: set[str] = set()
    crews: set[str] = set()
    modules: set[str] = set()
    for file in context.repository_files():
        relative = file.relative
        if relative in _AGENTS_CONFIG_PATHS or relative.endswith(
            tuple(f"/{name}" for name in _AGENTS_CONFIG_PATHS)
        ):
            configs.add(relative)
            continue
        if file.path.name == _CREW_BASENAME:
            crews.add(relative)
        if file.path.suffix == ".py" and _imports_crewai(file.path):
            modules.add(relative)
    if configs:
        modules |= crews
    return tuple(sorted(configs)), tuple(sorted(modules))


def _claimed_paths(context: ScanContext) -> tuple[str, ...]:
    configs, modules = _relative_paths(context)
    return tuple(sorted(configs + modules))


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
    relative_path: str,
    key: str,
    entry: dict[str, Any],
    evidence: tuple[Evidence, ...],
    *,
    document_key: str | None = None,
) -> Node:
    """Named by `role`, identified by the YAML key, or for an agent built
    in code by `document_key`.

    The split is deliberate: `role` is a display name a human edits, and
    a display label is never identity input.
    """

    role = entry.get("role")
    name = role if isinstance(role, str) and role.strip() else key
    identity = NodeIdentityMaterial(
        node_type=NodeType.AGENT,
        namespace=_NAMESPACE,
        semantic_identity=SemanticIdentity(
            source_path=relative_path, in_document_key=document_key or key
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


def _agent_config_key(node: ast.Call) -> str | None:
    """The YAML key an `Agent(config=...)` construction reads, or `None`
    when the call is not an `Agent` or its config is not a literal key."""

    func = node.func
    name = (
        func.id
        if isinstance(func, ast.Name)
        else func.attr
        if isinstance(func, ast.Attribute)
        else None
    )
    if name != "Agent":
        return None
    for keyword in node.keywords:
        if keyword.arg == "config":
            return _config_key(keyword.value)
    return None


def _callee(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _literal_keyword(node: ast.Call, name: str) -> object:
    for keyword in node.keywords:
        if keyword.arg == name and isinstance(keyword.value, ast.Constant):
            return keyword.value.value
    return None


def _is_agent_decorator(decorator: ast.expr) -> bool:
    if isinstance(decorator, ast.Call):
        decorator = decorator.func
    if isinstance(decorator, ast.Name):
        return decorator.id == _AGENT_DECORATOR
    if isinstance(decorator, ast.Attribute):
        return decorator.attr == _AGENT_DECORATOR
    return False


@dataclass
class _Wiring:
    """One `Agent(...)` construction.

    `config_key` is set for an agent read from YAML. An agent built in
    code has `code_key`, or `None` when nothing literal names it.
    """

    config_key: str | None
    #: no `config=` at all, so the agent is defined by this call
    built_in_code: bool
    code_key: str | None
    role: str | None
    delegates: bool
    #: the literal tool entries, or `None` when the argument is not a list
    tools: list[ast.expr] | None
    argument: ast.expr | None

    @property
    def label(self) -> str | None:
        return self.config_key if self.config_key is not None else self.code_key


class _CrewVisitor(ast.NodeVisitor):
    """Collects `Agent(...)` constructions and their tool wiring.

    Deliberately shallow: it recognizes the shape CrewAI's own scaffold
    writes and refuses everything else, rather than trying to be a
    partial Python interpreter. A partial interpreter is how a static
    analyzer starts silently guessing.
    """

    def __init__(self) -> None:
        self.wirings: list[_Wiring] = []
        #: variable name -> the label of the `Agent(...)` assigned to it
        self.agent_variables: dict[str, str] = {}
        self.overrides_config_path = False
        self.hierarchical = False
        self._agent_methods: list[str] = []
        self._assigned: dict[int, str] = {}

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function(node)

    def _function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        decorated = any(_is_agent_decorator(item) for item in node.decorator_list)
        if decorated:
            self._agent_methods.append(node.name)
        self.generic_visit(node)
        if decorated:
            self._agent_methods.pop()

    def visit_Call(self, node: ast.Call) -> None:
        if _callee(node) == "Agent":
            config_key = _agent_config_key(node)
            literal_role = _literal_keyword(node, "role")
            role = (
                literal_role
                if isinstance(literal_role, str) and literal_role.strip()
                else None
            )
            # `config=` reads YAML, and a `**` splat may carry it.
            built_in_code = not any(
                keyword.arg in ("config", None) for keyword in node.keywords
            )
            code_key: str | None = None
            if built_in_code:
                code_key = (
                    self._agent_methods[-1]
                    if self._agent_methods
                    else self._assigned.get(id(node), role)
                )
            tools: list[ast.expr] | None = None
            argument: ast.expr | None = None
            for keyword in node.keywords:
                if keyword.arg == "tools":
                    argument = keyword.value
                    if isinstance(keyword.value, ast.List):
                        tools = list(keyword.value.elts)
            wiring = _Wiring(
                config_key=config_key,
                built_in_code=built_in_code,
                code_key=code_key,
                role=role,
                delegates=_literal_keyword(node, "allow_delegation") is True,
                tools=tools if argument is not None else [],
                argument=argument,
            )
            if argument is not None or config_key is not None or built_in_code:
                self.wirings.append(wiring)
            variable = self._assigned.get(id(node))
            if variable is not None and wiring.label is not None:
                self.agent_variables[variable] = wiring.label
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Call) and _callee(node.value) == "Agent":
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._assigned[id(node.value)] = target.id
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

    built_names = runtime_built_names(tree)
    code_agents, agent_edges, agent_diagnostics = _code_agents(
        relative_path, visitor.wirings
    )
    edges.extend(agent_edges)
    diagnostics.extend(agent_diagnostics)

    for wiring in visitor.wirings:
        config_key = wiring.label
        tool_elements, argument = wiring.tools, wiring.argument
        agent = (
            agents.get(wiring.config_key)
            if wiring.config_key is not None
            else code_agents.get(wiring.code_key)
            if wiring.code_key is not None
            else None
        )
        if agent is None or config_key is None:
            diagnostics.append(
                _unresolved(
                    evidence,
                    "an Agent built in code has no literal role, variable, "
                    "or @agent method to name it, so its tools are attributed "
                    "to nothing"
                    if wiring.built_in_code
                    else "an Agent construction could not be matched to a "
                    "declared agent, so its tools are attributed to nothing",
                )
            )
            continue
        if tool_elements is None:
            shape = dynamic_shape(argument, built_names) if argument else None
            if shape is not None and argument is not None:
                _attach_dynamic(
                    nodes,
                    edges,
                    diagnostics,
                    relative_path,
                    agent,
                    config_key,
                    argument.lineno,
                    f"the tools argument for {config_key!r} is {shape}",
                )
                continue
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
            element_shape = dynamic_element_shape(element)
            if element_shape is not None:
                _attach_dynamic(
                    nodes,
                    edges,
                    diagnostics,
                    relative_path,
                    agent,
                    config_key,
                    element.lineno,
                    f"a tool in {config_key!r}'s list is {element_shape}",
                )
                continue
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

    for variable, line in appended_agent_tools(tree):
        config_key = visitor.agent_variables.get(variable)
        agent = (
            agents.get(config_key) or code_agents.get(config_key)
            if config_key is not None
            else None
        )
        if agent is None or config_key is None:
            continue
        _attach_dynamic(
            nodes,
            edges,
            diagnostics,
            relative_path,
            agent,
            config_key,
            line,
            f"tools are added to {config_key!r} after it is constructed",
        )

    return [*code_agents.values(), *nodes.values()], edges, diagnostics


def _code_agents(
    relative_path: str, wirings: list[_Wiring]
) -> tuple[dict[str, Node], list[Edge], list[Diagnostic]]:
    """The agents a module builds in code, with no YAML `config`.

    Named by their literal `role`, identified by `code_key` -- the
    `@agent` method, the variable, or the role -- within this module.
    `allow_delegation=True` reaches every other agent the module builds,
    as it does in YAML.
    """

    evidence = _evidence(relative_path)
    agents: dict[str, Node] = {}
    delegating: list[str] = []
    diagnostics: list[Diagnostic] = []
    for wiring in wirings:
        key = wiring.code_key
        if wiring.config_key is not None or key is None or key in agents:
            continue
        try:
            agents[key] = _agent_node(
                relative_path,
                key,
                {"role": wiring.role},
                evidence,
                document_key=f"agent:{key}",
            )
        except ValueError:
            diagnostics.append(
                _malformed(evidence, "an agent built in code could not be represented")
            )
            continue
        if wiring.delegates:
            delegating.append(key)
    edges, edge_diagnostics = _delegation_edges(agents, tuple(delegating), evidence)
    return agents, edges, diagnostics + edge_diagnostics


def _attach_dynamic(
    nodes: dict[str, Node],
    edges: list[Edge],
    diagnostics: list[Diagnostic],
    relative_path: str,
    agent: Node,
    config_key: str,
    line: int,
    reason: str,
) -> None:
    """A runtime registration: the same unknown node an unresolved
    wiring gets, at `Confidence.UNKNOWN` and carrying the line the
    `INCOMPLETE-DYNAMIC-REGISTRATION` diagnostic names, so
    `policy.unresolved-dynamic-registration` can attribute it."""

    evidence = located(_NAME, relative_path, line)
    diagnostics.append(_dynamic(evidence, reason))
    _attach_unknown(
        nodes, edges, relative_path, agent, config_key, _evidence(relative_path)
    )
    name = f"unresolved-tools:{config_key}"
    if name in nodes:
        nodes[name] = mark_dynamic(nodes[name], evidence)


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
        if not configs and not crews:
            return DiscoveryResult()

        version_evidence = _evidence((configs or crews)[0])
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
