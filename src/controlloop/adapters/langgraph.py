"""LangGraph discovery.

LangGraph splits an application across a JSON manifest and Python:

    langgraph.json    which graphs exist, and where each one lives
    <module>.py       what the graph is actually wired to do

`langgraph.json` is a fixed path with a stable schema -- structurally
the same problem `.mcp.json` already solves -- and its `graphs` map
names every graph and the `module.py:attribute` it is defined at. That
is a real discovery entry point needing no source parsing at all. The
topology does need it.

**Reading source is not executing it.** `ast.parse` on file text, then a
tree walk. Never imported, never executed, never evaluated, no name ever
resolved to a runtime object. A structural test asserts `importlib`,
`subprocess`, `socket`, `runpy`, `eval`, `exec`, and `compile` appear
nowhere here, and `adapter_sandbox()` independently denies writes,
subprocesses, and sockets while this runs.

**Every branch of a runtime router is reachable.** `add_conditional_edges`
decides at runtime which node comes next. This module emits an edge to
*every* target in the mapping. Modelling one branch would understate
reach while looking precise -- a confident answer quietly narrower than
reality, which is the more dangerous error. A router whose targets
cannot be enumerated at all becomes a diagnostic *and* an
`"unknown"`-attributed node, which classifies as `UNCLASSIFIED` and
therefore ranks worst, so the blast radius names it rather than omitting
it.

**Environment values are never read.** `langgraph.json`'s `env` is
usually a *path* to a `.env` file, not a mapping of names. A committed
`.env` is a secret-leak problem for `controlloop.secret_scan` to find,
and an adapter that parsed it would be one bug away from putting a
credential into an ACBOM. So a path contributes only the fact that an
environment file is declared; only an inline mapping contributes
`env:NAME` scopes, and only its keys.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

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

_NAME = "langgraph"
_NAMESPACE = "langgraph.graph"
_FRAMEWORK = "langgraph"

_CONFIG_FILENAME = "langgraph.json"
_PYPROJECT = "pyproject.toml"

#: Bounds the walk of a graph module. A hostile or generated file must
#: not be able to produce an unbounded node set.
_MAX_NODES_PER_GRAPH = 512

#: LangGraph's entry and exit sentinels. `add_edge(START, "plan")` writes
#: `START` as a bare name, which is not a computed value and must not be
#: mistaken for one -- treating it as dynamic construction would flag
#: every idiomatic graph as partially unknown, which is a false alarm
#: that teaches readers to ignore the real ones.
_SENTINEL_NAMES = frozenset({"START", "END", "__start__", "__end__"})

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
        message=f"LangGraph configuration could not be parsed: {reason}.",
        evidence=evidence,
    )


def _unresolved(evidence: tuple[Evidence, ...], reason: str) -> Diagnostic:
    return incomplete_diagnostic(
        code="INCOMPLETE-UNRESOLVED-REFERENCE",
        message=f"LangGraph capability could not be resolved statically: {reason}.",
        evidence=evidence,
    )


def _config_paths(context: ScanContext) -> tuple[str, ...]:
    found = set()
    for file in context.repository_files():
        if file.path.name == _CONFIG_FILENAME:
            found.add(file.relative)
    return tuple(sorted(found))


def _project_dependencies(context: ScanContext) -> tuple[str, ...]:
    """Dependency strings from `pyproject.toml`, for version governance.

    A LangGraph project may also declare dependencies in
    `langgraph.json` itself; those are read separately as evidence, and
    both are consulted when deciding the framework version.
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


def _declared_dependencies(document: dict[str, Any]) -> tuple[str, ...]:
    """`langgraph.json`'s own `dependencies`, recorded as evidence.

    Never installed, never resolved, never fetched. A `"."` entry means
    "this project", which contributes no version information.
    """

    declared = document.get("dependencies")
    if not isinstance(declared, list):
        return ()
    return tuple(item for item in declared if isinstance(item, str) and item != ".")


def _environment_scopes(document: dict[str, Any]) -> tuple[str, ...]:
    """Permission scopes from `env`, names only.

    A mapping contributes `env:NAME` per key. A **path** contributes only
    the fact that an environment file is declared -- the file is never
    opened. See the module docstring.
    """

    env = document.get("env")
    if isinstance(env, dict):
        return tuple(
            sorted(f"env:{key}" for key in env if isinstance(key, str) and key)
        )
    if isinstance(env, str) and env:
        return ("env:declared-env-file",)
    return ()


# --------------------------------------------------------------------
# Graphs from the manifest
# --------------------------------------------------------------------


def _split_target(target: str) -> tuple[str, str] | None:
    """`"./agent.py:graph"` -> `("agent.py", "graph")`.

    Returns `None` for any shape that is not `path:attribute`, including
    a Windows-style drive letter, which would otherwise split wrongly.
    """

    if ":" not in target:
        return None
    module, _, attribute = target.rpartition(":")
    module = module.strip()
    attribute = attribute.strip()
    if not module or not attribute or "/" in attribute or "\\" in attribute:
        return None
    if module.startswith("./"):
        module = module[2:]
    return module, attribute


def _graph_node(relative_path: str, key: str, evidence: tuple[Evidence, ...]) -> Node:
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
        subtype="langgraph-graph",
        name=key,
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=evidence,
    )


# --------------------------------------------------------------------
# Topology and tool binding, from the AST
# --------------------------------------------------------------------


class _GraphVisitor(ast.NodeVisitor):
    """Collects graph topology and tool bindings from one module.

    Deliberately shallow: it recognizes the shapes LangGraph's own
    documented API produces and refuses everything else. A partial
    Python interpreter is how a static analyzer starts silently
    guessing, and a guess here becomes a capability path a reviewer
    trusts.
    """

    def __init__(self) -> None:
        self.nodes: list[str] = []
        self.edges: list[tuple[str, str]] = []
        self.tools: list[str] = []
        self.unresolved_routers = 0
        self.unresolved_tool_bindings = 0
        self.dynamic_construction = False

    @staticmethod
    def _literal(node: ast.expr) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None

    @staticmethod
    def _sentinel(node: ast.expr) -> bool:
        """Whether this expression is `START`/`END` rather than a
        computed value. Both are module constants LangGraph exports."""

        if isinstance(node, ast.Name):
            return node.id in _SENTINEL_NAMES
        if isinstance(node, ast.Attribute):
            return node.attr in _SENTINEL_NAMES
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value in _SENTINEL_NAMES
        return False

    @staticmethod
    def _callee(node: ast.Call) -> str | None:
        func = node.func
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
        return None

    def _tool_names(self, element: ast.expr) -> list[str] | None:
        """Every tool name in a literal list, or `None` if not literal."""

        if not isinstance(element, ast.List):
            return None
        names: list[str] = []
        for item in element.elts:
            if isinstance(item, ast.Call):
                callee = self._callee(item)
                if callee is None:
                    return None
                names.append(callee)
            elif isinstance(item, ast.Name):
                names.append(item.id)
            elif isinstance(item, ast.Attribute):
                names.append(item.attr)
            else:
                return None
        return names

    def visit_Call(self, node: ast.Call) -> None:
        callee = self._callee(node)

        if callee == "add_node" and node.args:
            name = self._literal(node.args[0])
            if name is not None:
                if len(self.nodes) < _MAX_NODES_PER_GRAPH:
                    self.nodes.append(name)
            else:
                # A node whose name is computed makes the whole graph's
                # shape unknowable, not merely this one node's.
                self.dynamic_construction = True

        elif callee == "add_edge" and len(node.args) >= 2:
            source = self._literal(node.args[0])
            target = self._literal(node.args[1])
            if source is not None and target is not None:
                self.edges.append((source, target))
            elif not (self._sentinel(node.args[0]) or self._sentinel(node.args[1])):
                self.dynamic_construction = True

        elif callee == "add_conditional_edges":
            self._visit_conditional(node)

        elif callee in {"bind_tools", "ToolNode"} and node.args:
            names = self._tool_names(node.args[0])
            if names is None:
                self.unresolved_tool_bindings += 1
            else:
                self.tools.extend(names)

        self.generic_visit(node)

    def _visit_conditional(self, node: ast.Call) -> None:
        """`add_conditional_edges(source, router, {"a": "n1", "b": "n2"})`.

        Every value in the mapping becomes reachable. LangGraph decides
        which at runtime; a scanner that picked one would report a
        narrower graph than the one that will actually run.
        """

        source = self._literal(node.args[0]) if node.args else None
        mapping = node.args[2] if len(node.args) >= 3 else None
        if mapping is None:
            for keyword in node.keywords:
                if keyword.arg in {"path_map", "conditional_edge_mapping"}:
                    mapping = keyword.value

        if source is None or mapping is None:
            if not (node.args and self._sentinel(node.args[0])):
                self.unresolved_routers += 1
            return

        targets: list[str] = []
        if isinstance(mapping, ast.Dict):
            for value in mapping.values:
                target = self._literal(value)
                if target is None:
                    targets = []
                    break
                targets.append(target)
        elif isinstance(mapping, ast.List):
            for element in mapping.elts:
                target = self._literal(element)
                if target is None:
                    targets = []
                    break
                targets.append(target)

        if not targets:
            self.unresolved_routers += 1
            return

        for target in targets:
            self.edges.append((source, target))


def _node_for(
    relative_path: str, graph_key: str, name: str, evidence: tuple[Evidence, ...]
) -> Node:
    identity = NodeIdentityMaterial(
        node_type=NodeType.TOOL,
        namespace=_NAMESPACE,
        semantic_identity=SemanticIdentity(
            source_path=relative_path, in_document_key=f"{graph_key}:node:{name}"
        ),
    )
    return Node(
        id=node_id(identity),
        type=NodeType.TOOL,
        subtype="langgraph-node",
        name=name,
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=evidence,
    )


def _tool_for(
    relative_path: str,
    graph_key: str,
    name: str,
    evidence: tuple[Evidence, ...],
    *,
    resolved: bool,
) -> Node:
    identity = NodeIdentityMaterial(
        node_type=NodeType.TOOL,
        namespace=_NAMESPACE,
        semantic_identity=SemanticIdentity(
            source_path=relative_path, in_document_key=f"{graph_key}:tool:{name}"
        ),
    )
    return Node(
        id=node_id(identity),
        type=NodeType.TOOL,
        subtype="langgraph-tool",
        name=name,
        security_attributes=SecurityAttributes() if resolved else _UNKNOWN_CAPABILITY,
        confidence=Confidence.HIGH if resolved else Confidence.LOW,
        evidence=evidence,
    )


def _edge(
    source: Node,
    target: Node,
    edge_type: EdgeType,
    discriminator: str,
    evidence: tuple[Evidence, ...],
    *,
    resolved: bool = True,
) -> Edge:
    material = EdgeIdentityMaterial(
        relationship_type=edge_type,
        source_id=source.id,
        target_id=target.id,
        relationship_discriminator=discriminator,
    )
    return Edge(
        id=edge_id(material),
        source=source.id,
        target=target.id,
        type=edge_type,
        status=EdgeStatus.DIRECT,
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH if resolved else Confidence.LOW,
        evidence=evidence,
    )


def _discover_graph_module(
    context: ScanContext,
    config_relative: str,
    graph_key: str,
    module_relative: str,
    graph_node: Node,
) -> tuple[list[Node], list[Edge], list[Diagnostic]]:
    """Parse one graph module and turn it into nodes and edges."""

    evidence = _evidence(module_relative)
    absolute = context.root.path / module_relative

    try:
        source = absolute.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return [], [], [_malformed(evidence, "the module could not be read as UTF-8")]

    try:
        with bounded_recursion(margin=500):
            tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return [], [], [_malformed(evidence, "the module is not parseable Python")]

    visitor = _GraphVisitor()
    visitor.visit(tree)

    nodes: dict[str, Node] = {}
    edges: list[Edge] = []
    diagnostics: list[Diagnostic] = []

    for name in visitor.nodes:
        try:
            nodes[name] = _node_for(module_relative, graph_key, name, evidence)
        except ValueError:
            diagnostics.append(
                _malformed(evidence, "a graph node could not be represented")
            )

    # The graph reaches each of its own nodes.
    for name, node in sorted(nodes.items()):
        try:
            edges.append(
                _edge(
                    graph_node,
                    node,
                    EdgeType.INVOKES,
                    f"langgraph:node:{name}",
                    evidence,
                )
            )
        except ValueError:
            diagnostics.append(_malformed(evidence, "an edge could not be represented"))

    # Node-to-node edges, including every branch of every router.
    for source_name, target_name in visitor.edges:
        source_node = nodes.get(source_name)
        target_node = nodes.get(target_name)
        if source_node is None or target_node is None:
            # START/END and other sentinels are not `add_node` names.
            continue
        try:
            edges.append(
                _edge(
                    source_node,
                    target_node,
                    EdgeType.DELEGATES_TO,
                    f"langgraph:edge:{source_name}->{target_name}",
                    evidence,
                )
            )
        except ValueError:
            diagnostics.append(_malformed(evidence, "an edge could not be represented"))

    tool_nodes, tool_edges, tool_diagnostics = _attach_tools(
        module_relative, graph_key, graph_node, visitor, evidence
    )
    nodes.update(tool_nodes)
    edges.extend(tool_edges)
    diagnostics.extend(tool_diagnostics)

    if visitor.dynamic_construction:
        diagnostics.append(
            _unresolved(
                evidence,
                f"graph {graph_key!r} is built dynamically, so its shape is "
                "not fully known",
            )
        )
    for _ in range(visitor.unresolved_routers):
        diagnostics.append(
            _unresolved(
                evidence,
                f"a conditional router in graph {graph_key!r} has targets that "
                "cannot be enumerated, so some reachable nodes are unknown",
            )
        )

    return list(nodes.values()), edges, diagnostics


def _attach_tools(
    module_relative: str,
    graph_key: str,
    graph_node: Node,
    visitor: _GraphVisitor,
    evidence: tuple[Evidence, ...],
) -> tuple[dict[str, Node], list[Edge], list[Diagnostic]]:
    nodes: dict[str, Node] = {}
    edges: list[Edge] = []
    diagnostics: list[Diagnostic] = []

    for name in visitor.tools:
        key = f"tool:{name}"
        if key in nodes:
            continue
        try:
            tool = _tool_for(module_relative, graph_key, name, evidence, resolved=True)
            nodes[key] = tool
            edges.append(
                _edge(
                    graph_node,
                    tool,
                    EdgeType.INVOKES,
                    f"langgraph:tool:{name}",
                    evidence,
                )
            )
        except ValueError:
            diagnostics.append(_malformed(evidence, "a tool could not be represented"))

    for index in range(visitor.unresolved_tool_bindings):
        name = f"unresolved-tools:{graph_key}"
        key = f"tool:{name}"
        diagnostics.append(
            _unresolved(
                evidence,
                f"a tool binding in graph {graph_key!r} is not a literal list, "
                "so what it can reach is unknown",
            )
        )
        if key in nodes:
            continue
        try:
            tool = _tool_for(module_relative, graph_key, name, evidence, resolved=False)
            nodes[key] = tool
            edges.append(
                _edge(
                    graph_node,
                    tool,
                    EdgeType.INVOKES,
                    f"langgraph:unresolved-tools:{index}",
                    evidence,
                    resolved=False,
                )
            )
        except ValueError:
            diagnostics.append(_malformed(evidence, "a tool could not be represented"))

    return nodes, edges, diagnostics


class LangGraphAdapter:
    """Discovers LangGraph applications from `langgraph.json` and the
    graph modules it names, executing nothing."""

    name = _NAME
    supported_versions: tuple[str, ...] = ("langgraph>=0.2,<1.0",)

    def detect(self, context: ScanContext) -> DetectionResult:
        return DetectionResult(adapter=self.name, claimed_paths=_config_paths(context))

    def discover(self, context: ScanContext) -> DiscoveryResult:
        configs = _config_paths(context)
        if not configs:
            return DiscoveryResult()

        nodes: list[Node] = []
        edges: list[Edge] = []
        diagnostics: list[Diagnostic] = []

        for config_relative in configs:
            found_nodes, found_edges, found_diagnostics = self._discover_config(
                context, config_relative
            )
            nodes.extend(found_nodes)
            edges.extend(found_edges)
            diagnostics.extend(found_diagnostics)

        return DiscoveryResult(
            nodes=tuple(nodes), edges=tuple(edges), diagnostics=tuple(diagnostics)
        )

    def _discover_config(
        self, context: ScanContext, config_relative: str
    ) -> tuple[list[Node], list[Edge], list[Diagnostic]]:
        evidence = _evidence(config_relative)
        absolute = context.root.path / config_relative

        try:
            with bounded_recursion(margin=500):
                document = json.loads(absolute.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            return [], [], [_malformed(evidence, "the file could not be read as JSON")]

        if not isinstance(document, dict):
            return (
                [],
                [],
                [_malformed(evidence, "the file's top level is not an object")],
            )

        declared = _declared_dependencies(document)
        try:
            require_supported(
                _FRAMEWORK,
                declared_version(_project_dependencies(context) + declared, _FRAMEWORK),
            )
        except UnsupportedFrameworkVersionError as error:
            return (
                [],
                [],
                [
                    incomplete_diagnostic(
                        code="INCOMPLETE-UNPARSED-REGION",
                        message=f"LangGraph project was not parsed: {error}.",
                        evidence=evidence,
                    )
                ],
            )

        graphs = document.get("graphs")
        if not isinstance(graphs, dict) or not graphs:
            return [], [], [_malformed(evidence, "no graphs object was found")]

        scopes = _environment_scopes(document)
        config_directory = Path(config_relative).parent

        nodes: list[Node] = []
        edges: list[Edge] = []
        diagnostics: list[Diagnostic] = []

        for key, target in sorted(graphs.items()):
            if not isinstance(key, str) or not isinstance(target, str):
                diagnostics.append(
                    _malformed(evidence, "a graph entry is not a string")
                )
                continue
            try:
                graph_node = _graph_node(config_relative, key, evidence)
            except ValueError:
                diagnostics.append(
                    _malformed(evidence, "a graph entry could not be represented")
                )
                continue

            if scopes:
                graph_node = graph_node.model_copy(
                    update={
                        "security_attributes": SecurityAttributes(
                            permission_scopes=scopes
                        )
                    }
                )
            nodes.append(graph_node)

            split = _split_target(target)
            if split is None:
                diagnostics.append(
                    _unresolved(
                        evidence,
                        f"graph {key!r} does not name a module and attribute",
                    )
                )
                continue

            module, _attribute = split
            module_relative = (config_directory / module).as_posix().lstrip("./")
            if not (context.root.path / module_relative).is_file():
                diagnostics.append(
                    _unresolved(
                        evidence,
                        f"graph {key!r} names a module that does not exist in "
                        "this repository",
                    )
                )
                continue

            module_nodes, module_edges, module_diagnostics = _discover_graph_module(
                context, config_relative, key, module_relative, graph_node
            )
            nodes.extend(module_nodes)
            edges.extend(module_edges)
            diagnostics.extend(module_diagnostics)

        return nodes, edges, diagnostics
