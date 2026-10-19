"""OpenAI Agents SDK discovery.

This SDK ships **no configuration file**. Every agent, tool, and handoff
is Python, which removes the cheap discovery entry point the CrewAI and
LangGraph adapters both had: detection keys on the SDK's own import
instead of a fixed path.

It earns an adapter anyway, because its central construct is unusually
well shaped for static analysis. `@function_tool` marks a tool at its
**definition site**, so the set of tools that exist is knowable even
when the set an agent holds is not. Those two questions are answered
separately here on purpose: a dynamic `tools=[...]` costs "which agent
holds this" without destroying "this tool exists". That is a strictly
better degradation curve than either predecessor gets.

**One deliberate step beyond reading a literal.** Neither predecessor
needed to resolve a variable; this one does:

    billing_agent = Agent(name="Billing", tools=[issue_refund])
    triage_agent  = Agent(name="Triage", handoffs=[billing_agent])

`handoffs=[billing_agent]` is a bare name. This module builds a map from
variable to agent from module-level assignments whose value is an
`Agent(...)` call, and resolves through it. Exactly one step: a single
assignment in the same module. No import following, no cross-module
resolution, no value tracking through reassignment. An unresolvable
reference is reported, never guessed -- a partial Python interpreter is
how a static analyzer starts inventing capability paths a reviewer then
trusts.

**`as_tool` is not a handoff.** A handoff transfers the conversation;
`Agent.as_tool()` calls into an agent and returns. Different authority,
so `as_tool` produces `invokes` and a handoff produces `delegates-to`.

**Reading source is not executing it.** `ast.parse` and a tree walk.
Never imported, never executed, never evaluated. A structural test
asserts `importlib`, `subprocess`, `socket`, `runpy`, `eval`, `exec`,
and `compile` appear nowhere here.
"""

from __future__ import annotations

import ast
from pathlib import Path

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

_NAME = "openai-agents"
_NAMESPACE = "openai-agents.module"
_FRAMEWORK = "openai-agents"

_PYPROJECT = "pyproject.toml"

#: The SDK's import root. Detection keys on this because the SDK ships
#: no configuration file to key on instead.
_SDK_MODULES = frozenset({"agents"})

_TOOL_DECORATOR = "function_tool"

#: Bounds one module's contribution, so a generated file cannot produce
#: an unbounded node set.
_MAX_ENTITIES_PER_MODULE = 512

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
        message=f"OpenAI Agents module could not be parsed: {reason}.",
        evidence=evidence,
    )


def _unresolved(evidence: tuple[Evidence, ...], reason: str) -> Diagnostic:
    return incomplete_diagnostic(
        code="INCOMPLETE-UNRESOLVED-REFERENCE",
        message=(
            f"OpenAI Agents capability could not be resolved statically: {reason}."
        ),
        evidence=evidence,
    )


def _imports_the_sdk(tree: ast.Module) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(a.name.split(".")[0] in _SDK_MODULES for a in node.names):
                return True
        elif (
            isinstance(node, ast.ImportFrom)
            and node.module
            and node.module.split(".")[0] in _SDK_MODULES
        ):
            return True
    return False


#: A cheap byte-level gate applied before any parsing. Every module that
#: imports the SDK necessarily contains one of these substrings, so a
#: file lacking both cannot possibly be a candidate and is skipped
#: without being parsed at all.
#:
#: This exists because it is measurable. Content-detection over every
#: `.py` file in a repository is the most expensive kind of detection
#: this codebase has, and parsing every file to reject almost all of
#: them regressed the scan benchmark's p50 by roughly 11% -- caught by
#: `tests/performance/test_benchmark.py`, which is exactly what that
#: test is for.
_IMPORT_MARKERS = (b"import agents", b"from agents")


def _looks_like_a_candidate(path: Path) -> bytes | None:
    """The file's bytes if it could plausibly import the SDK, else
    `None`. Read as bytes so a non-UTF-8 file costs a substring scan
    rather than a decode failure."""

    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if not any(marker in raw for marker in _IMPORT_MARKERS):
        return None
    return raw


def _candidate_modules(context: ScanContext) -> tuple[str, ...]:
    """Python files that import the SDK.

    Content-detected, like the OpenAPI adapter, because there is no
    filename convention to claim. A file that merely mentions `agents`
    in a string is not claimed: the substring gate above only decides
    what is worth parsing, and the claim itself is still made on real
    import syntax.
    """

    found: set[str] = set()
    for file in context.repository_files():
        if file.path.suffix != ".py":
            continue
        raw = _looks_like_a_candidate(file.path)
        if raw is None:
            continue
        try:
            source = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        try:
            with bounded_recursion(margin=500):
                tree = ast.parse(source)
        except (SyntaxError, ValueError, RecursionError):
            continue
        if _imports_the_sdk(tree):
            found.add(file.relative)
    return tuple(sorted(found))


def _project_dependencies(context: ScanContext) -> tuple[str, ...]:
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
# The one resolution step: variable -> what it was assigned
# --------------------------------------------------------------------


def _callee(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _literal_string(node: ast.expr) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _keyword(call: ast.Call, name: str) -> ast.expr | None:
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


class _ModuleScan(ast.NodeVisitor):
    """One pass over a module, collecting the agents, tools, and wiring
    discovery needs.

    Deliberately shallow. It recognizes the shapes the SDK's own
    documentation produces and refuses the rest, rather than tracking
    values through reassignment or following imports.
    """

    def __init__(self) -> None:
        #: variable name -> declared agent name
        self.agent_variables: dict[str, str] = {}
        #: declared agent name -> the `Agent(...)` call that made it
        self.agents: dict[str, ast.Call] = {}
        #: tool name -> the decorated function's parameter names
        self.tools: dict[str, tuple[str, ...]] = {}
        #: variable/function name -> tool name, for wiring lookups
        self.tool_symbols: dict[str, str] = {}
        self.unnamed_agents = 0
        self.dynamic_decorators = 0

    # -- agents -------------------------------------------------------

    def visit_Assign(self, node: ast.Assign) -> None:
        value = node.value
        if isinstance(value, ast.Call) and _callee(value) == "Agent":
            name = self._agent_name(value)
            if name is not None:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.agent_variables[target.id] = name
        self.generic_visit(node)

    def _agent_name(self, call: ast.Call) -> str | None:
        keyword = _keyword(call, "name")
        literal = _literal_string(keyword) if keyword is not None else None
        if literal is None and call.args:
            literal = _literal_string(call.args[0])
        if literal is None:
            # A computed name is reported, never synthesized --
            # a made-up agent identity is worse than a missing one.
            self.unnamed_agents += 1
            return None
        if len(self.agents) < _MAX_ENTITIES_PER_MODULE:
            self.agents.setdefault(literal, call)
        return literal

    def visit_Call(self, node: ast.Call) -> None:
        if _callee(node) == "Agent":
            self._agent_name(node)
        self.generic_visit(node)

    # -- tools --------------------------------------------------------

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function(node)
        self.generic_visit(node)

    def _function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """A `@function_tool`-decorated function is a tool.

        This does not consult any agent. A tool that nothing references
        is still a tool that exists, and reporting it is the point -- an
        unreferenced privileged function is exactly the kind of thing a
        reviewer wants to see.
        """

        for decorator in node.decorator_list:
            name_override: str | None = None
            if isinstance(decorator, ast.Name):
                if decorator.id != _TOOL_DECORATOR:
                    continue
            elif isinstance(decorator, ast.Attribute):
                if decorator.attr != _TOOL_DECORATOR:
                    continue
            elif isinstance(decorator, ast.Call):
                if _callee(decorator) != _TOOL_DECORATOR:
                    continue
                override = _keyword(decorator, "name_override")
                name_override = (
                    _literal_string(override) if override is not None else None
                )
                if override is not None and name_override is None:
                    # A computed override means the tool's name -- the
                    # thing a manifest must match -- is unknowable.
                    self.dynamic_decorators += 1
                    continue
            else:
                continue

            tool_name = name_override or node.name
            if len(self.tools) < _MAX_ENTITIES_PER_MODULE:
                # Parameter *names* only. No default value, no
                # docstring body, no literal argument -- none of it is
                # identity material and none of it belongs in evidence.
                parameters = tuple(
                    argument.arg
                    for argument in node.args.args + node.args.kwonlyargs
                    if argument.arg not in {"self", "cls"}
                )
                self.tools[tool_name] = parameters
                self.tool_symbols[node.name] = tool_name
            return


# --------------------------------------------------------------------
# Node and edge construction
# --------------------------------------------------------------------


def _agent_node(relative: str, name: str, evidence: tuple[Evidence, ...]) -> Node:
    identity = NodeIdentityMaterial(
        node_type=NodeType.AGENT,
        namespace=_NAMESPACE,
        semantic_identity=SemanticIdentity(
            source_path=relative, in_document_key=f"agent:{name}"
        ),
    )
    return Node(
        id=node_id(identity),
        type=NodeType.AGENT,
        subtype="openai-agents-agent",
        name=name,
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=evidence,
    )


def _tool_node(
    relative: str,
    name: str,
    parameters: tuple[str, ...],
    evidence: tuple[Evidence, ...],
    *,
    resolved: bool = True,
    subtype: str = "openai-agents-function-tool",
) -> Node:
    identity = NodeIdentityMaterial(
        node_type=NodeType.TOOL,
        namespace=_NAMESPACE,
        semantic_identity=SemanticIdentity(
            source_path=relative, in_document_key=f"tool:{name}"
        ),
    )
    return Node(
        id=node_id(identity),
        type=NodeType.TOOL,
        subtype=subtype,
        name=name,
        security_attributes=SecurityAttributes(
            permission_scopes=tuple(sorted(f"param:{p}" for p in parameters))
        )
        if resolved
        else _UNKNOWN_CAPABILITY,
        confidence=Confidence.HIGH if resolved else Confidence.LOW,
        evidence=evidence,
    )


def _build_edge(
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


def _handoff_targets(scan: _ModuleScan, expression: ast.expr) -> tuple[list[str], int]:
    """Agent names a `handoffs=[...]` list refers to, plus a count of
    entries that could not be resolved.

    Accepts a bare name assigned from `Agent(...)`, a `handoff(agent)`
    wrapper, and an inline `Agent(name="...")`. Anything else is
    unresolved and reported.
    """

    if not isinstance(expression, ast.List):
        return [], -1

    names: list[str] = []
    unresolved = 0
    for element in expression.elts:
        target = element
        if isinstance(target, ast.Call) and _callee(target) == "handoff":
            if not target.args:
                unresolved += 1
                continue
            target = target.args[0]
        if isinstance(target, ast.Name):
            resolved = scan.agent_variables.get(target.id)
            if resolved is None:
                unresolved += 1
            else:
                names.append(resolved)
        elif isinstance(target, ast.Call) and _callee(target) == "Agent":
            keyword = _keyword(target, "name")
            literal = _literal_string(keyword) if keyword is not None else None
            if literal is None:
                unresolved += 1
            else:
                names.append(literal)
        else:
            unresolved += 1
    return names, unresolved


def _discover_module(
    context: ScanContext, relative: str
) -> tuple[list[Node], list[Edge], list[Diagnostic]]:
    evidence = _evidence(relative)
    absolute = context.root.path / relative

    try:
        source = absolute.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return [], [], [_malformed(evidence, "the module could not be read as UTF-8")]

    try:
        with bounded_recursion(margin=500):
            tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return [], [], [_malformed(evidence, "the module is not parseable Python")]

    scan = _ModuleScan()
    scan.visit(tree)

    nodes: dict[str, Node] = {}
    edges: list[Edge] = []
    diagnostics: list[Diagnostic] = []

    # Every tool that exists, whether or not an agent holds it.
    for tool_name, parameters in sorted(scan.tools.items()):
        try:
            nodes[f"tool:{tool_name}"] = _tool_node(
                relative, tool_name, parameters, evidence
            )
        except ValueError:
            diagnostics.append(_malformed(evidence, "a tool could not be represented"))

    # Every declared agent.
    for agent_name in sorted(scan.agents):
        try:
            nodes[f"agent:{agent_name}"] = _agent_node(relative, agent_name, evidence)
        except ValueError:
            diagnostics.append(
                _malformed(evidence, "an agent could not be represented")
            )

    for _ in range(scan.unnamed_agents):
        diagnostics.append(
            _unresolved(
                evidence,
                "an Agent is constructed with a name that is not a literal, so "
                "it cannot be identified",
            )
        )
    for _ in range(scan.dynamic_decorators):
        diagnostics.append(
            _unresolved(
                evidence,
                "a function_tool decorator computes its name_override, so the "
                "tool's name is unknown",
            )
        )

    # Wiring: handoffs and tools.
    for agent_name, call in sorted(scan.agents.items()):
        agent = nodes.get(f"agent:{agent_name}")
        if agent is None:
            continue
        _wire_handoffs(
            scan, call, agent, agent_name, nodes, edges, diagnostics, evidence
        )
        _wire_tools(
            scan, call, agent, agent_name, relative, nodes, edges, diagnostics, evidence
        )

    _wire_as_tool(scan, tree, nodes, edges, diagnostics, evidence)

    # A tool nothing wires is reachable by nothing, and
    # said so rather than dropped.
    reached = {edge.target for edge in edges}
    for key, node in sorted(nodes.items()):
        if key.startswith("tool:") and node.id not in reached:
            diagnostics.append(
                _unresolved(
                    evidence,
                    f"tool {node.name!r} is defined but wired to no agent, so "
                    "nothing in this module can reach it",
                )
            )

    return list(nodes.values()), edges, diagnostics


def _wire_handoffs(
    scan: _ModuleScan,
    call: ast.Call,
    agent: Node,
    agent_name: str,
    nodes: dict[str, Node],
    edges: list[Edge],
    diagnostics: list[Diagnostic],
    evidence: tuple[Evidence, ...],
) -> None:
    """`handoffs=[...]` transfers the conversation: `delegates-to`."""

    expression = _keyword(call, "handoffs")
    if expression is None:
        return

    targets, unresolved = _handoff_targets(scan, expression)
    if unresolved < 0:
        diagnostics.append(
            _unresolved(
                evidence,
                f"the handoffs argument for {agent_name!r} is not a literal list",
            )
        )
        return

    for _ in range(unresolved):
        diagnostics.append(
            _unresolved(
                evidence,
                f"a handoff target for {agent_name!r} could not be resolved to a "
                "declared agent",
            )
        )

    for target_name in targets:
        target = nodes.get(f"agent:{target_name}")
        if target is None:
            diagnostics.append(
                _unresolved(
                    evidence,
                    f"{agent_name!r} hands off to {target_name!r}, which is not "
                    "declared in this module",
                )
            )
            continue
        try:
            edges.append(
                _build_edge(
                    agent,
                    target,
                    EdgeType.DELEGATES_TO,
                    f"openai-agents:handoff:{target_name}",
                    evidence,
                )
            )
        except ValueError:
            diagnostics.append(_malformed(evidence, "an edge could not be represented"))


def _wire_tools(
    scan: _ModuleScan,
    call: ast.Call,
    agent: Node,
    agent_name: str,
    relative: str,
    nodes: dict[str, Node],
    edges: list[Edge],
    diagnostics: list[Diagnostic],
    evidence: tuple[Evidence, ...],
) -> None:
    expression = _keyword(call, "tools")
    if expression is None:
        return

    if not isinstance(expression, ast.List):
        _attach_unknown(
            agent, agent_name, relative, nodes, edges, diagnostics, evidence
        )
        return

    for element in expression.elts:
        symbol: str | None = None
        if isinstance(element, ast.Name):
            symbol = element.id
        elif isinstance(element, ast.Attribute):
            symbol = element.attr

        tool_name = scan.tool_symbols.get(symbol) if symbol else None
        if tool_name is None:
            _attach_unknown(
                agent, agent_name, relative, nodes, edges, diagnostics, evidence
            )
            continue

        target = nodes.get(f"tool:{tool_name}")
        if target is None:
            continue
        try:
            edges.append(
                _build_edge(
                    agent,
                    target,
                    EdgeType.INVOKES,
                    f"openai-agents:tool:{tool_name}",
                    evidence,
                )
            )
        except ValueError:
            diagnostics.append(_malformed(evidence, "an edge could not be represented"))


def _attach_unknown(
    agent: Node,
    agent_name: str,
    relative: str,
    nodes: dict[str, Node],
    edges: list[Edge],
    diagnostics: list[Diagnostic],
    evidence: tuple[Evidence, ...],
) -> None:
    """An unresolvable wiring still produces a node.

    Omitting it would leave the agent with no tool edge, and a graph
    that classifies to nothing reports "no material capability is
    reachable" -- a confident pass over a tool nobody could read.
    `"unknown"` classifies as `UNCLASSIFIED`, which ranks worst.
    """

    diagnostics.append(
        _unresolved(
            evidence,
            f"a tool in {agent_name!r}'s list could not be resolved to a "
            "declared function tool",
        )
    )
    name = f"unresolved-tools:{agent_name}"
    key = f"tool:{name}"
    try:
        if key not in nodes:
            nodes[key] = _tool_node(
                relative,
                name,
                (),
                evidence,
                resolved=False,
                subtype="openai-agents-unresolved",
            )
        edge = _build_edge(
            agent,
            nodes[key],
            EdgeType.INVOKES,
            f"openai-agents:unresolved:{agent_name}",
            evidence,
            resolved=False,
        )
        if all(existing.id != edge.id for existing in edges):
            edges.append(edge)
    except ValueError:
        diagnostics.append(_malformed(evidence, "a tool could not be represented"))


def _wire_as_tool(
    scan: _ModuleScan,
    tree: ast.Module,
    nodes: dict[str, Node],
    edges: list[Edge],
    diagnostics: list[Diagnostic],
    evidence: tuple[Evidence, ...],
) -> None:
    """`other_agent.as_tool()` is `invokes`, not `delegates-to`.

    A handoff transfers the conversation; `as_tool` calls in and
    returns. Collapsing them would overstate what a caller gave away.
    """

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or _callee(node) != "as_tool":
            continue
        func = node.func
        if not isinstance(func, ast.Attribute) or not isinstance(func.value, ast.Name):
            diagnostics.append(
                _unresolved(
                    evidence,
                    "an as_tool call could not be resolved to a declared agent",
                )
            )
            continue
        target_name = scan.agent_variables.get(func.value.id)
        target = nodes.get(f"agent:{target_name}") if target_name else None
        if target is None:
            diagnostics.append(
                _unresolved(
                    evidence,
                    "an as_tool call could not be resolved to a declared agent",
                )
            )
            continue
        for key, candidate in sorted(nodes.items()):
            if not key.startswith("agent:") or candidate.id == target.id:
                continue
            try:
                edge = _build_edge(
                    candidate,
                    target,
                    EdgeType.INVOKES,
                    f"openai-agents:as-tool:{target.name}",
                    evidence,
                )
            except ValueError:
                continue
            if all(existing.id != edge.id for existing in edges):
                edges.append(edge)
            break


class OpenAiAgentsAdapter:
    """Discovers OpenAI Agents SDK agents, handoffs, and function tools
    from committed source, executing nothing."""

    name = _NAME
    supported_versions: tuple[str, ...] = ("openai-agents>=0.1,<2.0",)

    def detect(self, context: ScanContext) -> DetectionResult:
        return DetectionResult(
            adapter=self.name, claimed_paths=_candidate_modules(context)
        )

    def discover(self, context: ScanContext) -> DiscoveryResult:
        modules = _candidate_modules(context)
        if not modules:
            return DiscoveryResult()

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
                        message=f"OpenAI Agents project was not parsed: {error}.",
                        evidence=_evidence(modules[0]),
                    ),
                )
            )

        nodes: list[Node] = []
        edges: list[Edge] = []
        diagnostics: list[Diagnostic] = []
        for relative in modules:
            found_nodes, found_edges, found_diagnostics = _discover_module(
                context, relative
            )
            nodes.extend(found_nodes)
            edges.extend(found_edges)
            diagnostics.extend(found_diagnostics)

        return DiscoveryResult(
            nodes=tuple(nodes), edges=tuple(edges), diagnostics=tuple(diagnostics)
        )
