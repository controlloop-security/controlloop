"""Telling a tool list built at runtime from one the adapter did not follow.

The framework adapters (`crewai`, `langgraph`, `openai_agents`) read a
tool list from Python source with `ast`, and refuse anything that is not
a literal list. That refusal covers two different unknowns, and they
deserve different diagnostics:

    tools=TOOLS                      a name the adapter did not follow
    tools=[make(t) for t in cfg]     a list that only exists at runtime

The first is one step of resolution the adapter deliberately does not
take: `INCOMPLETE-UNRESOLVED-REFERENCE`. The second is registration at
runtime, which no amount of static resolution would enumerate:
`INCOMPLETE-DYNAMIC-REGISTRATION`, which
`policy.unresolved-dynamic-registration` turns into a finding naming the
file and the agent.

A comprehension, a call, a splat, a conditional expression, or any other
computed value is dynamic. So is a bare name the module builds at
runtime -- assigned from one of those shapes, or appended to, extended,
or added to (most often inside a loop) -- and an agent whose `tools` is
appended to or extended after construction.

**Reading source is not executing it.** Everything here is a walk over an
already-parsed tree. Nothing is imported, evaluated, or resolved to a
runtime object, and no source text leaves this module: callers get a
short fixed description of the shape and a line number.
"""

from __future__ import annotations

import ast
from collections.abc import Mapping

from controlloop.acbom import Confidence, Evidence, Node

#: The list methods that add registrations to a list that already exists.
_MUTATING_METHODS = frozenset({"append", "extend", "insert"})

#: The attribute an agent object keeps its tools in, for both CrewAI's
#: and the OpenAI Agents SDK's `Agent`.
_TOOLS_ATTRIBUTE = "tools"

#: `Evidence` collections hold at most 32 entries.
_MAX_EVIDENCE = 32


def dynamic_shape(
    expression: ast.expr, built_names: Mapping[str, str] | None = None
) -> str | None:
    """A short description of how `expression` builds a tool list at
    runtime, or `None` when it does not.

    A literal list or tuple is not dynamic unless it splats another
    value into itself. A bare name is dynamic only when `built_names`
    (from `runtime_built_names`) says the module builds it; otherwise it
    is an unresolved reference, as is an attribute.
    """

    if isinstance(expression, ast.List | ast.Tuple):
        if any(isinstance(element, ast.Starred) for element in expression.elts):
            return "a splat"
        return None
    if isinstance(expression, ast.Name):
        return (built_names or {}).get(expression.id)
    if isinstance(expression, ast.Attribute):
        return None
    if isinstance(expression, ast.ListComp | ast.SetComp | ast.GeneratorExp):
        return "a comprehension"
    if isinstance(expression, ast.Call):
        return "a call"
    if isinstance(expression, ast.Starred):
        return "a splat"
    if isinstance(expression, ast.IfExp):
        return "a conditional expression"
    return "a computed expression"


def dynamic_element_shape(element: ast.expr) -> str | None:
    """The same question for one entry inside a literal list.

    Calls and names inside a list are left to each adapter, which reads
    them as tool constructors or tool references. Only a splat, a
    comprehension, or a conditional expression in an entry is dynamic.
    """

    if isinstance(element, ast.Starred):
        return "a splat"
    if isinstance(element, ast.ListComp | ast.SetComp | ast.GeneratorExp):
        return "a comprehension"
    if isinstance(element, ast.IfExp):
        return "a conditional expression"
    return None


class _BuiltNames(ast.NodeVisitor):
    def __init__(self) -> None:
        self.built: dict[str, str] = {}
        self._loop_depth = 0

    def _record(self, name: str, shape: str) -> None:
        # A loop that appends is the more specific description, so it is
        # never overwritten by a later, plainer one.
        if self.built.get(name) != "a list a loop appends to":
            self.built[name] = shape

    def _mutation(self) -> str:
        if self._loop_depth:
            return "a list a loop appends to"
        return "a list appended to after it is built"

    def _visit_loop(self, node: ast.For | ast.AsyncFor | ast.While) -> None:
        self._loop_depth += 1
        self.generic_visit(node)
        self._loop_depth -= 1

    visit_For = _visit_loop
    visit_AsyncFor = _visit_loop
    visit_While = _visit_loop

    def visit_Assign(self, node: ast.Assign) -> None:
        shape = dynamic_shape(node.value)
        if shape is not None:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._record(target.id, shape)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        if isinstance(node.target, ast.Name):
            self._record(node.target.id, self._mutation())
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr in _MUTATING_METHODS
            and isinstance(func.value, ast.Name)
        ):
            self._record(func.value.id, self._mutation())
        self.generic_visit(node)


def runtime_built_names(tree: ast.AST) -> dict[str, str]:
    """Names the module builds at runtime, each with a description.

    Scope-blind on purpose: a name built anywhere in the module is
    treated as built everywhere. Over-reporting a runtime registration
    costs a reviewer a look; under-reporting one is a confident pass.
    """

    visitor = _BuiltNames()
    visitor.visit(tree)
    return visitor.built


def appended_agent_tools(tree: ast.AST) -> tuple[tuple[str, int], ...]:
    """`(variable, line)` for each `agent.tools.append(...)`,
    `agent.tools.extend(...)`, `agent.tools.insert(...)`, or
    `agent.tools += ...` on a bare variable, in source order."""

    found: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        target: ast.expr | None = None
        line = 0
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr in _MUTATING_METHODS:
                target, line = func.value, node.lineno
        elif isinstance(node, ast.AugAssign):
            target, line = node.target, node.lineno
        if (
            isinstance(target, ast.Attribute)
            and target.attr == _TOOLS_ATTRIBUTE
            and isinstance(target.value, ast.Name)
        ):
            found.append((target.value.id, line))
    return tuple(sorted(found, key=lambda item: (item[1], item[0])))


def located(adapter: str, relative_path: str, line: int) -> tuple[Evidence, ...]:
    """Evidence naming a line, which is what links an
    `INCOMPLETE-DYNAMIC-REGISTRATION` diagnostic to its unknown node."""

    return (Evidence(adapter=adapter, path=relative_path, line_start=line),)


def mark_dynamic(node: Node, evidence: tuple[Evidence, ...]) -> Node:
    """The unknown tool node for a runtime registration.

    `Confidence.UNKNOWN`, rather than the `LOW` an unresolved reference
    gets, and carrying the diagnostic's own located evidence:
    `policy.unresolved-dynamic-registration` correlates the two by
    `(path, line_start)`. Evidence is excluded from the diff, so a line
    number moving never makes the node look changed.
    """

    merged = list(node.evidence)
    for item in evidence:
        if item not in merged and len(merged) < _MAX_EVIDENCE:
            merged.append(item)
    return node.model_copy(
        update={"confidence": Confidence.UNKNOWN, "evidence": tuple(merged)}
    )


__all__ = [
    "appended_agent_tools",
    "dynamic_element_shape",
    "dynamic_shape",
    "located",
    "mark_dynamic",
    "runtime_built_names",
]
