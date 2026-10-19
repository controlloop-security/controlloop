"""Tests for the LangGraph adapter.

The tests that carry the most weight are the ones about what the adapter
*cannot* see. A graph that routes at runtime, or binds tools it computes,
must never be reported as smaller than it is.
"""

from __future__ import annotations

import ast
import json
from collections.abc import Mapping
from pathlib import Path

import pytest

from controlloop.acbom import EdgeType
from controlloop.adapters import (
    ALL_ADAPTERS,
    LangGraphAdapter,
    ScanContext,
    run_adapters,
)
from controlloop.adapters.framework import DiscoveryResult
from controlloop.capability.blast_radius import compute_blast_radius
from controlloop.capability.taxonomy import (
    MaterialCapabilityClass,
    classify_material_capability,
)
from controlloop.repository import RepositoryRoot

_PYPROJECT = """
[project]
name = "research-graph"
version = "0.1.0"
dependencies = ["langgraph>=0.4.0"]
"""

_CONFIG: Mapping[str, object] = {
    "dependencies": ["langchain_openai", "."],
    "graphs": {"agent": "./agent.py:graph"},
    "python_version": "3.12",
}

_MODULE = """
from langgraph.graph import StateGraph, START, END
from langgraph.prebuilt import ToolNode
from langchain_community.tools import TavilySearchResults

builder = StateGraph(dict)
builder.add_node("plan", plan_step)
builder.add_node("research", ToolNode([TavilySearchResults()]))
builder.add_node("write", write_step)

builder.add_edge(START, "plan")
builder.add_conditional_edges("plan", route, {"research": "research", "write": "write"})
builder.add_edge("research", "write")
builder.add_edge("write", END)

graph = builder.compile()
"""


def _project(
    tmp_path: Path,
    *,
    config: Mapping[str, object] | None = None,
    module: str | None = _MODULE,
    pyproject: str | None = _PYPROJECT,
) -> Path:
    (tmp_path / "langgraph.json").write_text(
        json.dumps(config if config is not None else _CONFIG), encoding="utf-8"
    )
    if pyproject is not None:
        (tmp_path / "pyproject.toml").write_text(pyproject, encoding="utf-8")
    if module is not None:
        (tmp_path / "agent.py").write_text(module, encoding="utf-8")
    return tmp_path


def _run(root: Path) -> DiscoveryResult:
    return run_adapters(
        [LangGraphAdapter()], ScanContext(root=RepositoryRoot(path=root))
    )


def _names(result: DiscoveryResult, subtype: str) -> set[str]:
    return {node.name for node in result.nodes if node.subtype == subtype}


def _codes(result: DiscoveryResult) -> list[str]:
    return [d.code for d in result.diagnostics]


def _edge_pairs(result: DiscoveryResult, edge_type: EdgeType) -> set[tuple[str, str]]:
    by_id = {node.id: node.name for node in result.nodes}
    return {
        (by_id[edge.source], by_id[edge.target])
        for edge in result.edges
        if edge.type is edge_type
    }


# --------------------------------------------------------------------
# The manifest
# --------------------------------------------------------------------


class TestApplicationDiscovery:
    def test_each_declared_graph_becomes_an_agent(self, tmp_path: Path) -> None:
        result = _run(_project(tmp_path))
        assert _names(result, "langgraph-graph") == {"agent"}

    def test_a_graph_naming_a_missing_module_is_reported(self, tmp_path: Path) -> None:
        """An unresolvable target is a diagnostic, never a silently
        missing graph."""

        result = _run(_project(tmp_path, module=None))
        assert "INCOMPLETE-UNRESOLVED-REFERENCE" in _codes(result)
        assert _names(result, "langgraph-graph") == {"agent"}

    @pytest.mark.parametrize("target", ["agent.py", "no-attribute:", ":graph"])
    def test_a_malformed_target_is_reported(self, tmp_path: Path, target: str) -> None:
        config = {**_CONFIG, "graphs": {"agent": target}}
        result = _run(_project(tmp_path, config=config))
        assert "INCOMPLETE-UNRESOLVED-REFERENCE" in _codes(result)

    def test_an_env_mapping_contributes_names_only(self, tmp_path: Path) -> None:
        """Keys become scopes; values are never touched."""

        config = {**_CONFIG, "env": {"OPENAI_API_KEY": "sk-not-a-real-key"}}
        result = _run(_project(tmp_path, config=config))

        graph = next(n for n in result.nodes if n.subtype == "langgraph-graph")
        assert graph.security_attributes.permission_scopes == ("env:OPENAI_API_KEY",)
        assert "sk-not-a-real-key" not in json.dumps(result.model_dump(mode="json"))

    def test_an_env_path_is_declared_but_never_opened(self, tmp_path: Path) -> None:
        """The names-only rule, applied more strongly. `env` is usually a
        path to a `.env` file holding real values. The adapter records
        that one is declared and does not read it -- an adapter that
        parsed it would be one bug away from putting a credential in an
        ACBOM."""

        canary = "AKIAIOSFODNN7EXAMPLE"
        (tmp_path / ".env").write_text(
            f"AWS_ACCESS_KEY_ID={canary}\n", encoding="utf-8"
        )
        config = {**_CONFIG, "env": "./.env"}
        result = _run(_project(tmp_path, config=config))

        graph = next(n for n in result.nodes if n.subtype == "langgraph-graph")
        assert graph.security_attributes.permission_scopes == ("env:declared-env-file",)
        assert canary not in json.dumps(result.model_dump(mode="json"))

    def test_declared_dependencies_are_never_installed_or_fetched(
        self, tmp_path: Path
    ) -> None:
        """Recorded as evidence only; the module never imports anything
        a repository names."""

        result = _run(_project(tmp_path))
        assert result.nodes

    def test_a_malformed_config_is_a_diagnostic_not_a_crash(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "langgraph.json").write_text("{ not json", encoding="utf-8")
        result = _run(tmp_path)
        assert "INCOMPLETE-UNPARSED-REGION" in _codes(result)


class TestVersionGovernance:
    def test_an_unsupported_version_is_refused(self, tmp_path: Path) -> None:
        """Checked against the shared framework-version registry rather
        than a copy of it."""

        pyproject = _PYPROJECT.replace("langgraph>=0.4.0", "langgraph>=99.0.0")
        result = _run(_project(tmp_path, pyproject=pyproject))
        assert result.nodes == ()
        assert "INCOMPLETE-UNPARSED-REGION" in _codes(result)

    def test_an_undeclared_version_is_refused(self, tmp_path: Path) -> None:
        result = _run(_project(tmp_path, pyproject=None))
        assert result.nodes == ()

    def test_a_version_declared_only_in_langgraph_json_is_accepted(
        self, tmp_path: Path
    ) -> None:
        config = {**_CONFIG, "dependencies": ["langgraph>=0.4.0", "."]}
        result = _run(_project(tmp_path, config=config, pyproject=None))
        assert _names(result, "langgraph-graph") == {"agent"}


# --------------------------------------------------------------------
# Topology
# --------------------------------------------------------------------


class TestGraphTopology:
    def test_add_node_becomes_nodes(self, tmp_path: Path) -> None:
        result = _run(_project(tmp_path))
        assert _names(result, "langgraph-node") == {"plan", "research", "write"}

    def test_add_edge_becomes_edges(self, tmp_path: Path) -> None:
        pairs = _edge_pairs(_run(_project(tmp_path)), EdgeType.DELEGATES_TO)
        assert ("research", "write") in pairs

    def test_every_branch_of_a_conditional_router_is_reachable(
        self, tmp_path: Path
    ) -> None:
        """The requirement this adapter exists to get right.
        LangGraph picks one branch at runtime; a scanner that picked one
        would report a graph narrower than the one that runs."""

        pairs = _edge_pairs(_run(_project(tmp_path)), EdgeType.DELEGATES_TO)
        assert ("plan", "research") in pairs
        assert ("plan", "write") in pairs

    def test_a_list_path_map_also_yields_every_branch(self, tmp_path: Path) -> None:
        module = _MODULE.replace(
            '{"research": "research", "write": "write"}', '["research", "write"]'
        )
        pairs = _edge_pairs(
            _run(_project(tmp_path, module=module)), EdgeType.DELEGATES_TO
        )
        assert ("plan", "research") in pairs
        assert ("plan", "write") in pairs

    def test_a_router_with_unenumerable_targets_is_reported(
        self, tmp_path: Path
    ) -> None:
        """Not fully analyzed, and it says so."""

        module = _MODULE.replace(
            '{"research": "research", "write": "write"}', "computed_map"
        )
        result = _run(_project(tmp_path, module=module))
        assert "INCOMPLETE-UNRESOLVED-REFERENCE" in _codes(result)

    def test_start_and_end_sentinels_are_not_dynamic_construction(
        self, tmp_path: Path
    ) -> None:
        """A false alarm on every idiomatic graph would teach readers to
        ignore the real ones."""

        result = _run(_project(tmp_path))
        assert not any("built dynamically" in d.message for d in result.diagnostics)

    def test_a_dynamically_built_graph_is_reported(self, tmp_path: Path) -> None:
        """A graph whose nodes are added in a loop is reported as built
        dynamically."""

        module = """
from langgraph.graph import StateGraph
builder = StateGraph(dict)
for name in step_names:
    builder.add_node(name, make_step(name))
graph = builder.compile()
"""
        result = _run(_project(tmp_path, module=module))
        assert any("built dynamically" in d.message for d in result.diagnostics)

    def test_a_cyclic_graph_terminates(self, tmp_path: Path) -> None:
        """LangGraph cycles are ordinary; discovery must not be the
        thing that cannot handle them."""

        module = """
from langgraph.graph import StateGraph
builder = StateGraph(dict)
builder.add_node("a", step)
builder.add_node("b", step)
builder.add_edge("a", "b")
builder.add_edge("b", "a")
graph = builder.compile()
"""
        result = _run(_project(tmp_path, module=module))
        pairs = _edge_pairs(result, EdgeType.DELEGATES_TO)
        assert ("a", "b") in pairs
        assert ("b", "a") in pairs

    def test_unparseable_python_is_a_diagnostic_not_a_crash(
        self, tmp_path: Path
    ) -> None:
        result = _run(_project(tmp_path, module="def broken( :\n"))
        assert "INCOMPLETE-UNPARSED-REGION" in _codes(result)


# --------------------------------------------------------------------
# Tool binding
# --------------------------------------------------------------------


class TestToolBinding:
    def test_a_literal_tool_node_becomes_a_tool(self, tmp_path: Path) -> None:
        result = _run(_project(tmp_path))
        assert "TavilySearchResults" in _names(result, "langgraph-tool")

    def test_bind_tools_is_read_too(self, tmp_path: Path) -> None:
        module = _MODULE.replace(
            "ToolNode([TavilySearchResults()])", "model.bind_tools([SearchTool()])"
        )
        result = _run(_project(tmp_path, module=module))
        assert "SearchTool" in _names(result, "langgraph-tool")

    def test_a_computed_binding_is_reported(self, tmp_path: Path) -> None:
        """A computed tool binding is a diagnostic, not a silent omission."""

        module = _MODULE.replace(
            "ToolNode([TavilySearchResults()])", "ToolNode(build_tools())"
        )
        result = _run(_project(tmp_path, module=module))
        assert "INCOMPLETE-UNRESOLVED-REFERENCE" in _codes(result)

    def test_a_computed_binding_still_produces_a_node(self, tmp_path: Path) -> None:
        """An omitted binding leaves a graph that classifies to
        nothing, which reports 'no material capability is reachable'."""

        module = _MODULE.replace(
            "ToolNode([TavilySearchResults()])", "ToolNode(build_tools())"
        )
        result = _run(_project(tmp_path, module=module))
        unknown = [
            n for n in result.nodes if n.security_attributes.destructive == "unknown"
        ]
        assert len(unknown) == 1

    def test_an_unresolved_binding_classifies_as_unclassified(
        self, tmp_path: Path
    ) -> None:
        module = _MODULE.replace(
            "ToolNode([TavilySearchResults()])", "ToolNode(build_tools())"
        )
        result = _run(_project(tmp_path, module=module))
        node = next(
            n for n in result.nodes if n.security_attributes.destructive == "unknown"
        )
        assert MaterialCapabilityClass.UNCLASSIFIED in classify_material_capability(
            node.security_attributes, edge_type=EdgeType.INVOKES
        )

    def test_an_unresolved_binding_never_yields_no_material_capability(
        self, tmp_path: Path
    ) -> None:
        """The same guarantee, end to end against the real blast-radius
        computation."""

        module = _MODULE.replace(
            "ToolNode([TavilySearchResults()])", "ToolNode(build_tools())"
        )
        result = _run(_project(tmp_path, module=module))
        assert compute_blast_radius(result.nodes, result.edges) is not None

    def test_a_fully_resolved_graph_carries_no_unknown_attributes(
        self, tmp_path: Path
    ) -> None:
        result = _run(_project(tmp_path))
        for node in result.nodes:
            assert "unknown" not in node.security_attributes.model_dump().values()


# --------------------------------------------------------------------
# Safety, detection, determinism
# --------------------------------------------------------------------


class TestNeverExecutesRepositoryCode:
    def test_the_module_imports_no_execution_primitive(self) -> None:
        source = Path("src/controlloop/adapters/langgraph.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        assert not imported & {"importlib", "subprocess", "socket", "runpy"}

        called = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        assert not called & {"eval", "exec", "compile", "__import__"}

    def test_a_module_that_would_crash_on_import_still_scans(
        self, tmp_path: Path
    ) -> None:
        module = "raise RuntimeError('importing me is a bug')\n" + _MODULE
        result = _run(_project(tmp_path, module=module))
        assert _names(result, "langgraph-node") == {"plan", "research", "write"}


class TestDetection:
    def test_a_project_without_langgraph_json_is_not_claimed(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "agent.py").write_text(_MODULE, encoding="utf-8")
        detection = LangGraphAdapter().detect(
            ScanContext(root=RepositoryRoot(path=tmp_path))
        )
        assert detection.claimed_paths == ()

    def test_the_adapter_is_registered(self) -> None:
        assert LangGraphAdapter in ALL_ADAPTERS


class TestDeterminism:
    def test_identical_input_produces_an_identical_result(self, tmp_path: Path) -> None:
        root = _project(tmp_path)
        first, second = _run(root), _run(root)
        assert [n.id for n in first.nodes] == [n.id for n in second.nodes]
        assert [e.id for e in first.edges] == [e.id for e in second.edges]
