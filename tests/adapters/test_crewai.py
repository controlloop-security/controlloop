"""The CrewAI adapter: agents and delegation, then tools.

The tests that matter most here are the negative ones. A framework
adapter that finds agents but silently misses tools is not a partial
success; it produces a confident pass over an agent nobody has read.
Every "cannot resolve" case therefore asserts two things: that a
diagnostic was emitted, and that the graph still carries a node the
blast radius will report.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from controlloop.acbom import Confidence, EdgeType, NodeType
from controlloop.adapters import ALL_ADAPTERS, CrewAiAdapter, ScanContext, run_adapters
from controlloop.adapters.framework import DiscoveryResult
from controlloop.capability.blast_radius import compute_blast_radius
from controlloop.capability.taxonomy import (
    MaterialCapabilityClass,
    classify_material_capability,
)
from controlloop.repository import RepositoryRoot

_PYPROJECT = """
[project]
name = "research-crew"
version = "0.1.0"
dependencies = ["crewai>=0.86.0"]
"""

_AGENTS = """
researcher:
  role: Senior Research Analyst
  goal: Find and summarize information
  allow_delegation: true
writer:
  role: Content Writer
  goal: Turn research into prose
  allow_delegation: false
"""


def _project(
    tmp_path: Path,
    *,
    agents: str = _AGENTS,
    crew: str | None = None,
    pyproject: str | None = _PYPROJECT,
) -> Path:
    (tmp_path / "config").mkdir(parents=True, exist_ok=True)
    (tmp_path / "config" / "agents.yaml").write_text(agents, encoding="utf-8")
    if pyproject is not None:
        (tmp_path / "pyproject.toml").write_text(pyproject, encoding="utf-8")
    if crew is not None:
        (tmp_path / "src" / "demo").mkdir(parents=True, exist_ok=True)
        (tmp_path / "src" / "demo" / "crew.py").write_text(crew, encoding="utf-8")
    return tmp_path


def _run(root: Path) -> DiscoveryResult:
    return run_adapters([CrewAiAdapter()], ScanContext(root=RepositoryRoot(path=root)))


def _codes(result: DiscoveryResult) -> list[str]:
    return [diagnostic.code for diagnostic in result.diagnostics]


def _names(result: DiscoveryResult, node_type: NodeType) -> set[str]:
    return {node.name for node in result.nodes if node.type == node_type}


# --------------------------------------------------------------------
# Agents and delegation
# --------------------------------------------------------------------


class TestAgentDiscovery:
    def test_each_entry_becomes_an_agent_named_by_its_role(
        self, tmp_path: Path
    ) -> None:
        """Each entry becomes an agent node, named by its role."""

        result = _run(_project(tmp_path))
        assert _names(result, NodeType.AGENT) == {
            "Senior Research Analyst",
            "Content Writer",
        }

    def test_identity_comes_from_the_yaml_key_not_the_role(
        self, tmp_path: Path
    ) -> None:
        """`role` is a display label a human edits, and display labels are
        never identity input. Renaming the role must not change the node
        id."""

        first = _run(_project(tmp_path))
        renamed = _AGENTS.replace("Senior Research Analyst", "Principal Analyst")
        second = _run(_project(tmp_path, agents=renamed))

        assert {node.id for node in first.nodes} == {node.id for node in second.nodes}
        assert "Principal Analyst" in _names(second, NodeType.AGENT)

    def test_an_entry_with_no_role_falls_back_to_its_key(self, tmp_path: Path) -> None:
        result = _run(_project(tmp_path, agents="analyst:\n  goal: something\n"))
        assert _names(result, NodeType.AGENT) == {"analyst"}

    def test_allow_delegation_produces_edges_to_the_other_agents(
        self, tmp_path: Path
    ) -> None:
        """`allow_delegation` yields an edge to each other agent."""

        result = _run(_project(tmp_path))
        delegations = [
            edge for edge in result.edges if edge.type == EdgeType.DELEGATES_TO
        ]
        by_id = {node.id: node.name for node in result.nodes}
        assert [(by_id[edge.source], by_id[edge.target]) for edge in delegations] == [
            ("Senior Research Analyst", "Content Writer")
        ]

    def test_delegation_false_produces_no_edge(self, tmp_path: Path) -> None:
        """The negative half: no delegation, no edge."""

        agents = _AGENTS.replace("allow_delegation: true", "allow_delegation: false")
        result = _run(_project(tmp_path, agents=agents))
        assert not [e for e in result.edges if e.type == EdgeType.DELEGATES_TO]

    def test_an_agent_never_delegates_to_itself(self, tmp_path: Path) -> None:
        result = _run(_project(tmp_path))
        assert all(edge.source != edge.target for edge in result.edges)

    def test_a_hierarchical_process_is_disclosed(self, tmp_path: Path) -> None:
        """The manager's fan-out is real authority; a crew that
        declares one and says nothing would understate reach."""

        crew = (
            "from crewai import Crew, Process\nc = Crew(process=Process.hierarchical)\n"
        )
        result = _run(_project(tmp_path, crew=crew))
        assert "INCOMPLETE-UNRESOLVED-REFERENCE" in _codes(result)
        assert any("hierarchical" in d.message for d in result.diagnostics)

    def test_an_overridden_agents_config_is_disclosed(self, tmp_path: Path) -> None:
        """Silently discovering nothing is the failure."""

        crew = "class C:\n    agents_config = 'other/agents.yaml'\n"
        result = _run(_project(tmp_path, crew=crew))
        assert any("agents_config" in d.message for d in result.diagnostics)


class TestMalformedInput:
    def test_unreadable_yaml_becomes_a_diagnostic(self, tmp_path: Path) -> None:
        """Unreadable YAML is a diagnostic, not a crash."""

        result = _run(_project(tmp_path, agents="{ not: valid: yaml: ["))
        assert "INCOMPLETE-UNPARSED-REGION" in _codes(result)
        assert result.nodes == ()

    def test_one_bad_entry_does_not_discard_the_others(self, tmp_path: Path) -> None:
        """Isolation, not collapse."""

        agents = "researcher:\n  role: Analyst\nbroken: 'not a mapping'\n"
        result = _run(_project(tmp_path, agents=agents))
        assert _names(result, NodeType.AGENT) == {"Analyst"}
        assert "INCOMPLETE-UNPARSED-REGION" in _codes(result)

    def test_a_non_mapping_top_level_is_refused(self, tmp_path: Path) -> None:
        result = _run(_project(tmp_path, agents="- just\n- a\n- list\n"))
        assert result.nodes == ()
        assert "INCOMPLETE-UNPARSED-REGION" in _codes(result)

    def test_unparseable_python_becomes_a_diagnostic_not_a_crash(
        self, tmp_path: Path
    ) -> None:
        result = _run(_project(tmp_path, crew="def broken( :\n"))
        assert "INCOMPLETE-UNPARSED-REGION" in _codes(result)
        assert _names(result, NodeType.AGENT)


class TestVersionGovernance:
    def test_an_unsupported_version_is_refused_not_parsed(self, tmp_path: Path) -> None:
        """An unsupported framework version is refused, not parsed."""

        pyproject = _PYPROJECT.replace("crewai>=0.86.0", "crewai>=0.1.0")
        result = _run(_project(tmp_path, pyproject=pyproject))
        assert result.nodes == ()
        assert "INCOMPLETE-UNPARSED-REGION" in _codes(result)

    def test_an_undeclared_version_is_refused(self, tmp_path: Path) -> None:
        result = _run(_project(tmp_path, pyproject=None))
        assert result.nodes == ()
        assert any("not parsed" in d.message for d in result.diagnostics)


# --------------------------------------------------------------------
# Tools, and the unknowns that block
# --------------------------------------------------------------------

_RESOLVABLE = """
from crewai import Agent
from crewai_tools import FileWriterTool, SerperDevTool


class ResearchCrew:
    def researcher(self):
        return Agent(
            config=self.agents_config["researcher"],
            tools=[SerperDevTool(), FileWriterTool()],
        )
"""

_DYNAMIC = """
from crewai import Agent


class ResearchCrew:
    def researcher(self):
        return Agent(config=self.agents_config["researcher"], tools=self._pick())
"""


class TestToolResolution:
    def test_a_literal_list_becomes_tools_and_invokes_edges(
        self, tmp_path: Path
    ) -> None:
        """A literal tool list becomes tool nodes and invokes edges."""

        result = _run(_project(tmp_path, crew=_RESOLVABLE))
        assert _names(result, NodeType.TOOL) == {"SerperDevTool", "FileWriterTool"}
        invokes = [edge for edge in result.edges if edge.type == EdgeType.INVOKES]
        assert len(invokes) == 2

    def test_a_dotted_constructor_resolves(self, tmp_path: Path) -> None:
        crew = _RESOLVABLE.replace("SerperDevTool()", "tools.SerperDevTool()")
        result = _run(_project(tmp_path, crew=crew))
        assert "SerperDevTool" in _names(result, NodeType.TOOL)

    @pytest.mark.parametrize(
        "expression",
        [
            "self._pick()",
            "[t for t in self.all_tools]",
            "[SerperDevTool()] if flag else []",
            "[*base_tools]",
            "[SerperDevTool(), *base_tools]",
        ],
        ids=["call", "comprehension", "conditional", "splat", "splat-entry"],
    )
    def test_every_runtime_shape_is_a_dynamic_registration(
        self, tmp_path: Path, expression: str
    ) -> None:
        """Each of these is a shape a real project writes. None of them
        can be enumerated statically, so each is a dynamic registration
        rather than an unresolved reference."""

        crew = _DYNAMIC.replace("self._pick()", expression)
        result = _run(_project(tmp_path, crew=crew))
        assert "INCOMPLETE-DYNAMIC-REGISTRATION" in _codes(result)
        assert "INCOMPLETE-UNRESOLVED-REFERENCE" not in _codes(result)

    def test_a_bare_name_stays_an_unresolved_reference(self, tmp_path: Path) -> None:
        """A name the adapter did not follow is one step of resolution it
        declines to take, not a runtime registration."""

        crew = _DYNAMIC.replace("self._pick()", "TOOLS")
        result = _run(_project(tmp_path, crew=crew))
        assert "INCOMPLETE-UNRESOLVED-REFERENCE" in _codes(result)
        assert "INCOMPLETE-DYNAMIC-REGISTRATION" not in _codes(result)

    def test_a_literal_list_is_neither(self, tmp_path: Path) -> None:
        result = _run(_project(tmp_path, crew=_RESOLVABLE))
        assert "INCOMPLETE-DYNAMIC-REGISTRATION" not in _codes(result)
        assert "INCOMPLETE-UNRESOLVED-REFERENCE" not in _codes(result)

    def test_a_list_a_loop_appends_to_is_dynamic(self, tmp_path: Path) -> None:
        """`@tool`-decorated functions collected by a loop: the list the
        agent receives exists only once the loop has run."""

        crew = """
from crewai import Agent
from crewai.tools import tool


@tool("Search")
def search(query: str) -> str:
    return query


@tool("Fetch")
def fetch(url: str) -> str:
    return url


TOOLS = []
for candidate in (search, fetch):
    TOOLS.append(candidate)


class ResearchCrew:
    def researcher(self):
        return Agent(config=self.agents_config["researcher"], tools=TOOLS)
"""
        result = _run(_project(tmp_path, crew=crew))
        dynamic = [
            d for d in result.diagnostics if d.code == "INCOMPLETE-DYNAMIC-REGISTRATION"
        ]
        assert len(dynamic) == 1
        assert "a loop appends to" in dynamic[0].message

    def test_tools_appended_after_construction_are_dynamic(
        self, tmp_path: Path
    ) -> None:
        crew = """
from crewai import Agent
from crewai_tools import SerperDevTool


class ResearchCrew:
    def researcher(self):
        agent = Agent(config=self.agents_config["researcher"])
        agent.tools.append(SerperDevTool())
        return agent
"""
        result = _run(_project(tmp_path, crew=crew))
        dynamic = [
            d for d in result.diagnostics if d.code == "INCOMPLETE-DYNAMIC-REGISTRATION"
        ]
        assert len(dynamic) == 1
        assert dynamic[0].evidence[0].line_start == 9
        assert "after it is constructed" in dynamic[0].message

    def test_a_dynamic_registration_is_linked_to_its_unknown_node(
        self, tmp_path: Path
    ) -> None:
        """`policy.unresolved-dynamic-registration` attributes the
        diagnostic to a node at `Confidence.UNKNOWN` sharing its
        `(path, line_start)`, reached from the agent by `invokes`."""

        result = _run(_project(tmp_path, crew=_DYNAMIC))
        diagnostic = next(
            d for d in result.diagnostics if d.code == "INCOMPLETE-DYNAMIC-REGISTRATION"
        )
        location = (diagnostic.evidence[0].path, diagnostic.evidence[0].line_start)
        assert location == ("src/demo/crew.py", 7)
        tool = next(n for n in result.nodes if n.type == NodeType.TOOL)
        assert tool.confidence is Confidence.UNKNOWN
        assert location in {(e.path, e.line_start) for e in tool.evidence}
        assert any(
            edge.type == EdgeType.INVOKES and edge.target == tool.id
            for edge in result.edges
        )

    def test_an_unresolved_reference_node_is_not_marked_dynamic(
        self, tmp_path: Path
    ) -> None:
        crew = _DYNAMIC.replace("self._pick()", "TOOLS")
        result = _run(_project(tmp_path, crew=crew))
        tool = next(n for n in result.nodes if n.type == NodeType.TOOL)
        assert tool.confidence is Confidence.LOW

    def test_an_unresolved_tool_still_produces_a_node(self, tmp_path: Path) -> None:
        """Why an unresolved tool must still be a node: an omitted tool
        leaves a graph that classifies to nothing, which reports 'no
        material capability is reachable' -- the confident pass this
        adapter exists to prevent."""

        result = _run(_project(tmp_path, crew=_DYNAMIC))
        tools = [node for node in result.nodes if node.type == NodeType.TOOL]
        assert len(tools) == 1
        assert tools[0].security_attributes.destructive == "unknown"

    def test_an_unresolved_tool_classifies_as_unclassified(
        self, tmp_path: Path
    ) -> None:
        """`UNCLASSIFIED` ranks worst in the taxonomy, so the blast radius
        reports the unknown tool rather than omitting it."""

        result = _run(_project(tmp_path, crew=_DYNAMIC))
        tool = next(n for n in result.nodes if n.type == NodeType.TOOL)
        assert MaterialCapabilityClass.UNCLASSIFIED in classify_material_capability(
            tool.security_attributes, edge_type=EdgeType.INVOKES
        )

    def test_an_unresolved_tool_never_yields_no_material_capability(
        self, tmp_path: Path
    ) -> None:
        """The same guarantee, asserted end to end against the real
        blast-radius computation rather than against the adapter's own
        output."""

        result = _run(_project(tmp_path, crew=_DYNAMIC))
        statement = compute_blast_radius(result.nodes, result.edges)
        assert statement is not None

    def test_a_resolved_only_crew_carries_no_unknown_attributes(
        self, tmp_path: Path
    ) -> None:
        """The negative half: resolution must not manufacture unknowns."""

        result = _run(_project(tmp_path, crew=_RESOLVABLE))
        assert result.diagnostics == ()
        for node in result.nodes:
            dumped = node.security_attributes.model_dump()
            assert "unknown" not in dumped.values()

    def test_an_unrecognized_tool_class_is_still_a_node(self, tmp_path: Path) -> None:
        """An unrecognized tool class is a node, never a dropped edge."""

        crew = _RESOLVABLE.replace("SerperDevTool()", "CompletelyUnknownTool()")
        result = _run(_project(tmp_path, crew=crew))
        assert "CompletelyUnknownTool" in _names(result, NodeType.TOOL)

    def test_an_agent_construction_matching_no_declared_agent_is_reported(
        self, tmp_path: Path
    ) -> None:
        crew = _RESOLVABLE.replace('"researcher"', '"ghost"')
        result = _run(_project(tmp_path, crew=crew))
        assert "INCOMPLETE-UNRESOLVED-REFERENCE" in _codes(result)

    def test_the_same_tool_used_twice_is_one_node(self, tmp_path: Path) -> None:
        crew = _RESOLVABLE.replace(
            "tools=[SerperDevTool(), FileWriterTool()]",
            "tools=[SerperDevTool(), SerperDevTool()]",
        )
        result = _run(_project(tmp_path, crew=crew))
        assert _names(result, NodeType.TOOL) == {"SerperDevTool"}


# --------------------------------------------------------------------
# Agents built in code, with no config/agents.yaml
# --------------------------------------------------------------------

_CODE_STATIC = """
from crewai import Agent, Crew
from crewai_tools import FileWriterTool, SerperDevTool

researcher = Agent(
    role="Researcher",
    goal="Find sources",
    backstory="Careful",
    tools=[SerperDevTool()],
    allow_delegation=True,
)
writer = Agent(
    role="Writer",
    goal="Write it up",
    backstory="Clear",
    tools=[FileWriterTool()],
)
crew = Crew(agents=[researcher, writer])
"""

_CODE_DYNAMIC = """
from crewai import Agent
from crewai.tools import tool


@tool("Search")
def search(query: str) -> str:
    return query


TOOLS = []
for candidate in (search,):
    TOOLS.append(candidate)

researcher = Agent(role="Researcher", goal="g", backstory="b", tools=TOOLS)
"""

_CODE_DECORATED = """
from crewai import Agent
from crewai.project import CrewBase, agent


@CrewBase
class ResearchCrew:
    @agent
    def researcher(self) -> Agent:
        return Agent(role="Researcher", goal="g", backstory="b", tools=self._pick())
"""


def _code_project(tmp_path: Path, module: str, name: str = "crew_app.py") -> Path:
    (tmp_path / "pyproject.toml").write_text(_PYPROJECT, encoding="utf-8")
    (tmp_path / name).write_text(module, encoding="utf-8")
    return tmp_path


class TestAgentsBuiltInCode:
    def test_each_agent_is_discovered_and_named_by_its_role(
        self, tmp_path: Path
    ) -> None:
        result = _run(_code_project(tmp_path, _CODE_STATIC))
        assert _names(result, NodeType.AGENT) == {"Researcher", "Writer"}

    def test_static_tools_resolve_with_no_unknowns(self, tmp_path: Path) -> None:
        result = _run(_code_project(tmp_path, _CODE_STATIC))
        assert _names(result, NodeType.TOOL) == {"SerperDevTool", "FileWriterTool"}
        invokes = [edge for edge in result.edges if edge.type == EdgeType.INVOKES]
        assert len(invokes) == 2
        assert not [code for code in _codes(result) if code.startswith("INCOMPLETE")]

    def test_allow_delegation_reaches_the_other_agents(self, tmp_path: Path) -> None:
        result = _run(_code_project(tmp_path, _CODE_STATIC))
        delegations = [e for e in result.edges if e.type == EdgeType.DELEGATES_TO]
        agents = {n.id: n.name for n in result.nodes if n.type == NodeType.AGENT}
        assert [(agents[e.source], agents[e.target]) for e in delegations] == [
            ("Researcher", "Writer")
        ]

    def test_identity_comes_from_the_variable_not_the_role(
        self, tmp_path: Path
    ) -> None:
        first = _run(_code_project(tmp_path, _CODE_STATIC))
        renamed = _run(
            _code_project(tmp_path, _CODE_STATIC.replace('"Researcher"', '"Analyst"'))
        )
        before = {n.id for n in first.nodes if n.type == NodeType.AGENT}
        after = {n.id for n in renamed.nodes if n.type == NodeType.AGENT}
        assert before == after

    def test_a_list_built_in_a_loop_is_a_dynamic_registration(
        self, tmp_path: Path
    ) -> None:
        result = _run(_code_project(tmp_path, _CODE_DYNAMIC))
        assert _names(result, NodeType.AGENT) == {"Researcher"}
        diagnostic = next(
            d for d in result.diagnostics if d.code == "INCOMPLETE-DYNAMIC-REGISTRATION"
        )
        location = (diagnostic.evidence[0].path, diagnostic.evidence[0].line_start)
        assert location == ("crew_app.py", 15)
        tool = next(n for n in result.nodes if n.type == NodeType.TOOL)
        assert tool.confidence is Confidence.UNKNOWN
        assert location in {(e.path, e.line_start) for e in tool.evidence}

    def test_tools_appended_after_construction_are_dynamic(
        self, tmp_path: Path
    ) -> None:
        module = _CODE_STATIC + "researcher.tools.append(extra_tool)\n"
        result = _run(_code_project(tmp_path, module))
        dynamic = [
            d for d in result.diagnostics if d.code == "INCOMPLETE-DYNAMIC-REGISTRATION"
        ]
        assert len(dynamic) == 1
        assert "'researcher'" in dynamic[0].message

    def test_an_agent_method_without_yaml_is_an_agent(self, tmp_path: Path) -> None:
        result = _run(_code_project(tmp_path, _CODE_DECORATED))
        assert _names(result, NodeType.AGENT) == {"Researcher"}
        assert "INCOMPLETE-DYNAMIC-REGISTRATION" in _codes(result)
        assert "unresolved-tools:researcher" in _names(result, NodeType.TOOL)

    def test_an_agent_nothing_names_is_reported(self, tmp_path: Path) -> None:
        module = (
            "from crewai import Agent, Crew\n"
            "crew = Crew(agents=[Agent(goal=compute(), tools=[SerperDevTool()])])\n"
        )
        result = _run(_code_project(tmp_path, module))
        assert _names(result, NodeType.AGENT) == set()
        assert "INCOMPLETE-UNRESOLVED-REFERENCE" in _codes(result)

    def test_a_splatted_config_is_not_an_agent_built_in_code(
        self, tmp_path: Path
    ) -> None:
        crew = _RESOLVABLE.replace(
            'config=self.agents_config["researcher"]',
            '**self.agents_config["researcher"]',
        )
        result = _run(_project(tmp_path, crew=crew))
        assert _names(result, NodeType.AGENT) == {
            "Senior Research Analyst",
            "Content Writer",
        }

    def test_a_yaml_project_is_unchanged(self, tmp_path: Path) -> None:
        """A YAML agent's identity does not move now that code agents
        exist."""

        result = _run(_project(tmp_path, crew=_RESOLVABLE))
        assert _names(result, NodeType.AGENT) == {
            "Senior Research Analyst",
            "Content Writer",
        }
        assert _names(result, NodeType.TOOL) == {"SerperDevTool", "FileWriterTool"}

    def test_a_module_that_imports_crewai_is_claimed(self, tmp_path: Path) -> None:
        root = _code_project(tmp_path, _CODE_STATIC)
        detection = CrewAiAdapter().detect(ScanContext(root=RepositoryRoot(path=root)))
        assert detection.claimed_paths == ("crew_app.py",)

    def test_a_module_naming_crewai_only_in_a_string_is_not_claimed(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "notes.py").write_text('NOTE = "see crewai"\n', encoding="utf-8")
        detection = CrewAiAdapter().detect(
            ScanContext(root=RepositoryRoot(path=tmp_path))
        )
        assert detection.claimed_paths == ()

    def test_a_code_only_crew_is_deterministic(self, tmp_path: Path) -> None:
        root = _code_project(tmp_path, _CODE_DYNAMIC)
        first, second = _run(root), _run(root)
        assert [n.id for n in first.nodes] == [n.id for n in second.nodes]
        assert [e.id for e in first.edges] == [e.id for e in second.edges]
        assert first.diagnostics == second.diagnostics


# --------------------------------------------------------------------
# Safety and determinism
# --------------------------------------------------------------------


class TestNeverExecutesRepositoryCode:
    def test_the_module_imports_no_execution_primitive(self) -> None:
        """The adapter never executes repository code, asserted
        structurally rather than by hoping a review notices."""

        source = Path("src/controlloop/adapters/crewai.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        assert not imported & {"importlib", "subprocess", "socket", "runpy"}

        called = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        assert not called & {"eval", "exec", "compile", "__import__"}

    def test_a_crew_that_would_crash_on_import_still_scans(
        self, tmp_path: Path
    ) -> None:
        """Parsing is not importing. This module raises at import time
        and is still analyzed correctly."""

        crew = "raise RuntimeError('importing me is a bug')\n" + _RESOLVABLE
        result = _run(_project(tmp_path, crew=crew))
        assert _names(result, NodeType.TOOL) == {"SerperDevTool", "FileWriterTool"}


class TestDetection:
    def test_a_crew_py_without_an_agents_config_is_not_claimed(
        self, tmp_path: Path
    ) -> None:
        """A stray `crew.py` in a non-CrewAI repository must not make
        this adapter claim it."""

        (tmp_path / "crew.py").write_text("x = 1\n", encoding="utf-8")
        adapter = CrewAiAdapter()
        detection = adapter.detect(ScanContext(root=RepositoryRoot(path=tmp_path)))
        assert detection.claimed_paths == ()

    def test_the_adapter_is_registered(self) -> None:
        assert CrewAiAdapter in ALL_ADAPTERS


class TestDeterminism:
    def test_identical_input_produces_an_identical_result(self, tmp_path: Path) -> None:
        root = _project(tmp_path, crew=_RESOLVABLE)
        first, second = _run(root), _run(root)
        assert [n.id for n in first.nodes] == [n.id for n in second.nodes]
        assert [e.id for e in first.edges] == [e.id for e in second.edges]
