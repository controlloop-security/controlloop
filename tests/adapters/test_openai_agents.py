"""Tests for the OpenAI Agents SDK adapter.

The distinguishing test in this file is
`test_a_tool_is_found_even_when_no_agent_holds_it`. `@function_tool`
marks a tool at its definition site, so the set of tools that exist is
knowable even when the set an agent holds is not -- a strictly better
degradation curve than CrewAI or LangGraph get, and the reason this SDK
earns an adapter despite shipping no configuration file.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from controlloop.acbom import Confidence, EdgeType, NodeType
from controlloop.adapters import (
    ALL_ADAPTERS,
    OpenAiAgentsAdapter,
    ScanContext,
    run_adapters,
)
from controlloop.adapters.framework import DiscoveryResult
from controlloop.capability.blast_radius import compute_blast_radius
from controlloop.capability.compute import compute_transitive_capability_paths
from controlloop.capability.taxonomy import (
    MaterialCapabilityClass,
    classify_material_capability,
)
from controlloop.repository import RepositoryRoot

_PYPROJECT = """
[project]
name = "support-desk"
version = "0.1.0"
dependencies = ["openai-agents>=0.2.0"]
"""

_MODULE = """
from agents import Agent, function_tool, handoff


@function_tool
def lookup_order(order_id: str) -> str:
    return "delivered"


@function_tool(name_override="issue-refund")
def refund(order_id: str, amount_cents: int) -> str:
    return "refunded"


escalation_agent = Agent(name="Escalation", tools=[refund])
billing_agent = Agent(name="Billing", handoffs=[escalation_agent])
triage_agent = Agent(
    name="Triage",
    tools=[lookup_order],
    handoffs=[handoff(billing_agent)],
)
"""


def _project(
    tmp_path: Path, *, module: str = _MODULE, pyproject: str | None = _PYPROJECT
) -> Path:
    (tmp_path / "desk.py").write_text(module, encoding="utf-8")
    if pyproject is not None:
        (tmp_path / "pyproject.toml").write_text(pyproject, encoding="utf-8")
    return tmp_path


def _run(root: Path) -> DiscoveryResult:
    return run_adapters(
        [OpenAiAgentsAdapter()], ScanContext(root=RepositoryRoot(path=root))
    )


def _names(result: DiscoveryResult, node_type: NodeType) -> set[str]:
    return {n.name for n in result.nodes if n.type == node_type}


def _codes(result: DiscoveryResult) -> list[str]:
    return [d.code for d in result.diagnostics]


def _pairs(result: DiscoveryResult, edge_type: EdgeType) -> set[tuple[str, str]]:
    by_id = {n.id: n.name for n in result.nodes}
    return {
        (by_id[e.source], by_id[e.target]) for e in result.edges if e.type is edge_type
    }


# --------------------------------------------------------------------
# Agents and handoffs
# --------------------------------------------------------------------


class TestAgentDiscovery:
    def test_each_agent_becomes_a_node(self, tmp_path: Path) -> None:
        result = _run(_project(tmp_path))
        assert _names(result, NodeType.AGENT) == {"Triage", "Billing", "Escalation"}

    def test_a_positional_name_is_read_too(self, tmp_path: Path) -> None:
        module = "from agents import Agent\nsolo = Agent('Solo')\n"
        assert _names(_run(_project(tmp_path, module=module)), NodeType.AGENT) == {
            "Solo"
        }

    def test_a_computed_name_is_reported_never_synthesized(
        self, tmp_path: Path
    ) -> None:
        """A made-up agent identity is worse than a missing one: a
        manifest would then be matched against a name no human wrote."""

        module = "from agents import Agent\nagent = Agent(name=build_name())\n"
        result = _run(_project(tmp_path, module=module))
        assert result.nodes == ()
        assert "INCOMPLETE-UNRESOLVED-REFERENCE" in _codes(result)


class TestHandoffs:
    def test_handoffs_become_delegates_to_edges(self, tmp_path: Path) -> None:
        """Through both spellings: a bare name and a `handoff(...)`
        wrapper."""

        pairs = _pairs(_run(_project(tmp_path)), EdgeType.DELEGATES_TO)
        assert ("Triage", "Billing") in pairs
        assert ("Billing", "Escalation") in pairs

    def test_a_multi_hop_chain_is_transitively_reachable(self, tmp_path: Path) -> None:
        """The capability a flat tool inventory cannot show: Triage
        reaches a refund tool it never names, through two hops.

        Asserted on the capability paths rather than the blast radius.
        The blast radius is `None` here, and correctly so -- nothing in
        an SDK project states that issuing a refund moves money, so no
        capability classifies until `controlloop.yaml` says what these
        tools do. The *reach* is what discovery establishes; the
        *severity* is what the manifest adds.
        """

        result = _run(_project(tmp_path))
        paths, _ = compute_transitive_capability_paths(result.nodes, result.edges)
        by_id = {node.id: node.name for node in result.nodes}

        reached = {
            (by_id[path.agent_id], by_id[path.target_id])
            for path in paths
            if len(path.hops) > 1
        }
        assert ("Triage", "issue-refund") in reached

    def test_an_inline_agent_handoff_resolves(self, tmp_path: Path) -> None:
        module = (
            "from agents import Agent\n"
            'a = Agent(name="A", handoffs=[Agent(name="B")])\n'
        )
        pairs = _pairs(_run(_project(tmp_path, module=module)), EdgeType.DELEGATES_TO)
        assert ("A", "B") in pairs

    def test_an_unresolvable_handoff_target_is_reported(self, tmp_path: Path) -> None:
        """Reported, never dropped."""

        module = (
            "from agents import Agent\n"
            'a = Agent(name="A", handoffs=[some_imported_agent])\n'
        )
        result = _run(_project(tmp_path, module=module))
        assert "INCOMPLETE-UNRESOLVED-REFERENCE" in _codes(result)

    def test_a_non_literal_handoffs_argument_is_reported(self, tmp_path: Path) -> None:
        module = (
            'from agents import Agent\na = Agent(name="A", handoffs=build_handoffs())\n'
        )
        result = _run(_project(tmp_path, module=module))
        assert "INCOMPLETE-DYNAMIC-REGISTRATION" in _codes(result)

    def test_a_bare_handoffs_name_stays_an_unresolved_reference(
        self, tmp_path: Path
    ) -> None:
        module = 'from agents import Agent\na = Agent(name="A", handoffs=TEAM)\n'
        result = _run(_project(tmp_path, module=module))
        assert "INCOMPLETE-UNRESOLVED-REFERENCE" in _codes(result)
        assert "INCOMPLETE-DYNAMIC-REGISTRATION" not in _codes(result)

    def test_a_splatted_handoff_is_dynamic(self, tmp_path: Path) -> None:
        """A handoff target is an agent, so a dynamic one gets the
        diagnostic but no invented node."""

        module = (
            "from agents import Agent\n"
            'b = Agent(name="B")\n'
            'a = Agent(name="A", handoffs=[b, *OTHERS])\n'
        )
        result = _run(_project(tmp_path, module=module))
        assert _codes(result) == ["INCOMPLETE-DYNAMIC-REGISTRATION"]
        assert ("A", "B") in _pairs(result, EdgeType.DELEGATES_TO)
        assert _names(result, NodeType.AGENT) == {"A", "B"}


class TestVersionGovernance:
    def test_an_unsupported_version_is_refused(self, tmp_path: Path) -> None:
        pyproject = _PYPROJECT.replace("openai-agents>=0.2.0", "openai-agents>=99.0")
        result = _run(_project(tmp_path, pyproject=pyproject))
        assert result.nodes == ()

    def test_an_undeclared_version_is_refused(self, tmp_path: Path) -> None:
        assert _run(_project(tmp_path, pyproject=None)).nodes == ()


# --------------------------------------------------------------------
# Tools, discovered at their definition site
# --------------------------------------------------------------------


class TestToolDiscovery:
    def test_a_decorated_function_becomes_a_tool(self, tmp_path: Path) -> None:
        result = _run(_project(tmp_path))
        assert "lookup_order" in _names(result, NodeType.TOOL)

    def test_name_override_wins(self, tmp_path: Path) -> None:
        """The override is what a manifest must match."""

        result = _run(_project(tmp_path))
        assert "issue-refund" in _names(result, NodeType.TOOL)
        assert "refund" not in _names(result, NodeType.TOOL)

    def test_a_tool_is_found_even_when_no_agent_holds_it(self, tmp_path: Path) -> None:
        """The structural advantage this SDK has. An unreferenced
        privileged function is exactly what a reviewer wants to see, and
        it is invisible to any adapter that only reads agent wiring."""

        module = (
            "from agents import function_tool\n"
            "@function_tool\n"
            "def purge_account(customer_id: str) -> str:\n"
            "    return 'purged'\n"
        )
        result = _run(_project(tmp_path, module=module))
        assert "purge_account" in _names(result, NodeType.TOOL)

    def test_a_tool_wired_to_nothing_is_reported_as_reachable_by_nothing(
        self, tmp_path: Path
    ) -> None:
        """Found, and said to be unreachable, rather than silently
        dropped."""

        module = _MODULE + (
            "\n@function_tool\n"
            "def purge_account(customer_id: str) -> str:\n"
            "    return 'purged'\n"
        )
        result = _run(_project(tmp_path, module=module))
        assert any("wired to no agent" in d.message for d in result.diagnostics)

    def test_parameter_names_are_recorded_and_nothing_else(
        self, tmp_path: Path
    ) -> None:
        """No default value, no docstring body, no literal argument --
        none of it is identity material or evidence."""

        canary = "sk-not-a-real-secret-value"
        module = (
            "from agents import function_tool\n"
            "@function_tool\n"
            f"def call_api(endpoint: str, token: str = '{canary}') -> str:\n"
            f'    """Docstring mentioning {canary}."""\n'
            "    return 'ok'\n"
        )
        result = _run(_project(tmp_path, module=module))
        tool = next(n for n in result.nodes if n.type is NodeType.TOOL)

        assert set(tool.security_attributes.permission_scopes) == {
            "param:endpoint",
            "param:token",
        }
        assert canary not in result.model_dump_json()

    def test_a_computed_name_override_is_reported(self, tmp_path: Path) -> None:
        """A computed `name_override` is a diagnostic, never a guessed
        name."""

        module = (
            "from agents import function_tool\n"
            "@function_tool(name_override=build_name())\n"
            "def thing() -> str:\n"
            "    return 'x'\n"
        )
        result = _run(_project(tmp_path, module=module))
        assert "INCOMPLETE-UNRESOLVED-REFERENCE" in _codes(result)


# --------------------------------------------------------------------
# Wiring
# --------------------------------------------------------------------


class TestWiring:
    def test_a_literal_tools_list_produces_invokes_edges(self, tmp_path: Path) -> None:
        pairs = _pairs(_run(_project(tmp_path)), EdgeType.INVOKES)
        assert ("Triage", "lookup_order") in pairs
        assert ("Escalation", "issue-refund") in pairs

    def test_a_non_literal_tools_list_is_reported(self, tmp_path: Path) -> None:
        module = "from agents import Agent\na = Agent(name='A', tools=load())\n"
        result = _run(_project(tmp_path, module=module))
        assert "INCOMPLETE-DYNAMIC-REGISTRATION" in _codes(result)

    @pytest.mark.parametrize(
        "expression",
        [
            "load()",
            "[t for t in REGISTRY]",
            "[lookup] if fast else []",
            "[*BASE]",
            "[lookup, *EXTRA]",
        ],
        ids=["call", "comprehension", "conditional", "splat", "splat-entry"],
    )
    def test_every_runtime_shape_is_a_dynamic_registration(
        self, tmp_path: Path, expression: str
    ) -> None:
        module = (
            "from agents import Agent, function_tool\n"
            "@function_tool\n"
            "def lookup(q: str) -> str:\n"
            "    return q\n"
            f"a = Agent(name='A', tools={expression})\n"
        )
        result = _run(_project(tmp_path, module=module))
        assert "INCOMPLETE-DYNAMIC-REGISTRATION" in _codes(result)
        assert not any(
            "could not be resolved to a declared function tool" in d.message
            for d in result.diagnostics
        )

    def test_a_list_a_loop_appends_to_is_dynamic(self, tmp_path: Path) -> None:
        module = (
            "from agents import Agent\n"
            "tools = []\n"
            "for name in NAMES:\n"
            "    tools.append(make(name))\n"
            "a = Agent(name='A', tools=tools)\n"
        )
        result = _run(_project(tmp_path, module=module))
        assert _codes(result) == ["INCOMPLETE-DYNAMIC-REGISTRATION"]
        assert "a loop appends to" in result.diagnostics[0].message

    def test_tools_appended_after_construction_are_dynamic(
        self, tmp_path: Path
    ) -> None:
        module = (
            "from agents import Agent\n"
            "a = Agent(name='A')\n"
            "a.tools.extend(load_more())\n"
        )
        result = _run(_project(tmp_path, module=module))
        assert _codes(result) == ["INCOMPLETE-DYNAMIC-REGISTRATION"]
        diagnostic = result.diagnostics[0]
        assert diagnostic.evidence[0].line_start == 3
        assert "after it is constructed" in diagnostic.message

    def test_a_bare_tools_name_stays_an_unresolved_reference(
        self, tmp_path: Path
    ) -> None:
        module = "from agents import Agent\na = Agent(name='A', tools=IMPORTED)\n"
        result = _run(_project(tmp_path, module=module))
        assert "INCOMPLETE-UNRESOLVED-REFERENCE" in _codes(result)
        assert "INCOMPLETE-DYNAMIC-REGISTRATION" not in _codes(result)

    def test_a_literal_tools_list_is_neither(self, tmp_path: Path) -> None:
        result = _run(_project(tmp_path))
        assert "INCOMPLETE-DYNAMIC-REGISTRATION" not in _codes(result)
        assert "INCOMPLETE-UNRESOLVED-REFERENCE" not in _codes(result)

    def test_a_dynamic_registration_is_linked_to_its_unknown_node(
        self, tmp_path: Path
    ) -> None:
        module = "from agents import Agent\na = Agent(name='A', tools=load())\n"
        result = _run(_project(tmp_path, module=module))
        diagnostic = result.diagnostics[0]
        location = (diagnostic.evidence[0].path, diagnostic.evidence[0].line_start)
        assert location == ("desk.py", 2)
        node = next(n for n in result.nodes if n.type == NodeType.TOOL)
        assert node.confidence is Confidence.UNKNOWN
        assert location in {(e.path, e.line_start) for e in node.evidence}

    def test_a_non_literal_tools_list_still_produces_a_node(
        self, tmp_path: Path
    ) -> None:
        """The agent still gets a node, carrying unknown attributes."""

        module = "from agents import Agent\na = Agent(name='A', tools=load())\n"
        result = _run(_project(tmp_path, module=module))
        unknown = [
            n for n in result.nodes if n.security_attributes.destructive == "unknown"
        ]
        assert len(unknown) == 1

    def test_an_unresolved_wiring_classifies_as_unclassified(
        self, tmp_path: Path
    ) -> None:
        module = "from agents import Agent\na = Agent(name='A', tools=load())\n"
        result = _run(_project(tmp_path, module=module))
        node = next(
            n for n in result.nodes if n.security_attributes.destructive == "unknown"
        )
        assert MaterialCapabilityClass.UNCLASSIFIED in classify_material_capability(
            node.security_attributes, edge_type=EdgeType.INVOKES
        )

    def test_an_unresolved_wiring_never_yields_no_material_capability(
        self, tmp_path: Path
    ) -> None:
        """End to end against the real blast-radius computation."""

        module = "from agents import Agent\na = Agent(name='A', tools=load())\n"
        result = _run(_project(tmp_path, module=module))
        assert compute_blast_radius(result.nodes, result.edges) is not None

    def test_as_tool_is_invokes_not_delegates_to(self, tmp_path: Path) -> None:
        """A handoff transfers the conversation; `as_tool` calls
        in and returns. Collapsing them would overstate what the caller
        gave away."""

        module = (
            "from agents import Agent\n"
            'specialist = Agent(name="Specialist")\n'
            'main = Agent(name="Main", tools=[specialist.as_tool()])\n'
        )
        result = _run(_project(tmp_path, module=module))
        assert ("Main", "Specialist") in _pairs(result, EdgeType.INVOKES)
        assert ("Main", "Specialist") not in _pairs(result, EdgeType.DELEGATES_TO)

    def test_a_fully_resolved_module_carries_no_unknown_attributes(
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
        source = Path("src/controlloop/adapters/openai_agents.py").read_text(
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
            n.func.id
            for n in ast.walk(tree)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
        }
        assert not called & {"eval", "exec", "compile", "__import__"}

    def test_a_module_that_would_crash_on_import_still_scans(
        self, tmp_path: Path
    ) -> None:
        module = "raise RuntimeError('importing me is a bug')\n" + _MODULE
        result = _run(_project(tmp_path, module=module))
        assert "Triage" in _names(result, NodeType.AGENT)


class TestDetection:
    def test_a_module_not_importing_the_sdk_is_not_claimed(
        self, tmp_path: Path
    ) -> None:
        module = "agents = ['not', 'the', 'sdk']\nAgent = object\n"
        (tmp_path / "other.py").write_text(module, encoding="utf-8")
        detection = OpenAiAgentsAdapter().detect(
            ScanContext(root=RepositoryRoot(path=tmp_path))
        )
        assert detection.claimed_paths == ()

    def test_a_module_importing_the_sdk_is_claimed(self, tmp_path: Path) -> None:
        detection = OpenAiAgentsAdapter().detect(
            ScanContext(root=RepositoryRoot(path=_project(tmp_path)))
        )
        assert detection.claimed_paths == ("desk.py",)

    def test_the_adapter_is_registered(self) -> None:
        assert OpenAiAgentsAdapter in ALL_ADAPTERS


class TestMalformedInput:
    def test_unparseable_python_is_never_claimed(self, tmp_path: Path) -> None:
        (tmp_path / "broken.py").write_text("def x( :\n", encoding="utf-8")
        result = _run(tmp_path)
        assert result.nodes == ()


class TestDeterminism:
    def test_identical_input_produces_an_identical_result(self, tmp_path: Path) -> None:
        root = _project(tmp_path)
        first, second = _run(root), _run(root)
        assert [n.id for n in first.nodes] == [n.id for n in second.nodes]
        assert [e.id for e in first.edges] == [e.id for e in second.edges]
