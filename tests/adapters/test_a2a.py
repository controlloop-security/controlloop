"""Tests for A2aAgentCardAdapter."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from controlloop.acbom import Confidence, EdgeType, NodeType
from controlloop.adapters import A2aAgentCardAdapter, ScanContext, run_adapters
from controlloop.repository import resolve_repository_root


def _context(tmp_path: Path) -> ScanContext:
    return ScanContext(root=resolve_repository_root(tmp_path))


def _write(tmp_path: Path, relative_path: str, payload: object) -> None:
    target = tmp_path / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload))


@pytest.mark.parametrize(
    "relative_path",
    [".well-known/agent.json", ".well-known/agent-card.json", "agent-card.json"],
)
def test_each_known_location_is_detected(tmp_path: Path, relative_path: str) -> None:
    """A card at any of the known locations is claimed."""
    _write(tmp_path, relative_path, {"name": "x"})

    detection = A2aAgentCardAdapter().detect(_context(tmp_path))

    assert detection.claimed_paths == (relative_path,)


def test_card_becomes_agent_node_with_identity_from_security_schemes(
    tmp_path: Path,
) -> None:
    """A card becomes an agent node, with its security schemes as identities."""
    _write(
        tmp_path,
        "agent-card.json",
        {
            "name": "Refund Agent",
            "protocolVersion": "0.2.1",
            "securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}},
        },
    )

    result = run_adapters([A2aAgentCardAdapter()], _context(tmp_path))

    agents = [n for n in result.nodes if n.type is NodeType.AGENT]
    identities = [n for n in result.nodes if n.type is NodeType.IDENTITY]
    assert [a.name for a in agents] == ["Refund Agent"]
    assert [i.name for i in identities] == ["bearer"]


def test_skills_become_tool_nodes_with_invokes_edges(tmp_path: Path) -> None:
    """Each declared skill becomes a tool node the agent invokes."""
    _write(
        tmp_path,
        "agent-card.json",
        {
            "name": "Refund Agent",
            "skills": [
                {"id": "refund", "name": "Issue Refund"},
                {"id": "lookup", "name": "Lookup Order"},
            ],
        },
    )

    result = run_adapters([A2aAgentCardAdapter()], _context(tmp_path))

    tools = [n for n in result.nodes if n.type is NodeType.TOOL]
    assert {t.name for t in tools} == {"Issue Refund", "Lookup Order"}
    assert len(result.edges) == 2
    assert all(e.type is EdgeType.INVOKES for e in result.edges)


def test_adapter_module_never_imports_socket() -> None:
    """Structural: cards are only ever read from committed files, never
    fetched."""
    import ast

    import controlloop.adapters.a2a as a2a_module

    source = Path(a2a_module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }

    assert "socket" not in imported


def test_unsupported_version_produces_a_diagnostic_naming_it(tmp_path: Path) -> None:
    """An unsupported protocol version yields no nodes and a diagnostic."""
    _write(tmp_path, "agent-card.json", {"name": "x", "protocolVersion": "9.9"})

    result = run_adapters([A2aAgentCardAdapter()], _context(tmp_path))

    assert result.nodes == ()
    assert len(result.diagnostics) == 1
    assert "9.9" in result.diagnostics[0].message


def test_hostile_card_text_produces_a_diagnostic_not_a_crash(tmp_path: Path) -> None:
    """Card text flows into DisplayName/SafeText-constrained
    fields, which already reject control characters structurally."""
    _write(tmp_path, "agent-card.json", {"name": "x\x01\x02hostile"})

    result = run_adapters([A2aAgentCardAdapter()], _context(tmp_path))

    assert result.nodes == ()
    assert len(result.diagnostics) == 1


def test_malformed_skill_entry_produces_diagnostic_not_a_dropped_card(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path,
        "agent-card.json",
        {
            "name": "Refund Agent",
            "skills": [{"id": "good", "name": "Good"}, {"nope": True}],
        },
    )

    result = run_adapters([A2aAgentCardAdapter()], _context(tmp_path))

    assert any(n.type is NodeType.AGENT for n in result.nodes)
    assert any(n.name == "Good" for n in result.nodes)
    assert len(result.diagnostics) == 1


def test_result_is_deterministic(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "agent-card.json",
        {"name": "x", "skills": [{"id": "a", "name": "A"}, {"id": "b", "name": "B"}]},
    )
    context = _context(tmp_path)

    first = run_adapters([A2aAgentCardAdapter()], context)
    second = run_adapters([A2aAgentCardAdapter()], context)

    assert first == second


def test_repo_local_delegation_target_links_to_its_agent_node(tmp_path: Path) -> None:
    """A repo-local target is linked to its own agent node, not left as a
    dangling reference."""
    _write(
        tmp_path,
        "agent-card.json",
        {
            "name": "Coordinator",
            "x-controlloop-delegates-to": ["sub-agents/researcher/agent-card.json"],
        },
    )
    _write(tmp_path, "sub-agents/researcher/agent-card.json", {"name": "Researcher"})

    result = run_adapters([A2aAgentCardAdapter()], _context(tmp_path))

    agents = {n.name for n in result.nodes if n.type is NodeType.AGENT}
    assert agents == {"Coordinator", "Researcher"}
    delegation_edges = [e for e in result.edges if e.type is EdgeType.DELEGATES_TO]
    assert len(delegation_edges) == 1
    assert result.diagnostics == ()


def test_url_delegation_target_becomes_a_bounded_external_node(
    tmp_path: Path,
) -> None:
    """An external target is represented, never fetched."""
    _write(
        tmp_path,
        "agent-card.json",
        {
            "name": "Coordinator",
            "x-controlloop-delegates-to": [
                "https://partner.example.com/.well-known/agent.json"
            ],
        },
    )

    result = run_adapters([A2aAgentCardAdapter()], _context(tmp_path))

    external = [
        n for n in result.nodes if n.subtype == "a2a-external-delegation-target"
    ]
    assert len(external) == 1
    assert external[0].name == "https://partner.example.com/.well-known/agent.json"
    assert external[0].security_attributes.external_communication is True
    delegation_edges = [e for e in result.edges if e.type is EdgeType.DELEGATES_TO]
    assert len(delegation_edges) == 1
    assert result.diagnostics == ()


def test_unresolvable_delegation_target_produces_an_unknown(tmp_path: Path) -> None:
    """An unresolvable target is an unknown, never a silently missing edge."""
    _write(
        tmp_path,
        "agent-card.json",
        {
            "name": "Coordinator",
            "x-controlloop-delegates-to": ["sub-agents/nonexistent/agent-card.json"],
        },
    )

    result = run_adapters([A2aAgentCardAdapter()], _context(tmp_path))

    assert [e for e in result.edges if e.type is EdgeType.DELEGATES_TO] == []
    assert len(result.diagnostics) == 1
    assert result.diagnostics[0].code == "INCOMPLETE-UNRESOLVED-REFERENCE"


def test_mutual_delegation_cycle_completes_without_hanging(tmp_path: Path) -> None:
    """A mutual delegation cycle completes. Both cards use one of the two
    other known root-level card locations (`.well-known/agent.json` and
    `agent-card.json`) so both are independently discovered and their
    edges both actually resolve -- a genuinely observable two-node mutual
    cycle, not just a reference into an unclaimed file."""
    _write(
        tmp_path,
        ".well-known/agent.json",
        {"name": "Agent A", "x-controlloop-delegates-to": ["agent-card.json"]},
    )
    _write(
        tmp_path,
        "agent-card.json",
        {
            "name": "Agent B",
            "x-controlloop-delegates-to": [".well-known/agent.json"],
        },
    )

    result = run_adapters([A2aAgentCardAdapter()], _context(tmp_path))

    delegation_edges = [e for e in result.edges if e.type is EdgeType.DELEGATES_TO]
    assert len(delegation_edges) == 2
    assert result.diagnostics == ()


def test_escaping_delegation_target_produces_an_unknown_not_a_read(
    tmp_path: Path,
) -> None:
    """A hostile delegation target attempting to leave the repository
    root is refused, not silently followed."""
    _write(
        tmp_path,
        "agent-card.json",
        {
            "name": "Coordinator",
            "x-controlloop-delegates-to": ["../../etc/passwd"],
        },
    )

    result = run_adapters([A2aAgentCardAdapter()], _context(tmp_path))

    assert [e for e in result.edges if e.type is EdgeType.DELEGATES_TO] == []
    assert len(result.diagnostics) == 1
    assert result.diagnostics[0].code == "INCOMPLETE-UNRESOLVED-REFERENCE"


def test_card_with_no_delegation_field_is_unaffected(tmp_path: Path) -> None:
    _write(tmp_path, "agent-card.json", {"name": "x"})

    result = run_adapters([A2aAgentCardAdapter()], _context(tmp_path))

    assert [e for e in result.edges if e.type is EdgeType.DELEGATES_TO] == []
    assert result.diagnostics == ()


class TestEndpointInference:
    """A card's `url` is where the agent accepts requests: recorded as an
    inferred, unconfirmed untrusted-input leg, never a confirmed one."""

    def test_a_url_becomes_an_unknown_trigger_the_agent_receives_from(
        self, tmp_path: Path
    ) -> None:
        _write(
            tmp_path,
            "agent-card.json",
            {"name": "Refund Agent", "url": "https://agents.example.com/refunds/v1"},
        )
        result = run_adapters([A2aAgentCardAdapter()], _context(tmp_path))

        triggers = [n for n in result.nodes if n.type is NodeType.TRIGGER]
        assert [t.name for t in triggers] == ["inbound requests to agents.example.com"]
        assert triggers[0].subtype == "a2a-endpoint"
        assert triggers[0].security_attributes.untrusted_input == "unknown"
        assert triggers[0].confidence is Confidence.LOW
        receives = [e for e in result.edges if e.type is EdgeType.RECEIVES_FROM]
        assert len(receives) == 1
        agent = next(n for n in result.nodes if n.type is NodeType.AGENT)
        assert receives[0].source == agent.id
        assert receives[0].target == triggers[0].id
        assert receives[0].security_attributes.untrusted_input == "unknown"
        assert receives[0].confidence is Confidence.LOW

    def test_the_path_and_query_are_not_kept(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "agent-card.json",
            {
                "name": "Refund Agent",
                "url": "https://agents.example.com/a/b?token=secret",
            },
        )
        result = run_adapters([A2aAgentCardAdapter()], _context(tmp_path))

        trigger = next(n for n in result.nodes if n.type is NodeType.TRIGGER)
        assert trigger.name == "inbound requests to agents.example.com"
        assert "secret" not in trigger.name

    @pytest.mark.parametrize("url", ["", "not a url", 42, None, "/relative/path"])
    def test_no_usable_url_means_no_trigger(self, tmp_path: Path, url: object) -> None:
        card: dict[str, object] = {"name": "Refund Agent"}
        if url is not None:
            card["url"] = url
        _write(tmp_path, "agent-card.json", card)
        result = run_adapters([A2aAgentCardAdapter()], _context(tmp_path))

        assert not any(n.type is NodeType.TRIGGER for n in result.nodes)
        assert not any(e.type is EdgeType.RECEIVES_FROM for e in result.edges)

    def test_the_same_card_twice_gives_the_same_ids(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "agent-card.json",
            {"name": "Refund Agent", "url": "https://agents.example.com/"},
        )
        first = run_adapters([A2aAgentCardAdapter()], _context(tmp_path))
        second = run_adapters([A2aAgentCardAdapter()], _context(tmp_path))

        assert [n.id for n in first.nodes] == [n.id for n in second.nodes]
        assert [e.id for e in first.edges] == [e.id for e in second.edges]
