"""Tests for `controlloop.manifest.inputs`: a declared external input
becomes one trigger node and one `receives-from` edge on the named
agent, authoritative and content-addressed; nothing discovered is ever
changed."""

from __future__ import annotations

import json
from pathlib import Path

from controlloop.acbom import (
    Confidence,
    Edge,
    EdgeStatus,
    EdgeType,
    Evidence,
    Node,
    NodeType,
    SecurityAttributes,
)
from controlloop.bom import build_acbom_document
from controlloop.manifest.inputs import declare_external_inputs
from controlloop.manifest.models import (
    CURRENT_MANIFEST_SCHEMA_VERSION,
    ExternalInputDeclaration,
    ManifestDocument,
)
from controlloop.repository import resolve_repository_root

_EVIDENCE = (Evidence(adapter="manifest", path="controlloop.yaml"),)


def _agent(
    name: str = "support-agent", node_id: str = "clp:agent:sha256:" + "a" * 64
) -> Node:
    return Node(
        id=node_id,
        type=NodeType.AGENT,
        name=name,
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=(Evidence(adapter="a2a", path="agent-card.json"),),
    )


def _manifest(*declarations: ExternalInputDeclaration) -> ManifestDocument:
    return ManifestDocument(
        schema_version=CURRENT_MANIFEST_SCHEMA_VERSION,
        owner="support-eng",
        external_inputs=declarations,
    )


def _declare(
    agent: str = "support-agent", source: str = "customer support inbox"
) -> ExternalInputDeclaration:
    return ExternalInputDeclaration(agent=agent, source=source)


class TestDeclaration:
    def test_adds_one_trigger_and_one_receives_from_edge(self) -> None:
        agent = _agent()

        nodes, edges, diagnostics = declare_external_inputs(
            (agent,), (), _manifest(_declare()), "controlloop.yaml", _EVIDENCE
        )

        assert diagnostics == ()
        assert [node.type for node in nodes] == [NodeType.AGENT, NodeType.TRIGGER]
        trigger = nodes[1]
        assert trigger.name == "customer support inbox"
        assert trigger.subtype == "declared-external-input"
        assert trigger.security_attributes.untrusted_input is True
        assert trigger.security_attributes.trusted is False
        assert trigger.evidence == _EVIDENCE
        assert len(edges) == 1
        edge = edges[0]
        assert edge.type is EdgeType.RECEIVES_FROM
        assert edge.source == agent.id and edge.target == trigger.id
        assert edge.security_attributes.untrusted_input is True
        assert edge.confidence is Confidence.HIGH

    def test_nothing_declared_changes_nothing(self) -> None:
        agent = _agent()
        existing = (agent,)

        assert declare_external_inputs(
            existing, (), None, "controlloop.yaml", _EVIDENCE
        ) == (
            existing,
            (),
            (),
        )
        assert declare_external_inputs(
            existing, (), _manifest(), "controlloop.yaml", _EVIDENCE
        ) == (existing, (), ())

    def test_discovered_nodes_and_edges_are_untouched(self) -> None:
        agent = _agent()
        tool = Node(
            id="clp:tool:sha256:" + "b" * 64,
            type=NodeType.TOOL,
            name="send email",
            security_attributes=SecurityAttributes(external_communication=True),
            confidence=Confidence.HIGH,
            evidence=agent.evidence,
        )
        invokes = Edge(
            id="clp:edge:sha256:" + "c" * 64,
            source=agent.id,
            target=tool.id,
            type=EdgeType.INVOKES,
            status=EdgeStatus.DIRECT,
            security_attributes=SecurityAttributes(),
            confidence=Confidence.HIGH,
            evidence=agent.evidence,
        )

        nodes, edges, _ = declare_external_inputs(
            (agent, tool),
            (invokes,),
            _manifest(_declare()),
            "controlloop.yaml",
            _EVIDENCE,
        )

        assert nodes[:2] == (agent, tool)
        assert edges[0] == invokes
        assert len(nodes) == 3 and len(edges) == 2

    def test_an_unmatched_agent_is_an_unverified_diagnostic(self) -> None:
        nodes, edges, diagnostics = declare_external_inputs(
            (_agent(),),
            (),
            _manifest(_declare(agent="nobody")),
            "controlloop.yaml",
            _EVIDENCE,
        )

        assert len(nodes) == 1 and edges == ()
        assert len(diagnostics) == 1
        assert "names an agent discovery did not find" in diagnostics[0].message

    def test_two_agents_with_the_same_name_both_receive(self) -> None:
        first = _agent(node_id="clp:agent:sha256:" + "1" * 64)
        second = _agent(node_id="clp:agent:sha256:" + "2" * 64)

        nodes, edges, _ = declare_external_inputs(
            (first, second), (), _manifest(_declare()), "controlloop.yaml", _EVIDENCE
        )

        assert len(nodes) == 3, "one trigger, shared"
        assert {edge.source for edge in edges} == {first.id, second.id}

    def test_a_repeated_declaration_adds_nothing_twice(self) -> None:
        nodes, edges, _ = declare_external_inputs(
            (_agent(),),
            (),
            _manifest(_declare(), _declare()),
            "controlloop.yaml",
            _EVIDENCE,
        )

        assert len(nodes) == 2 and len(edges) == 1

    def test_identity_is_stable_and_content_addressed(self) -> None:
        first = declare_external_inputs(
            (_agent(),), (), _manifest(_declare()), "controlloop.yaml", _EVIDENCE
        )
        second = declare_external_inputs(
            (_agent(),), (), _manifest(_declare()), "controlloop.yaml", _EVIDENCE
        )
        other = declare_external_inputs(
            (_agent(),),
            (),
            _manifest(_declare(source="public webhook")),
            "controlloop.yaml",
            _EVIDENCE,
        )

        assert first == second
        assert first[0][1].id != other[0][1].id
        assert first[1][0].id != other[1][0].id


class TestThroughTheRealBuilder:
    def test_a_declared_input_appears_in_the_acbom(self, tmp_path: Path) -> None:
        (tmp_path / "agent-card.json").write_text(
            json.dumps(
                {"name": "support-agent", "skills": [{"id": "s", "name": "send email"}]}
            )
        )
        (tmp_path / "controlloop.yaml").write_text(
            f'schema_version: "{CURRENT_MANIFEST_SCHEMA_VERSION}"\n'
            "owner: support-eng\n"
            "external_inputs:\n"
            "  - agent: support-agent\n"
            "    source: customer support inbox\n"
            "    description: Tickets anyone on the internet can open.\n"
        )

        document = build_acbom_document(resolve_repository_root(tmp_path))

        triggers = [node for node in document.nodes if node.type is NodeType.TRIGGER]
        assert [node.name for node in triggers] == ["customer support inbox"]
        receives = [
            edge for edge in document.edges if edge.type is EdgeType.RECEIVES_FROM
        ]
        assert len(receives) == 1
        agent = next(node for node in document.nodes if node.type is NodeType.AGENT)
        assert receives[0].source == agent.id and receives[0].target == triggers[0].id
        assert not any(
            "could not be corroborated" in d.message for d in document.diagnostics
        )

    def test_the_same_repository_twice_gives_the_same_digest(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "agent-card.json").write_text(json.dumps({"name": "support-agent"}))
        (tmp_path / "controlloop.yaml").write_text(
            f'schema_version: "{CURRENT_MANIFEST_SCHEMA_VERSION}"\n'
            "owner: support-eng\n"
            "external_inputs:\n"
            "  - agent: support-agent\n"
            "    source: public webhook\n"
        )
        root = resolve_repository_root(tmp_path)

        assert build_acbom_document(root).digest == build_acbom_document(root).digest

    def test_a_declaration_for_an_unknown_agent_is_reported(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "agent-card.json").write_text(json.dumps({"name": "support-agent"}))
        (tmp_path / "controlloop.yaml").write_text(
            f'schema_version: "{CURRENT_MANIFEST_SCHEMA_VERSION}"\n'
            "owner: support-eng\n"
            "external_inputs:\n"
            "  - agent: billing-agent\n"
            "    source: public webhook\n"
        )

        document = build_acbom_document(resolve_repository_root(tmp_path))

        assert not any(node.type is NodeType.TRIGGER for node in document.nodes)
        assert any(
            "a declared external input names an agent discovery did not find"
            in d.message
            for d in document.diagnostics
        )
