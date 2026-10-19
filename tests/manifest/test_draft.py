"""Tests for controlloop.manifest.draft."""

from __future__ import annotations

from controlloop.acbom import (
    Confidence,
    Edge,
    EdgeIdentityMaterial,
    EdgeStatus,
    EdgeType,
    Evidence,
    Node,
    NodeIdentityMaterial,
    NodeType,
    SecurityAttributes,
    SemanticIdentity,
    edge_id,
    node_id,
)
from controlloop.manifest import CURRENT_MANIFEST_SCHEMA_VERSION, load_manifest
from controlloop.manifest.draft import render_draft_manifest

_ADAPTER = "test-fixture"


def _agent(name: str, discriminator: str) -> Node:
    identity = NodeIdentityMaterial(
        node_type=NodeType.AGENT,
        namespace="test",
        semantic_identity=SemanticIdentity(identifier=discriminator),
    )
    return Node(
        id=node_id(identity),
        type=NodeType.AGENT,
        name=name,
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=(Evidence(adapter=_ADAPTER, path="agent-card.json"),),
    )


def _tool(name: str, discriminator: str) -> Node:
    identity = NodeIdentityMaterial(
        node_type=NodeType.TOOL,
        namespace="test",
        semantic_identity=SemanticIdentity(identifier=discriminator),
    )
    return Node(
        id=node_id(identity),
        type=NodeType.TOOL,
        name=name,
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=(Evidence(adapter=_ADAPTER, path="agent-card.json"),),
    )


def _identity(name: str, discriminator: str) -> Node:
    identity = NodeIdentityMaterial(
        node_type=NodeType.IDENTITY,
        namespace="test",
        semantic_identity=SemanticIdentity(identifier=discriminator),
    )
    return Node(
        id=node_id(identity),
        type=NodeType.IDENTITY,
        name=name,
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=(Evidence(adapter=_ADAPTER, path="agent-card.json"),),
    )


def _edge(
    edge_type: EdgeType,
    source: Node,
    target: Node,
    discriminator: str,
    *,
    confidence: Confidence = Confidence.HIGH,
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
        confidence=confidence,
        evidence=(Evidence(adapter=_ADAPTER, path="agent-card.json"),),
    )


def _assert_valid_manifest(text: str) -> None:
    """The rendered draft parses through the manifest schema
    validator (`load_manifest`) without edits."""
    document = load_manifest(text, path="controlloop.yaml")
    assert document.schema_version == CURRENT_MANIFEST_SCHEMA_VERSION


class TestEveryFieldPresent:
    """Every field ControlLoop could not determine is present
    (as a YAML key) and marked TODO with an explanatory comment, even
    with zero discovered nodes."""

    def test_zero_nodes_still_produces_every_schema_field(self) -> None:
        text = render_draft_manifest((), ())

        _assert_valid_manifest(text)
        document = load_manifest(text, path="controlloop.yaml")
        assert document.owner == "TODO-owner"
        assert len(document.trust_boundaries) == 1
        assert document.trust_boundaries[0].name == "TODO-trust-boundary-name"
        assert document.trust_boundaries[0].agents == ()
        assert document.approvals == ()
        assert document.prohibited_capabilities == ()
        assert document.allowed_delegation == ()
        assert document.data_classification == ()
        assert document.ceilings == ()

    def test_every_todo_field_has_an_explanatory_comment(self) -> None:
        text = render_draft_manifest((), ())

        for field_name in (
            "owner",
            "approvals",
            "prohibited_capabilities",
            "allowed_delegation",
            "data_classification",
            "ceilings",
        ):
            assert f"# TODO: {field_name}" in text

    def test_zero_agents_comment_names_the_gap(self) -> None:
        text = render_draft_manifest((), ())

        assert "ControlLoop discovered no candidate agents" in text


class TestDiscoveredAgentsPreFilled:
    """Init discovers candidate agents and pre-fills them."""

    def test_discovered_agent_appears_in_trust_boundary_agents(self) -> None:
        agent = _agent("refund-agent", "agent-1")

        text = render_draft_manifest((agent,), ())

        document = load_manifest(text, path="controlloop.yaml")
        assert document.trust_boundaries[0].agents == ("refund-agent",)

    def test_discovered_tools_appear_as_a_comment(self) -> None:
        agent = _agent("refund-agent", "agent-1")
        tool = _tool("issue-refund", "tool-1")
        invokes = _edge(EdgeType.INVOKES, agent, tool, "agent-1:issue-refund")

        text = render_draft_manifest((agent, tool), (invokes,))

        _assert_valid_manifest(text)
        assert "tools observed: issue-refund" in text

    def test_agent_with_no_invoked_tools_says_so(self) -> None:
        agent = _agent("refund-agent", "agent-1")

        text = render_draft_manifest((agent,), ())

        assert "no tools observed" in text

    def test_non_agent_non_tool_nodes_are_ignored(self) -> None:
        identity = NodeIdentityMaterial(
            node_type=NodeType.IDENTITY,
            namespace="test",
            semantic_identity=SemanticIdentity(identifier="scheme-1"),
        )
        identity_node = Node(
            id=node_id(identity),
            type=NodeType.IDENTITY,
            name="api-key",
            security_attributes=SecurityAttributes(),
            confidence=Confidence.HIGH,
            evidence=(Evidence(adapter=_ADAPTER, path="agent-card.json"),),
        )

        text = render_draft_manifest((identity_node,), ())

        _assert_valid_manifest(text)
        document = load_manifest(text, path="controlloop.yaml")
        assert document.trust_boundaries[0].agents == ()

    def test_multiple_agents_sorted_deterministically_by_id(self) -> None:
        agent_a = _agent("agent-a", "1")
        agent_b = _agent("agent-b", "2")

        forward = render_draft_manifest((agent_a, agent_b), ())
        reversed_order = render_draft_manifest((agent_b, agent_a), ())

        assert forward == reversed_order


class TestUnsafeAgentNameExcludedNeverFabricated:
    """Boundary/malformed case: a discovered Node.name that does not
    satisfy the manifest's SafeIdentifier character class (for example,
    one containing a space) must never be silently slugified into a
    mismatched reference -- it is excluded from the real `agents:`
    field and disclosed by a comment, because ceiling.py matches by exact
    Node.name equality."""

    def test_unsafe_name_is_excluded_from_the_real_field(self) -> None:
        agent = _agent("Customer Support Bot", "agent-1")

        text = render_draft_manifest((agent,), ())

        document = load_manifest(text, path="controlloop.yaml")
        assert document.trust_boundaries[0].agents == ()

    def test_unsafe_name_is_still_disclosed_in_a_comment(self) -> None:
        agent = _agent("Customer Support Bot", "agent-1")

        text = render_draft_manifest((agent,), ())

        assert "Customer Support Bot" in text
        assert "1 discovered agent(s) could not be listed automatically" in text

    def test_the_document_still_validates_with_an_excluded_agent(self) -> None:
        """The draft stays schema-valid even on the exclusion path, not
        only the happy path."""
        agent = _agent("Customer Support Bot", "agent-1")

        text = render_draft_manifest((agent,), ())

        _assert_valid_manifest(text)

    def test_mixed_safe_and_unsafe_agents(self) -> None:
        safe = _agent("refund-agent", "agent-1")
        unsafe = _agent("Customer Support Bot", "agent-2")

        text = render_draft_manifest((safe, unsafe), ())

        document = load_manifest(text, path="controlloop.yaml")
        assert document.trust_boundaries[0].agents == ("refund-agent",)
        assert "1 discovered agent(s) could not be listed automatically" in text

    def test_hostile_unicode_in_a_name_is_escaped_in_comments(self) -> None:
        """A right-to-left override or other Cf/Cc/Cs character in a
        discovered (untrusted) agent-card name must never reach a
        comment raw -- it is replaced with a printable <U+XXXX> marker,
        mirroring controlloop.repository's own handling of the same
        threat class for evidence paths."""
        rtl_override = chr(0x202E)
        hostile_name = f"agent{rtl_override}-evil"
        agent = _agent(hostile_name, "agent-1")

        text = render_draft_manifest((agent,), ())

        assert rtl_override not in text
        assert "<U+202E>" in text
        _assert_valid_manifest(text)


class TestAllowedDelegationInformationalOnly:
    """Delegation-shaped relationships discovered between two agents
    are surfaced as a reference-only comment, never written as an
    approved `allowed_delegation` entry -- declaring one is a human
    policy decision, not a mirror of discovery."""

    def test_delegates_to_edge_appears_as_a_comment_not_a_field_value(self) -> None:
        source = _agent("agent-a", "1")
        target = _agent("agent-b", "2")
        delegates = _edge(EdgeType.DELEGATES_TO, source, target, "a-to-b")

        text = render_draft_manifest((source, target), (delegates,))

        document = load_manifest(text, path="controlloop.yaml")
        assert document.allowed_delegation == ()
        assert "agent-a -> agent-b" in text

    def test_no_delegation_edges_produces_no_observed_comment(self) -> None:
        text = render_draft_manifest((), ())

        assert "ControlLoop observed these delegation-shaped" not in text


class TestDeterminism:
    """Identical input, regardless of original ordering, produces
    byte-identical output."""

    def test_repeated_calls_are_byte_identical(self) -> None:
        agent = _agent("refund-agent", "agent-1")
        tool = _tool("issue-refund", "tool-1")
        invokes = _edge(EdgeType.INVOKES, agent, tool, "agent-1:issue-refund")

        first = render_draft_manifest((agent, tool), (invokes,))
        second = render_draft_manifest((agent, tool), (invokes,))

        assert first == second

    def test_permuted_edge_order_is_identical(self) -> None:
        agent = _agent("refund-agent", "agent-1")
        tool_a = _tool("tool-a", "tool-a")
        tool_b = _tool("tool-b", "tool-b")
        edge_a = _edge(EdgeType.INVOKES, agent, tool_a, "a")
        edge_b = _edge(EdgeType.INVOKES, agent, tool_b, "b")

        forward = render_draft_manifest((agent, tool_a, tool_b), (edge_a, edge_b))
        reversed_edges = render_draft_manifest(
            (agent, tool_a, tool_b), (edge_b, edge_a)
        )

        assert forward == reversed_edges

    def test_no_timestamp_or_absolute_path_appears(self) -> None:
        """Privacy/determinism: nothing environment- or clock-derived
        leaks into the draft."""
        text = render_draft_manifest((), ())

        assert "/private/" not in text
        assert "/Users/" not in text
        assert "/home/" not in text


class TestPrivacyCanary:
    """A synthetic secret-shaped string reachable only through a
    discovered node's own already-validated fields never appears
    unexpectedly transformed or duplicated raw beyond what the field
    itself already carries -- this module reads no evidence content,
    only already-sanitized Node/Edge fields, so there is no separate
    secret-shaped source for it to leak."""

    def test_evidence_path_never_appears_in_output(self) -> None:
        agent = _agent("refund-agent", "agent-1")

        text = render_draft_manifest((agent,), ())

        assert "agent-card.json" not in text


class TestCeilingProposal:
    """Tests for the `ceilings:` section."""

    def test_zero_agents_says_so_and_stays_schema_valid(self) -> None:
        """Boundary: no candidate agents discovered."""
        text = render_draft_manifest((), ())

        _assert_valid_manifest(text)
        assert (
            "ControlLoop discovered no candidate agents to propose a "
            "ceiling for" in text
        )
        document = load_manifest(text, path="controlloop.yaml")
        assert document.ceilings == ()

    def test_starting_point_marking_is_present(self) -> None:
        """Clearly marked as a starting point, not an approved
        envelope."""
        text = render_draft_manifest((), ())

        assert "STARTING POINT" in text
        assert "not an approved security" in text

    def test_incomplete_categories_are_always_disclosed(self) -> None:
        """The categories this analysis structurally cannot
        derive are disclosed every time, not just on the empty path."""
        agent = _agent("refund-agent", "agent-1")
        tool = _tool("issue-refund", "tool-1")
        invokes = _edge(EdgeType.INVOKES, agent, tool, "agent-1:issue-refund")

        text = render_draft_manifest((agent, tool), (invokes,))

        assert "prohibited_resources" in text
        assert "prohibited_external_destinations" in text
        assert "prohibited_data_classes" in text
        assert "cannot determine" in text

    def test_proposed_actions_reflect_what_was_not_observed(self) -> None:
        """Positive: an agent that only invokes a tool gets a
        ceiling proposal prohibiting reads and writes, never invokes --
        adopting it unchanged cannot conflict with this scan."""
        agent = _agent("refund-agent", "agent-1")
        tool = _tool("issue-refund", "tool-1")
        invokes = _edge(EdgeType.INVOKES, agent, tool, "agent-1:issue-refund")

        text = render_draft_manifest((agent, tool), (invokes,))

        _assert_valid_manifest(text)
        document = load_manifest(text, path="controlloop.yaml")
        assert len(document.ceilings) == 1
        ceiling = document.ceilings[0]
        assert ceiling.agent == "refund-agent"
        assert set(ceiling.prohibited_actions) == {EdgeType.READS, EdgeType.WRITES}
        assert ceiling.prohibited_resources == ()
        assert ceiling.prohibited_external_destinations == ()
        assert ceiling.prohibited_data_classes == ()

    def test_agent_exercising_everything_alone_says_nothing_to_propose(
        self,
    ) -> None:
        """Similar negative/boundary: nothing meaningful to propose is
        disclosed, not silently rendered as an empty list with no
        explanation."""
        agent = _agent("solo-agent", "agent-1")
        resource = _tool("only-tool", "tool-1")
        edges = (
            _edge(EdgeType.READS, agent, resource, "r"),
            _edge(EdgeType.WRITES, agent, resource, "w"),
            _edge(EdgeType.INVOKES, agent, resource, "i"),
        )

        text = render_draft_manifest((agent, resource), edges)

        _assert_valid_manifest(text)
        document = load_manifest(text, path="controlloop.yaml")
        assert document.ceilings == ()
        assert "nothing meaningful to propose yet" in text

    def test_low_confidence_action_is_disclosed_not_prohibited(self) -> None:
        """A low-confidence action appears as a disclosed
        comment and never as a `prohibited_actions` YAML value. An
        `authenticates-as` edge is included so
        `compute_effective_authority`'s confidence-combination rule
        (weaker of the action edge and the identity edge) propagates
        the action edge's own `LOW` confidence through, rather than the
        separate "no identity at all" `UNKNOWN` case covered by
        `test_agent_with_no_identity_edge_is_disclosed_as_unknown`
        below."""
        agent = _agent("refund-agent", "agent-1")
        tool = _tool("issue-refund", "tool-1")
        identity = _identity("api-key", "1")
        invokes = _edge(
            EdgeType.INVOKES,
            agent,
            tool,
            "agent-1:issue-refund",
            confidence=Confidence.LOW,
        )
        authenticates = _edge(EdgeType.AUTHENTICATES_AS, agent, identity, "auth")

        text = render_draft_manifest((agent, tool, identity), (invokes, authenticates))

        _assert_valid_manifest(text)
        document = load_manifest(text, path="controlloop.yaml")
        ceiling = document.ceilings[0]
        assert EdgeType.INVOKES not in ceiling.prohibited_actions
        assert "low or unknown" in text
        assert "issue-refund" in text
        assert "low confidence" in text

    def test_agent_with_no_identity_edge_is_disclosed_as_unknown(self) -> None:
        """Effective authority's "unknown, never omitted" rule: an
        action with no `authenticates-as` edge at all is `UNKNOWN`
        confidence, disclosed the same way `LOW` is."""
        agent = _agent("refund-agent", "agent-1")
        tool = _tool("issue-refund", "tool-1")
        invokes = _edge(EdgeType.INVOKES, agent, tool, "agent-1:issue-refund")

        text = render_draft_manifest((agent, tool), (invokes,))

        _assert_valid_manifest(text)
        document = load_manifest(text, path="controlloop.yaml")
        ceiling = document.ceilings[0]
        assert EdgeType.INVOKES not in ceiling.prohibited_actions
        assert "low or unknown" in text
        assert "unknown confidence" in text

    def test_low_confidence_delegation_is_disclosed_not_prohibited(self) -> None:
        """Delegation counterpart of the previous test."""
        source = _agent("agent-a", "1")
        target = _agent("agent-b", "2")
        delegates = _edge(
            EdgeType.DELEGATES_TO,
            source,
            target,
            "a-to-b",
            confidence=Confidence.UNKNOWN,
        )

        text = render_draft_manifest((source, target), (delegates,))

        _assert_valid_manifest(text)
        document = load_manifest(text, path="controlloop.yaml")
        by_agent = {ceiling.agent: ceiling for ceiling in document.ceilings}
        assert "agent-b" not in by_agent["agent-a"].prohibited_delegation_targets
        assert "agent-a may delegate to agent-b" in text
        assert "unknown confidence" in text

    def test_excluded_agent_note_references_trust_boundaries(self) -> None:
        """An unsafe agent name excluded from trust_boundaries is also
        never used to build a ceiling entry; the ceiling section says
        so instead of silently covering fewer agents than discovered."""
        agent = _agent("Customer Support Bot", "agent-1")

        text = render_draft_manifest((agent,), ())

        assert "Ceiling proposals are limited to the safely-identified" in text

    def test_no_evidence_path_or_absolute_path_in_ceiling_section(self) -> None:
        """Privacy/offline: nothing environment- or evidence-derived
        leaks through the new section."""
        agent = _agent("refund-agent", "agent-1")
        tool = _tool("issue-refund", "tool-1")
        invokes = _edge(
            EdgeType.INVOKES,
            agent,
            tool,
            "agent-1:issue-refund",
            confidence=Confidence.LOW,
        )

        text = render_draft_manifest((agent, tool), (invokes,))

        assert "agent-card.json" not in text
        assert "/private/" not in text
        assert "/Users/" not in text
        assert "/home/" not in text

    def test_permuted_edge_order_is_byte_identical(self) -> None:
        """Determinism, ceiling section specific."""
        agent = _agent("refund-agent", "agent-1")
        tool_a = _tool("tool-a", "a")
        tool_b = _tool("tool-b", "b")
        edge_a = _edge(EdgeType.INVOKES, agent, tool_a, "a")
        edge_b = _edge(EdgeType.WRITES, agent, tool_b, "b", confidence=Confidence.LOW)

        forward = render_draft_manifest((agent, tool_a, tool_b), (edge_a, edge_b))
        reversed_edges = render_draft_manifest(
            (agent, tool_a, tool_b), (edge_b, edge_a)
        )

        assert forward == reversed_edges
