"""Tests for controlloop.manifest.ceiling, including
`propose_starter_ceiling`."""

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
    Sensitivity,
    edge_id,
    node_id,
)
from controlloop.manifest import (
    CURRENT_MANIFEST_SCHEMA_VERSION,
    CapabilityCeiling,
    ManifestDocument,
    ceiling_policy_boundary_nodes_and_edges,
    effective_ceiling,
    propose_starter_ceiling,
)

_AGENT_ID = f"clp:agent:sha256:{'a' * 64}"
_OTHER_AGENT_ID = f"clp:agent:sha256:{'b' * 64}"
_ADAPTER = "test-fixture"


def _manifest(**overrides: object) -> ManifestDocument:
    payload: dict[str, object] = {
        "schema_version": CURRENT_MANIFEST_SCHEMA_VERSION,
        "owner": "security-team",
    }
    payload.update(overrides)
    return ManifestDocument.model_validate(payload)


def _agent_node(node_id: str, name: str) -> Node:
    return Node(
        id=node_id,
        type=NodeType.AGENT,
        name=name,
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=(Evidence(adapter="mcp", path="a.json"),),
    )


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


class TestEffectiveCeiling:
    """The stricter of a repository-wide and an agent-specific
    ceiling applies, defined as the union of both prohibitions."""

    def test_no_ceilings_produce_an_empty_effective_ceiling(self) -> None:
        manifest = _manifest()

        ceiling = effective_ceiling("refund-agent", manifest)

        assert ceiling.prohibited_resources == ()
        assert ceiling.agent == "refund-agent"

    def test_repository_wide_only_applies_to_every_agent(self) -> None:
        manifest = _manifest(
            ceilings=(CapabilityCeiling(prohibited_resources=("billing-db",)),)
        )

        ceiling = effective_ceiling("any-agent", manifest)

        assert ceiling.prohibited_resources == ("billing-db",)

    def test_agent_specific_only_applies_to_that_agent(self) -> None:
        manifest = _manifest(
            ceilings=(
                CapabilityCeiling(
                    agent="refund-agent", prohibited_resources=("billing-db",)
                ),
            )
        )

        assert effective_ceiling("refund-agent", manifest).prohibited_resources == (
            "billing-db",
        )
        assert effective_ceiling("other-agent", manifest).prohibited_resources == ()

    def test_repository_wide_and_agent_specific_union(self) -> None:
        """The stricter of the two: both sets of prohibitions apply."""
        manifest = _manifest(
            ceilings=(
                CapabilityCeiling(prohibited_resources=("shared-db",)),
                CapabilityCeiling(
                    agent="refund-agent", prohibited_resources=("billing-db",)
                ),
            )
        )

        ceiling = effective_ceiling("refund-agent", manifest)

        assert set(ceiling.prohibited_resources) == {"shared-db", "billing-db"}

    def test_result_is_deterministic(self) -> None:
        manifest = _manifest(
            ceilings=(
                CapabilityCeiling(prohibited_resources=("b", "a")),
                CapabilityCeiling(
                    agent="refund-agent", prohibited_resources=("d", "c")
                ),
            )
        )

        first = effective_ceiling("refund-agent", manifest)
        second = effective_ceiling("refund-agent", manifest)

        assert first == second
        assert first.prohibited_resources == ("a", "b", "c", "d")


class TestCeilingPolicyBoundaryProjection:
    """The declared ceiling appears in the ACBOM as
    policy-boundary nodes with constrained-by edges."""

    def test_no_ceilings_produce_nothing(self) -> None:
        manifest = _manifest()

        nodes, edges, diagnostics = ceiling_policy_boundary_nodes_and_edges(
            manifest, ()
        )

        assert nodes == ()
        assert edges == ()
        assert diagnostics == ()

    def test_one_category_produces_one_node_and_edge(self) -> None:
        manifest = _manifest(
            ceilings=(
                CapabilityCeiling(
                    agent="refund-agent", prohibited_resources=("billing-db",)
                ),
            )
        )
        discovered = (_agent_node(_AGENT_ID, "refund-agent"),)

        nodes, edges, diagnostics = ceiling_policy_boundary_nodes_and_edges(
            manifest, discovered
        )

        assert len(nodes) == 1
        assert nodes[0].type is NodeType.POLICY_BOUNDARY
        assert nodes[0].subtype == "ceiling-prohibited-resources"
        assert len(edges) == 1
        assert edges[0].type is EdgeType.CONSTRAINED_BY
        assert edges[0].source == _AGENT_ID
        assert edges[0].target == nodes[0].id
        assert diagnostics == ()

    def test_all_five_categories_produce_five_nodes_and_edges(self) -> None:
        manifest = _manifest(
            ceilings=(
                CapabilityCeiling(
                    agent="refund-agent",
                    prohibited_resources=("billing-db",),
                    prohibited_actions=(EdgeType.WRITES,),
                    prohibited_external_destinations=("evil.example.com",),
                    prohibited_data_classes=(Sensitivity.RESTRICTED,),
                    prohibited_delegation_targets=("unapproved-agent",),
                ),
            )
        )
        discovered = (_agent_node(_AGENT_ID, "refund-agent"),)

        nodes, edges, diagnostics = ceiling_policy_boundary_nodes_and_edges(
            manifest, discovered
        )

        assert len(nodes) == 5
        assert len(edges) == 5
        assert len({node.id for node in nodes}) == 5
        assert diagnostics == ()

    def test_repository_wide_ceiling_projects_for_every_discovered_agent(
        self,
    ) -> None:
        manifest = _manifest(
            ceilings=(CapabilityCeiling(prohibited_resources=("billing-db",)),)
        )
        discovered = (
            _agent_node(_AGENT_ID, "refund-agent"),
            _agent_node(_OTHER_AGENT_ID, "support-agent"),
        )

        nodes, edges, diagnostics = ceiling_policy_boundary_nodes_and_edges(
            manifest, discovered
        )

        assert len(nodes) == 2
        assert len(edges) == 2
        assert diagnostics == ()

    def test_ceiling_naming_an_undiscovered_agent_is_unverified_not_fabricated(
        self,
    ) -> None:
        manifest = _manifest(
            ceilings=(
                CapabilityCeiling(
                    agent="ghost-agent", prohibited_resources=("billing-db",)
                ),
            )
        )

        nodes, edges, diagnostics = ceiling_policy_boundary_nodes_and_edges(
            manifest, ()
        )

        assert nodes == ()
        assert edges == ()
        assert len(diagnostics) == 1
        assert diagnostics[0].code == "INCOMPLETE-UNVERIFIED-DECLARATION"

    def test_result_is_deterministic(self) -> None:
        manifest = _manifest(
            ceilings=(
                CapabilityCeiling(
                    agent="refund-agent",
                    prohibited_resources=("billing-db",),
                    prohibited_actions=(EdgeType.WRITES,),
                ),
            )
        )
        discovered = (_agent_node(_AGENT_ID, "refund-agent"),)

        first = ceiling_policy_boundary_nodes_and_edges(manifest, discovered)
        second = ceiling_policy_boundary_nodes_and_edges(manifest, discovered)

        assert first == second


class TestProposeStarterCeiling:
    """Tests for `propose_starter_ceiling`."""

    def test_zero_agents_produces_an_empty_proposal(self) -> None:
        proposal = propose_starter_ceiling((), (), ())

        assert proposal.ceilings == ()
        assert proposal.low_confidence_actions == ()
        assert proposal.low_confidence_delegations == ()

    def test_agent_invoking_one_tool_prohibits_unobserved_actions(self) -> None:
        """Positive: only actions with zero observed evidence
        are proposed as prohibited."""
        agent = _agent("refund-agent", "1")
        tool = _tool("issue-refund", "1")
        invokes = _edge(EdgeType.INVOKES, agent, tool, "a")

        proposal = propose_starter_ceiling((agent,), (agent, tool), (invokes,))

        assert len(proposal.ceilings) == 1
        ceiling = proposal.ceilings[0]
        assert ceiling.agent == "refund-agent"
        assert set(ceiling.prohibited_actions) == {EdgeType.READS, EdgeType.WRITES}
        assert EdgeType.INVOKES not in ceiling.prohibited_actions
        # The three categories this analysis cannot derive are
        # never proposed, never guessed.
        assert ceiling.prohibited_resources == ()
        assert ceiling.prohibited_external_destinations == ()
        assert ceiling.prohibited_data_classes == ()

    def test_delegation_observed_only_one_direction(self) -> None:
        """Positive: a one-way delegates-to edge only excludes that
        direction from its source agent's prohibition list."""
        source = _agent("agent-a", "1")
        target = _agent("agent-b", "2")
        delegates = _edge(EdgeType.DELEGATES_TO, source, target, "a-to-b")

        proposal = propose_starter_ceiling(
            (source, target), (source, target), (delegates,)
        )

        by_agent = {ceiling.agent: ceiling for ceiling in proposal.ceilings}
        assert "agent-b" not in by_agent["agent-a"].prohibited_delegation_targets
        assert by_agent["agent-b"].prohibited_delegation_targets == ("agent-a",)

    def test_agent_exercising_everything_alone_gets_no_entry(self) -> None:
        """Similar negative: an agent with nothing meaningful to
        propose (every tracked action observed, no other agent to
        restrict delegation to) produces no ceiling entry at all."""
        agent = _agent("solo-agent", "1")
        resource = _tool("only-tool", "1")
        edges = (
            _edge(EdgeType.READS, agent, resource, "r"),
            _edge(EdgeType.WRITES, agent, resource, "w"),
            _edge(EdgeType.INVOKES, agent, resource, "i"),
        )

        proposal = propose_starter_ceiling((agent,), (agent, resource), edges)

        assert proposal.ceilings == ()

    def test_unsafe_named_delegation_target_is_never_referenced(self) -> None:
        """Malformed/boundary: a discovered agent excluded from
        `agent_nodes` (an unsafe manifest identifier -- the caller's
        job, mirroring `render_draft_manifest`'s own filter) is never
        named as a delegation target, and never silently fabricated
        into a prohibition either."""
        safe = _agent("agent-a", "1")
        unsafe = _agent("Agent B", "2")
        delegates = _edge(EdgeType.DELEGATES_TO, safe, unsafe, "a-to-b")

        proposal = propose_starter_ceiling((safe,), (safe, unsafe), (delegates,))

        assert len(proposal.ceilings) == 1
        ceiling = proposal.ceilings[0]
        assert ceiling.agent == "agent-a"
        # No other safe agent exists to restrict delegation to.
        assert ceiling.prohibited_delegation_targets == ()
        # "Agent B" never appears anywhere in the proposal.
        assert "Agent B" not in repr(proposal)

    def test_unsafe_named_agents_own_actions_are_ignored_entirely(self) -> None:
        """Malformed/boundary: an action taken by an agent excluded from
        `agent_nodes` (an unsafe manifest identifier) never leaks into
        `observed_actions`, `low_confidence_actions`, or any other
        agent's ceiling -- the caller's filter is respected for the
        acting agent too, not only for delegation targets."""
        safe = _agent("agent-a", "1")
        unsafe = _agent("Agent B", "2")
        tool = _tool("some-tool", "1")
        unsafe_invokes = _edge(
            EdgeType.INVOKES, unsafe, tool, "b", confidence=Confidence.LOW
        )

        proposal = propose_starter_ceiling(
            (safe,), (safe, unsafe, tool), (unsafe_invokes,)
        )

        # Only "agent-a" exists in agent_nodes, so only it gets an
        # entry, and its own prohibited_actions are unaffected by an
        # action taken by an agent it never filtered in.
        assert len(proposal.ceilings) == 1
        assert proposal.ceilings[0].agent == "agent-a"
        assert set(proposal.ceilings[0].prohibited_actions) == {
            EdgeType.READS,
            EdgeType.WRITES,
            EdgeType.INVOKES,
        }
        assert proposal.low_confidence_actions == ()

    def test_low_confidence_action_excluded_and_listed_separately(self) -> None:
        """A low-confidence action is excluded from `prohibited_actions`
        (only actions with zero observed evidence may be prohibited) and
        appears in `low_confidence_actions` instead of being silently
        granted.
        An `authenticates-as` edge is included so
        `compute_effective_authority`'s own confidence-combination rule
        (weaker of the action edge and the identity edge) actually
        propagates the action edge's `LOW` confidence through, rather
        than the separate "no identity at all" `UNKNOWN` case the next
        test covers."""
        agent = _agent("refund-agent", "1")
        tool = _tool("issue-refund", "1")
        identity = _identity("api-key", "1")
        invokes = _edge(EdgeType.INVOKES, agent, tool, "a", confidence=Confidence.LOW)
        authenticates = _edge(EdgeType.AUTHENTICATES_AS, agent, identity, "auth")

        proposal = propose_starter_ceiling(
            (agent,), (agent, tool, identity), (invokes, authenticates)
        )

        ceiling = proposal.ceilings[0]
        assert EdgeType.INVOKES not in ceiling.prohibited_actions
        assert len(proposal.low_confidence_actions) == 1
        observation = proposal.low_confidence_actions[0]
        assert observation.agent_name == "refund-agent"
        assert observation.action == EdgeType.INVOKES
        assert observation.resource_name == "issue-refund"
        assert observation.confidence == Confidence.LOW

    def test_action_with_no_identity_edge_is_unknown_confidence(self) -> None:
        """Effective authority's "unknown, never omitted" rule: an
        action edge with no `authenticates-as` edge at all produces an
        `UNKNOWN`-confidence effective-authority entry, which the
        proposal treats the same as `LOW` -- excluded from
        `prohibited_actions`, surfaced in `low_confidence_actions`."""
        agent = _agent("refund-agent", "1")
        tool = _tool("issue-refund", "1")
        invokes = _edge(EdgeType.INVOKES, agent, tool, "a")

        proposal = propose_starter_ceiling((agent,), (agent, tool), (invokes,))

        ceiling = proposal.ceilings[0]
        assert EdgeType.INVOKES not in ceiling.prohibited_actions
        assert len(proposal.low_confidence_actions) == 1
        assert proposal.low_confidence_actions[0].confidence == Confidence.UNKNOWN

    def test_unknown_confidence_delegation_excluded_and_listed_separately(
        self,
    ) -> None:
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

        proposal = propose_starter_ceiling(
            (source, target), (source, target), (delegates,)
        )

        by_agent = {ceiling.agent: ceiling for ceiling in proposal.ceilings}
        assert "agent-b" not in by_agent["agent-a"].prohibited_delegation_targets
        assert len(proposal.low_confidence_delegations) == 1
        observation = proposal.low_confidence_delegations[0]
        assert observation.agent_name == "agent-a"
        assert observation.target_name == "agent-b"
        assert observation.confidence == Confidence.UNKNOWN

    def test_evidence_path_never_appears_in_the_proposal(self) -> None:
        """Privacy: the proposal carries only names/enums/confidence,
        never the underlying `Evidence.path`."""
        agent = _agent("refund-agent", "1")
        tool = _tool("issue-refund", "1")
        invokes = _edge(EdgeType.INVOKES, agent, tool, "a", confidence=Confidence.LOW)

        proposal = propose_starter_ceiling((agent,), (agent, tool), (invokes,))

        assert "agent-card.json" not in repr(proposal)

    def test_permuted_input_order_is_identical(self) -> None:
        """Determinism: identical input, regardless of original
        node/edge ordering, produces an identical proposal."""
        agent = _agent("refund-agent", "1")
        tool_a = _tool("tool-a", "a")
        tool_b = _tool("tool-b", "b")
        edge_a = _edge(EdgeType.INVOKES, agent, tool_a, "a")
        edge_b = _edge(EdgeType.WRITES, agent, tool_b, "b", confidence=Confidence.LOW)

        forward = propose_starter_ceiling(
            (agent,), (agent, tool_a, tool_b), (edge_a, edge_b)
        )
        reversed_ = propose_starter_ceiling(
            (agent,), (tool_b, tool_a, agent), (edge_b, edge_a)
        )

        assert forward == reversed_

    def test_repeated_calls_are_identical(self) -> None:
        agent = _agent("refund-agent", "1")
        tool = _tool("issue-refund", "1")
        invokes = _edge(EdgeType.INVOKES, agent, tool, "a")

        first = propose_starter_ceiling((agent,), (agent, tool), (invokes,))
        second = propose_starter_ceiling((agent,), (agent, tool), (invokes,))

        assert first == second
