"""Tests for controlloop.capability.blast_radius."""

from __future__ import annotations

import random

from controlloop.acbom import (
    Confidence,
    Edge,
    EdgeStatus,
    EdgeType,
    Evidence,
    Node,
    NodeType,
    SecurityAttributes,
    Sensitivity,
)
from controlloop.capability import (
    BlastRadiusStatement,
    MaterialCapabilityClass,
    compute_blast_radius,
    describe_blast_radius,
)
from controlloop.capability.blast_radius import (
    _HEADLINE_VERB,
    CURRENT_BLAST_RADIUS_SCHEMA_VERSION,
)

_AGENT_ID = f"clp:agent:sha256:{'a' * 64}"
_RESOURCE_ID = f"clp:resource:sha256:{'c' * 64}"
_OTHER_RESOURCE_ID = f"clp:resource:sha256:{'e' * 64}"
_IDENTITY_ID = f"clp:identity:sha256:{'d' * 64}"


def _node(
    node_id: str,
    node_type: NodeType,
    *,
    name: str = "x",
    security_attributes: SecurityAttributes | None = None,
) -> Node:
    return Node(
        id=node_id,
        type=node_type,
        name=name,
        security_attributes=security_attributes or SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=(Evidence(adapter="mcp", path="a.json"),),
    )


def _edge(
    edge_type: EdgeType, source: str, target: str, *, edge_id_seed: str = "f"
) -> Edge:
    return Edge(
        id=f"clp:edge:sha256:{edge_id_seed * 64}",
        source=source,
        target=target,
        type=edge_type,
        status=EdgeStatus.DIRECT,
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=(Evidence(adapter="mcp", path="a.json"),),
    )


_AGENT_NODE = _node(_AGENT_ID, NodeType.AGENT, name="refund-agent")
_IDENTITY_NODE = _node(_IDENTITY_ID, NodeType.IDENTITY, name="service-account")


def _destructive_resource_node(node_id: str = _RESOURCE_ID, *, name: str) -> Node:
    return _node(
        node_id,
        NodeType.RESOURCE,
        name=name,
        security_attributes=SecurityAttributes(destructive=True),
    )


class TestWorstReachableAction:
    """The highest-ranked reachable action, by taxonomy ordering, with
    resource and permitting identity."""

    def test_picks_the_taxonomy_worst_class_among_several(self) -> None:
        destructive_resource = _destructive_resource_node(name="billing-db")
        mild_resource = _node(_OTHER_RESOURCE_ID, NodeType.RESOURCE, name="logs-db")
        nodes = (_AGENT_NODE, _IDENTITY_NODE, destructive_resource, mild_resource)
        edges = (
            _edge(EdgeType.WRITES, _AGENT_ID, _OTHER_RESOURCE_ID, edge_id_seed="1"),
            _edge(EdgeType.AUTHENTICATES_AS, _AGENT_ID, _IDENTITY_ID, edge_id_seed="2"),
            _edge(EdgeType.READS, _AGENT_ID, _RESOURCE_ID, edge_id_seed="3"),
        )

        statement = compute_blast_radius(nodes, edges)

        assert statement is not None
        assert statement.material_class is MaterialCapabilityClass.DESTRUCTIVE_ACTION
        assert statement.target_name == "billing-db"
        assert statement.agent_name == "refund-agent"

    def test_names_the_permitting_identity_when_known(self) -> None:
        resource = _destructive_resource_node(name="billing-db")
        nodes = (_AGENT_NODE, _IDENTITY_NODE, resource)
        edges = (
            _edge(EdgeType.READS, _AGENT_ID, _RESOURCE_ID, edge_id_seed="1"),
            _edge(EdgeType.AUTHENTICATES_AS, _AGENT_ID, _IDENTITY_ID, edge_id_seed="2"),
        )

        statement = compute_blast_radius(nodes, edges)

        assert statement is not None
        assert statement.permitting_identity_id == _IDENTITY_ID
        assert statement.permitting_identity_name == "service-account"

    def test_permitting_identity_is_none_when_unknown(self) -> None:
        resource = _destructive_resource_node(name="billing-db")
        nodes = (_AGENT_NODE, resource)
        edges = (_edge(EdgeType.READS, _AGENT_ID, _RESOURCE_ID),)

        statement = compute_blast_radius(nodes, edges)

        assert statement is not None
        assert statement.permitting_identity_id is None
        assert statement.permitting_identity_name is None


class TestTransitiveOnlyWorstAction:
    """Where the worst action is reachable only transitively, the statement
    says so and the path is available directly beneath the headline."""

    def test_transitive_only_worst_action_is_marked_and_carries_its_path(
        self,
    ) -> None:
        destructive_tool = _destructive_resource_node(_RESOURCE_ID, name="delete-tool")
        nodes = (_AGENT_NODE, _IDENTITY_NODE, destructive_tool)
        edges = (
            _edge(EdgeType.DELEGATES_TO, _AGENT_ID, _IDENTITY_ID, edge_id_seed="1"),
            _edge(EdgeType.INVOKES, _IDENTITY_ID, _RESOURCE_ID, edge_id_seed="2"),
        )

        statement = compute_blast_radius(nodes, edges)

        assert statement is not None
        assert statement.transitive is True
        assert len(statement.path) == 2

        lines = describe_blast_radius(statement)
        assert lines[0].startswith("! WORST REACHABLE")
        # Only the one-hop headline conjugates its verb; this wording stays.
        assert (
            "refund-agent can reach delete-tool via invokes (2-hop chain)" in (lines[0])
        )
        assert len(lines) == 3
        assert lines[1].strip().startswith("1.")
        assert lines[2].strip().startswith("2.")

    def test_direct_worst_action_is_not_marked_transitive(self) -> None:
        resource = _destructive_resource_node(name="billing-db")
        nodes = (_AGENT_NODE, resource)
        edges = (_edge(EdgeType.READS, _AGENT_ID, _RESOURCE_ID),)

        statement = compute_blast_radius(nodes, edges)

        assert statement is not None
        assert statement.transitive is False
        assert statement.path == ()
        lines = describe_blast_radius(statement)
        assert len(lines) == 1


class TestIncompleteAnalysis:
    """Where analysis is incomplete, the statement is qualified rather than
    stated as complete."""

    def test_a_bound_hit_anywhere_marks_the_statement_incomplete(self) -> None:
        destructive_resource = _destructive_resource_node(name="billing-db")
        far_identity_id = f"clp:identity:sha256:{'9' * 64}"
        far_identity = _node(far_identity_id, NodeType.IDENTITY, name="far-identity")
        nodes = (_AGENT_NODE, _IDENTITY_NODE, far_identity, destructive_resource)
        edges = (
            # A direct worst-class fact -- the winner -- alongside an
            # unrelated chain long enough to exceed a tight max_depth.
            _edge(EdgeType.READS, _AGENT_ID, _RESOURCE_ID, edge_id_seed="1"),
            _edge(EdgeType.AUTHENTICATES_AS, _AGENT_ID, _IDENTITY_ID, edge_id_seed="2"),
            _edge(
                EdgeType.DELEGATES_TO,
                _IDENTITY_ID,
                far_identity_id,
                edge_id_seed="3",
            ),
        )

        statement = compute_blast_radius(nodes, edges, max_depth=1)

        assert statement is not None
        assert statement.incomplete is True
        lines = describe_blast_radius(statement)
        assert "analysis incomplete" in lines[0]

    def test_no_bound_hit_is_not_marked_incomplete(self) -> None:
        resource = _destructive_resource_node(name="billing-db")
        nodes = (_AGENT_NODE, resource)
        edges = (_edge(EdgeType.READS, _AGENT_ID, _RESOURCE_ID),)

        statement = compute_blast_radius(nodes, edges)

        assert statement is not None
        assert statement.incomplete is False
        lines = describe_blast_radius(statement)
        assert "analysis incomplete" not in lines[0]


class TestDiscreteMachineField:
    """The machine-output half: `BlastRadiusStatement` is a discrete,
    independently serializable model."""

    def test_round_trips_through_json(self) -> None:
        resource = _destructive_resource_node(name="billing-db")
        nodes = (_AGENT_NODE, resource)
        edges = (_edge(EdgeType.READS, _AGENT_ID, _RESOURCE_ID),)
        statement = compute_blast_radius(nodes, edges)
        assert statement is not None

        restored = BlastRadiusStatement.model_validate_json(statement.model_dump_json())

        assert restored == statement


class TestReferenceRefundScenario:
    """A fixture asserts the exact expected sentence for the reference
    refund scenario -- refund-agent, permitted by service-account, able to
    write the destructive-and-financial billing-db resource."""

    def test_exact_expected_sentence(self) -> None:
        billing_db = _node(
            _RESOURCE_ID,
            NodeType.RESOURCE,
            name="billing-db",
            security_attributes=SecurityAttributes(
                destructive=True, sensitivity=Sensitivity.RESTRICTED
            ),
        )
        nodes = (_AGENT_NODE, _IDENTITY_NODE, billing_db)
        edges = (
            _edge(EdgeType.WRITES, _AGENT_ID, _RESOURCE_ID, edge_id_seed="1"),
            _edge(EdgeType.AUTHENTICATES_AS, _AGENT_ID, _IDENTITY_ID, edge_id_seed="2"),
        )

        statement = compute_blast_radius(nodes, edges)
        assert statement is not None
        lines = describe_blast_radius(statement)

        assert lines == (
            "! WORST REACHABLE  destructive-action: refund-agent can write "
            "billing-db, permitted by service-account",
        )


def _statement(action: EdgeType) -> BlastRadiusStatement:
    return BlastRadiusStatement(
        schema_version=CURRENT_BLAST_RADIUS_SCHEMA_VERSION,
        material_class=MaterialCapabilityClass.DESTRUCTIVE_ACTION,
        agent_id=_AGENT_ID,
        agent_name="refund-agent",
        action=action,
        target_id=_RESOURCE_ID,
        target_name="billing-db",
        transitive=False,
        incomplete=False,
    )


class TestHeadlineVerb:
    """The one-hop headline reads "can invoke", not the edge type's
    third-person value ("can invokes")."""

    def test_every_edge_type_has_a_headline_verb(self) -> None:
        """A new edge type fails here until its wording is decided."""
        assert set(_HEADLINE_VERB) == set(EdgeType)

    def test_no_one_hop_headline_uses_the_third_person_value(self) -> None:
        for action in EdgeType:
            (headline,) = describe_blast_radius(_statement(action))
            assert f" can {action.value} " not in headline
            assert f" can {_HEADLINE_VERB[action]} billing-db" in headline

    def test_invokes_reads_as_invoke(self) -> None:
        assert describe_blast_radius(_statement(EdgeType.INVOKES)) == (
            "! WORST REACHABLE  destructive-action: refund-agent can invoke billing-db",
        )


class TestBoundary:
    def test_empty_graph_returns_none(self) -> None:
        assert compute_blast_radius((), ()) is None

    def test_graph_with_no_material_classification_returns_none(self) -> None:
        benign_resource = _node(_RESOURCE_ID, NodeType.RESOURCE, name="scratch-file")
        nodes = (_AGENT_NODE, benign_resource)
        edges = (_edge(EdgeType.READS, _AGENT_ID, _RESOURCE_ID),)

        assert compute_blast_radius(nodes, edges) is None

    def test_describe_none_renders_no_material_capability_line(self) -> None:
        assert describe_blast_radius(None) == ("• no material capability is reachable",)

    def test_a_direct_edge_with_no_matching_resource_node_is_skipped(self) -> None:
        """Defensive branch: `compute_effective_authority` does not
        itself require `edge.target` to exist in `nodes` -- a real
        `ACBOMDocument` guarantees this, but `compute_blast_radius` is
        called directly here with a deliberately mismatched pair to
        prove a missing resource node is skipped rather than raising."""

        nodes = (_AGENT_NODE,)  # no resource node at all
        edges = (_edge(EdgeType.READS, _AGENT_ID, _RESOURCE_ID),)

        assert compute_blast_radius(nodes, edges) is None

    def test_authenticates_as_hop_to_an_undeclared_identity_leaves_identity_unknown(
        self,
    ) -> None:
        """A transitive path can traverse an intermediate
        `AUTHENTICATES_AS` hop to a node that was never itself
        declared in `nodes` (the walk only requires the *final*
        target's node type to be a known capability category, not
        every intermediate hop's). The permitting identity is then
        unknown, never fabricated or crashed on."""

        undeclared_identity_id = f"clp:identity:sha256:{'7' * 64}"
        destructive_resource = _destructive_resource_node(name="delete-tool")
        nodes = (_AGENT_NODE, destructive_resource)  # identity omitted
        edges = (
            _edge(
                EdgeType.AUTHENTICATES_AS,
                _AGENT_ID,
                undeclared_identity_id,
                edge_id_seed="1",
            ),
            _edge(
                EdgeType.INVOKES,
                undeclared_identity_id,
                _RESOURCE_ID,
                edge_id_seed="2",
            ),
        )

        statement = compute_blast_radius(nodes, edges)

        assert statement is not None
        assert statement.transitive is True
        assert statement.permitting_identity_id is None
        assert statement.permitting_identity_name is None

    def test_tie_between_direct_and_transitive_prefers_direct(self) -> None:
        """When a direct fact and a transitive fact reach the exact
        same (agent, target, action) and tie on the worst class, the
        deterministic sort key (`transitive` sorts after
        non-transitive) picks the direct one. A direct edge straight
        to the resource, plus a second, independent route through an
        identity that also ends by invoking the same resource,
        produces exactly this tie."""

        destructive_resource = _destructive_resource_node(name="delete-tool")
        nodes = (_AGENT_NODE, _IDENTITY_NODE, destructive_resource)
        edges = (
            _edge(EdgeType.INVOKES, _AGENT_ID, _RESOURCE_ID, edge_id_seed="1"),
            _edge(EdgeType.DELEGATES_TO, _AGENT_ID, _IDENTITY_ID, edge_id_seed="2"),
            _edge(EdgeType.INVOKES, _IDENTITY_ID, _RESOURCE_ID, edge_id_seed="3"),
        )

        statement = compute_blast_radius(nodes, edges)

        assert statement is not None
        assert statement.transitive is False
        assert statement.action is EdgeType.INVOKES
        assert statement.target_id == _RESOURCE_ID


class TestDeterminism:
    """Identical input, in any order, picks the same fact."""

    def test_order_independent(self) -> None:
        destructive_resource = _destructive_resource_node(name="billing-db")
        mild_resource = _node(_OTHER_RESOURCE_ID, NodeType.RESOURCE, name="logs-db")
        nodes = [_AGENT_NODE, _IDENTITY_NODE, destructive_resource, mild_resource]
        edges = [
            _edge(EdgeType.WRITES, _AGENT_ID, _OTHER_RESOURCE_ID, edge_id_seed="1"),
            _edge(EdgeType.AUTHENTICATES_AS, _AGENT_ID, _IDENTITY_ID, edge_id_seed="2"),
            _edge(EdgeType.READS, _AGENT_ID, _RESOURCE_ID, edge_id_seed="3"),
        ]

        random.shuffle(nodes)
        random.shuffle(edges)
        first = compute_blast_radius(tuple(nodes), tuple(edges))

        random.shuffle(nodes)
        random.shuffle(edges)
        second = compute_blast_radius(tuple(nodes), tuple(edges))

        assert first == second
        assert first is not None
        assert first.model_dump_json() == second.model_dump_json()  # type: ignore[union-attr]
