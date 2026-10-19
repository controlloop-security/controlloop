"""Tests for controlloop.diff.reduction."""

from __future__ import annotations

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
from controlloop.capability.models import PathHop
from controlloop.capability.taxonomy import (
    MaterialCapabilityClass,
    classify_material_capability,
)
from controlloop.diff import (
    CapabilityReductionReport,
    MaterialChange,
    MaterialChangeKind,
    MaterialChangeSummary,
    compute_capability_reduction_report,
    compute_material_change_summary,
    describe_capability_reduction,
)

_AGENT_ID = f"clp:agent:sha256:{'a' * 64}"
_RESOURCE_ID = f"clp:resource:sha256:{'c' * 64}"
_OTHER_RESOURCE_ID = f"clp:resource:sha256:{'e' * 64}"


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


def _destructive_resource_node(node_id: str = _RESOURCE_ID, *, name: str) -> Node:
    return _node(
        node_id,
        NodeType.RESOURCE,
        name=name,
        security_attributes=SecurityAttributes(destructive=True),
    )


_DESTRUCTIVE = MaterialCapabilityClass.DESTRUCTIVE_ACTION


def _change(
    kind: MaterialChangeKind,
    *,
    material_class: MaterialCapabilityClass = _DESTRUCTIVE,
    target_id: str = _RESOURCE_ID,
    target_name: str = "billing-db",
    action: EdgeType = EdgeType.READS,
    transitive: bool = False,
    path: tuple[PathHop, ...] = (),
) -> MaterialChange:
    return MaterialChange(
        kind=kind,
        material_class=material_class,
        agent_id=_AGENT_ID,
        agent_name="refund-agent",
        action=action,
        target_id=target_id,
        target_name=target_name,
        transitive=transitive,
        path=path,
    )


def _summary(*changes: MaterialChange) -> MaterialChangeSummary:
    return MaterialChangeSummary(schema_version="1.0.0", changes=changes)


class TestSameVocabularyAsAdditions:
    """Removed capabilities are summarized by material class in
    the same vocabulary as additions -- proven end to end, not just at
    the model level, since a real reduction and a real gain of the
    exact same fact must classify identically."""

    def test_a_reduction_and_a_gain_of_the_same_fact_share_a_material_class(
        self,
    ) -> None:
        resource = _destructive_resource_node(name="billing-db")
        edges = (_edge(EdgeType.READS, _AGENT_ID, _RESOURCE_ID),)

        gained_summary = compute_material_change_summary(
            baseline_nodes=(),
            baseline_edges=(),
            current_nodes=(_AGENT_NODE, resource),
            current_edges=edges,
        )
        lost_summary = compute_material_change_summary(
            baseline_nodes=(_AGENT_NODE, resource),
            baseline_edges=edges,
            current_nodes=(),
            current_edges=(),
        )

        gained_classes = {c.material_class for c in gained_summary.changes}
        lost_classes = {c.material_class for c in lost_summary.changes}
        assert (
            gained_classes
            == lost_classes
            == {MaterialCapabilityClass.DESTRUCTIVE_ACTION}
        )

        report = compute_capability_reduction_report(lost_summary)
        assert report.reductions[0].material_class == next(
            iter(
                classify_material_capability(
                    resource.security_attributes, edge_type=EdgeType.READS
                )
            )
        )


class TestReductionOnlyPasses:
    """A change containing only reductions passes and states
    what was reduced."""

    def test_reduction_only_summary_is_reduction_only(self) -> None:
        summary = _summary(_change(MaterialChangeKind.LOST))

        report = compute_capability_reduction_report(summary)

        assert report.is_reduction_only is True
        assert len(report.reductions) == 1
        assert report.other_changes == ()

    def test_reduction_only_report_states_what_was_reduced(self) -> None:
        summary = _summary(_change(MaterialChangeKind.LOST))
        report = compute_capability_reduction_report(summary)

        lines = describe_capability_reduction(report)

        assert len(lines) == 2
        assert lines[0].startswith("• REDUCED")
        assert "destructive-action" in lines[0]
        assert "refund-agent" in lines[0]
        assert "billing-db" in lines[0]
        assert (
            lines[1] == "✓ PASSED   capability reduced only -- no new authority gained"
        )

    def test_transitive_reduction_line_names_the_hop_count(self) -> None:
        identity_id = f"clp:identity:sha256:{'d' * 64}"
        hops = (
            PathHop(
                edge_id=f"clp:edge:sha256:{'1' * 64}",
                edge_type=EdgeType.DELEGATES_TO,
                source_id=_AGENT_ID,
                target_id=identity_id,
                evidence=(Evidence(adapter="mcp", path="a.json"),),
            ),
            PathHop(
                edge_id=f"clp:edge:sha256:{'2' * 64}",
                edge_type=EdgeType.INVOKES,
                source_id=identity_id,
                target_id=_RESOURCE_ID,
                evidence=(Evidence(adapter="mcp", path="a.json"),),
            ),
        )
        summary = _summary(
            _change(
                MaterialChangeKind.LOST,
                transitive=True,
                action=EdgeType.INVOKES,
                path=hops,
            )
        )
        report = compute_capability_reduction_report(summary)

        lines = describe_capability_reduction(report)

        assert lines[0].startswith("• REDUCED")
        assert "no longer reaches" in lines[0]
        assert "2-hop chain" in lines[0]

    def test_a_gain_alongside_a_reduction_is_not_reduction_only(self) -> None:
        summary = _summary(
            _change(MaterialChangeKind.LOST),
            _change(
                MaterialChangeKind.GAINED,
                target_id=_OTHER_RESOURCE_ID,
                target_name="orders-db",
            ),
        )

        report = compute_capability_reduction_report(summary)
        lines = describe_capability_reduction(report)

        assert report.is_reduction_only is False
        assert not any(line.startswith("✓ PASSED") for line in lines)
        assert len(lines) == 1
        assert lines[0].startswith("• REDUCED")

    def test_no_reductions_at_all_renders_no_lines(self) -> None:
        summary = _summary(_change(MaterialChangeKind.GAINED))
        report = compute_capability_reduction_report(summary)

        lines = describe_capability_reduction(report)

        assert lines == ()
        assert report.is_reduction_only is False


class TestJsonOutput:
    """Structural JSON output: a reduction report is an
    ordinary pydantic model."""

    def test_round_trips_through_json(self) -> None:
        summary = _summary(
            _change(MaterialChangeKind.LOST),
            _change(
                MaterialChangeKind.CHANGED,
                target_id=_OTHER_RESOURCE_ID,
                target_name="orders-db",
            ),
        )
        report = compute_capability_reduction_report(summary)

        restored = CapabilityReductionReport.model_validate_json(
            report.model_dump_json()
        )

        assert restored == report


class TestNeverMiscountedAsAFinding:
    """A reduction is never miscounted as a finding or a
    failure -- `reductions` and `other_changes` are disjoint and
    together exactly reconstruct the original summary."""

    def test_reductions_and_other_changes_are_disjoint_and_complete(self) -> None:
        gained = _change(MaterialChangeKind.GAINED, target_id=_OTHER_RESOURCE_ID)
        lost = _change(MaterialChangeKind.LOST)
        changed = _change(
            MaterialChangeKind.CHANGED,
            target_id=f"clp:resource:sha256:{'9' * 64}",
        )
        unknown = _change(
            MaterialChangeKind.UNKNOWN,
            target_id=f"clp:resource:sha256:{'8' * 64}",
        )
        summary = _summary(gained, lost, changed, unknown)

        report = compute_capability_reduction_report(summary)

        assert set(report.reductions) == {lost}
        assert set(report.other_changes) == {gained, changed, unknown}
        assert set(report.reductions) & set(report.other_changes) == set()
        assert set(report.reductions) | set(report.other_changes) == set(
            summary.changes
        )

    def test_no_lost_kind_change_ever_appears_in_reductions(self) -> None:
        summary = _summary(
            _change(MaterialChangeKind.GAINED),
            _change(MaterialChangeKind.CHANGED, target_id=_OTHER_RESOURCE_ID),
        )

        report = compute_capability_reduction_report(summary)

        assert report.reductions == ()
        assert len(report.other_changes) == 2


class TestBoundary:
    def test_empty_summary_is_not_reduction_only(self) -> None:
        summary = _summary()

        report = compute_capability_reduction_report(summary)

        assert report.reductions == ()
        assert report.other_changes == ()
        assert report.is_reduction_only is False

    def test_only_changed_and_unknown_is_not_reduction_only(self) -> None:
        summary = _summary(
            _change(MaterialChangeKind.CHANGED),
            _change(MaterialChangeKind.UNKNOWN, target_id=_OTHER_RESOURCE_ID),
        )

        report = compute_capability_reduction_report(summary)

        assert report.is_reduction_only is False


class TestDeterminism:
    def test_identical_summary_produces_an_identical_report(self) -> None:
        summary = _summary(
            _change(MaterialChangeKind.LOST),
            _change(MaterialChangeKind.GAINED, target_id=_OTHER_RESOURCE_ID),
        )

        first = compute_capability_reduction_report(summary)
        second = compute_capability_reduction_report(summary)

        assert first == second
        assert first.model_dump_json() == second.model_dump_json()
