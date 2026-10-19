"""Tests for `docs/concepts/acbom.md`'s generated examples.

The doc-sync tests below make sure `docs/concepts/acbom.md` never quietly
drifts from `tests/concepts/reference_fixture.py`'s
real fixture and real capability-path computation, because a mismatch
fails the suite instead of only being noticed by a human reader.
"""

from __future__ import annotations

from pathlib import Path

from reference_fixture import (
    EDGES,
    GENERATED_FRAGMENTS,
    NODES,
    REFUND_AGENT,
    REFUND_WRITE,
    extract_generated_fragments,
    render_direct_path_example,
    render_edge_examples,
    render_node_examples,
    render_transitive_path_example,
    render_unknown_example,
)

from controlloop.acbom import EdgeType, NodeType
from controlloop.capability.compute import compute_direct_capability_paths

_DOC_PATH = Path(__file__).resolve().parents[2] / "docs" / "concepts" / "acbom.md"


class TestFixtureCoverage:
    """Every node type and every edge type appears in the
    reference fixture at least once."""

    def test_every_node_type_is_covered(self) -> None:
        assert {node.type for node in NODES} == set(NodeType)

    def test_every_edge_type_is_covered(self) -> None:
        assert {edge.type for edge in EDGES} == set(EdgeType)

    def test_fixture_is_one_connected_scenario(self) -> None:
        node_ids = {node.id for node in NODES}
        for edge in EDGES:
            assert edge.source in node_ids
            assert edge.target in node_ids


class TestDocStaysInSyncWithTheGenerator:
    """`docs/concepts/acbom.md`'s generated regions are
    byte-for-byte identical to a fresh call to their generator."""

    def test_doc_generated_fragments_match_the_generator_exactly(self) -> None:
        doc_text = _DOC_PATH.read_text(encoding="utf-8")
        doc_fragments = extract_generated_fragments(doc_text)

        assert doc_fragments == GENERATED_FRAGMENTS

    def test_doc_contains_every_expected_marker_exactly_once(self) -> None:
        doc_text = _DOC_PATH.read_text(encoding="utf-8")

        for name in GENERATED_FRAGMENTS:
            assert doc_text.count(f"<!-- BEGIN GENERATED: {name} -->") == 1
            assert doc_text.count(f"<!-- END GENERATED: {name} -->") == 1


class TestExtractGeneratedFragments:
    """Boundary and malformed-input coverage for the extraction helper
    itself, independent of the real doc file."""

    def test_extracts_one_fragment(self) -> None:
        text = (
            "before\n"
            "<!-- BEGIN GENERATED: example -->\n"
            "line one\nline two\n"
            "<!-- END GENERATED: example -->\n"
            "after"
        )

        assert extract_generated_fragments(text) == {"example": "line one\nline two"}

    def test_no_markers_present_returns_empty(self) -> None:
        assert extract_generated_fragments("just plain prose, no markers") == {}

    def test_duplicate_marker_name_raises(self) -> None:
        text = (
            "<!-- BEGIN GENERATED: dup -->\na\n<!-- END GENERATED: dup -->\n"
            "<!-- BEGIN GENERATED: dup -->\nb\n<!-- END GENERATED: dup -->\n"
        )

        try:
            extract_generated_fragments(text)
        except ValueError as error:
            assert "dup" in str(error)
        else:
            raise AssertionError("expected ValueError for duplicate marker name")

    def test_mismatched_marker_names_are_not_paired(self) -> None:
        text = "<!-- BEGIN GENERATED: alpha -->\ncontent\n<!-- END GENERATED: beta -->"

        assert extract_generated_fragments(text) == {}


class TestGeneratorsAreDeterministic:
    """Identical fixture input produces an identical rendered fragment
    on repeated calls, per the repository's determinism discipline."""

    def test_node_examples_are_deterministic(self) -> None:
        assert render_node_examples() == render_node_examples()

    def test_edge_examples_are_deterministic(self) -> None:
        assert render_edge_examples() == render_edge_examples()

    def test_direct_path_example_is_deterministic(self) -> None:
        assert render_direct_path_example() == render_direct_path_example()

    def test_transitive_path_example_is_deterministic(self) -> None:
        assert render_transitive_path_example() == render_transitive_path_example()

    def test_unknown_example_is_deterministic(self) -> None:
        assert render_unknown_example() == render_unknown_example()


class TestGeneratedContent:
    """Spot-check the semantic claims the doc makes about
    the generated content, not just that the doc matches the
    generator."""

    def test_transitive_path_has_no_direct_counterpart(self) -> None:
        """The transitive example is only reachable in two hops
        precisely because no direct edge connects the same endpoints."""

        direct_paths = compute_direct_capability_paths(NODES, EDGES)

        assert not any(
            path.agent_id == REFUND_AGENT.id and path.target_id == REFUND_WRITE.id
            for path in direct_paths
        )

    def test_unknown_example_is_marked_incomplete_and_unknown_confidence(
        self,
    ) -> None:
        rendered = render_unknown_example()

        assert "confidence: unknown" in rendered
        assert "INCOMPLETE-DYNAMIC-REGISTRATION" in rendered
