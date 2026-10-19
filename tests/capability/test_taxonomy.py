"""Tests for controlloop.capability.taxonomy."""

from __future__ import annotations

import pytest

from controlloop.acbom import EdgeType, SecurityAttributes, Sensitivity
from controlloop.capability import (
    MaterialCapabilityClass,
    classify_material_capability,
    worst_class,
)

_CLASS = MaterialCapabilityClass


def test_no_classes_for_a_fully_benign_resource() -> None:
    result = classify_material_capability(SecurityAttributes())

    assert result == frozenset()


class TestPerClassFixtures:
    """One positive fixture per class."""

    def test_destructive_action(self) -> None:
        attrs = SecurityAttributes(destructive=True)

        assert classify_material_capability(attrs) == {_CLASS.DESTRUCTIVE_ACTION}

    def test_financial_action(self) -> None:
        attrs = SecurityAttributes(financial_action=True)

        assert classify_material_capability(attrs) == {_CLASS.FINANCIAL_ACTION}

    def test_code_execution(self) -> None:
        attrs = SecurityAttributes(code_execution=True)

        assert classify_material_capability(attrs) == {_CLASS.CODE_EXECUTION}

    def test_external_communication(self) -> None:
        attrs = SecurityAttributes(external_communication=True)

        assert classify_material_capability(attrs) == {_CLASS.EXTERNAL_COMMUNICATION}

    @pytest.mark.parametrize(
        "sensitivity", [Sensitivity.CONFIDENTIAL, Sensitivity.RESTRICTED]
    )
    def test_sensitive_data_access_via_sensitivity(
        self, sensitivity: Sensitivity
    ) -> None:
        attrs = SecurityAttributes(sensitivity=sensitivity)

        assert classify_material_capability(attrs) == {_CLASS.SENSITIVE_DATA_ACCESS}

    def test_sensitive_data_access_via_data_classifications(self) -> None:
        attrs = SecurityAttributes(data_classifications=("customer-pii",))

        assert classify_material_capability(attrs) == {_CLASS.SENSITIVE_DATA_ACCESS}

    @pytest.mark.parametrize(
        "sensitivity", [Sensitivity.PUBLIC, Sensitivity.INTERNAL, None]
    )
    def test_non_sensitive_levels_do_not_classify(
        self, sensitivity: Sensitivity | None
    ) -> None:
        attrs = SecurityAttributes(sensitivity=sensitivity)

        assert classify_material_capability(attrs) == frozenset()

    def test_delegation(self) -> None:
        result = classify_material_capability(
            SecurityAttributes(), edge_type=EdgeType.DELEGATES_TO
        )

        assert result == {_CLASS.DELEGATION}

    def test_write_access_via_writes_edge(self) -> None:
        result = classify_material_capability(
            SecurityAttributes(), edge_type=EdgeType.WRITES
        )

        assert result == {_CLASS.WRITE_ACCESS}

    def test_write_access_via_invokes_with_read_only_false(self) -> None:
        result = classify_material_capability(
            SecurityAttributes(read_only=False), edge_type=EdgeType.INVOKES
        )

        assert result == {_CLASS.WRITE_ACCESS}

    def test_invokes_with_read_only_true_does_not_classify_as_write(self) -> None:
        result = classify_material_capability(
            SecurityAttributes(read_only=True), edge_type=EdgeType.INVOKES
        )

        assert result == frozenset()

    def test_reads_edge_never_classifies_as_write_access(self) -> None:
        result = classify_material_capability(
            SecurityAttributes(read_only=False), edge_type=EdgeType.READS
        )

        assert _CLASS.WRITE_ACCESS not in result


def test_multiple_classes_are_all_reported() -> None:
    """A capability may hold multiple classes and reports all of them."""
    attrs = SecurityAttributes(destructive=True, external_communication=True)

    result = classify_material_capability(attrs)

    assert result == {_CLASS.DESTRUCTIVE_ACTION, _CLASS.EXTERNAL_COMMUNICATION}


class TestUnclassified:
    """An unclassifiable capability is marked unclassified, never defaulted
    to harmless. `"unknown"` (an explicit assertion of indeterminacy) and
    `None` (no assertion at all) are distinct."""

    @pytest.mark.parametrize(
        "field",
        ["destructive", "financial_action", "code_execution", "external_communication"],
    )
    def test_unknown_boolean_field_adds_unclassified(self, field: str) -> None:
        attrs = SecurityAttributes.model_validate({field: "unknown"})

        result = classify_material_capability(attrs)

        assert _CLASS.UNCLASSIFIED in result
        # The field's own positive class is not also claimed.
        assert len(result) == 1

    @pytest.mark.parametrize(
        "field",
        ["destructive", "financial_action", "code_execution", "external_communication"],
    )
    def test_none_boolean_field_does_not_add_unclassified(self, field: str) -> None:
        attrs = SecurityAttributes.model_validate({field: None})

        result = classify_material_capability(attrs)

        assert result == frozenset()

    @pytest.mark.parametrize(
        "field",
        ["destructive", "financial_action", "code_execution", "external_communication"],
    )
    def test_false_boolean_field_does_not_add_unclassified(self, field: str) -> None:
        attrs = SecurityAttributes.model_validate({field: False})

        result = classify_material_capability(attrs)

        assert result == frozenset()

    def test_unknown_sensitivity_adds_unclassified(self) -> None:
        attrs = SecurityAttributes(sensitivity=Sensitivity.UNKNOWN)

        result = classify_material_capability(attrs)

        assert result == {_CLASS.UNCLASSIFIED}

    def test_unknown_read_only_on_invokes_adds_unclassified(self) -> None:
        result = classify_material_capability(
            SecurityAttributes(read_only="unknown"), edge_type=EdgeType.INVOKES
        )

        assert result == {_CLASS.UNCLASSIFIED}

    def test_unresolved_read_only_on_a_non_invokes_edge_is_not_unclassified(
        self,
    ) -> None:
        """`read_only` only matters for `invokes`; leaving it unknown on
        an edge type where it is not consulted must not spuriously mark
        the capability unclassified."""
        result = classify_material_capability(
            SecurityAttributes(read_only="unknown"), edge_type=EdgeType.READS
        )

        assert result == frozenset()


class TestWorstClass:
    def test_picks_the_most_severe(self) -> None:
        assert (
            worst_class({_CLASS.WRITE_ACCESS, _CLASS.DESTRUCTIVE_ACTION})
            is _CLASS.DESTRUCTIVE_ACTION
        )

    def test_unclassified_ranks_worst_of_all(self) -> None:
        """An unknown risk must never be treated as safer than a known
        one."""
        assert (
            worst_class({_CLASS.DESTRUCTIVE_ACTION, _CLASS.UNCLASSIFIED})
            is _CLASS.UNCLASSIFIED
        )

    def test_raises_on_empty_input(self) -> None:
        with pytest.raises(ValueError, match="requires at least one class"):
            worst_class([])

    def test_full_documented_ordering(self) -> None:
        """The complete worst-to-least-severe ordering, asserted
        directly against the taxonomy's own documented rationale."""
        ordering = [
            _CLASS.UNCLASSIFIED,
            _CLASS.DESTRUCTIVE_ACTION,
            _CLASS.FINANCIAL_ACTION,
            _CLASS.CODE_EXECUTION,
            _CLASS.EXTERNAL_COMMUNICATION,
            _CLASS.SENSITIVE_DATA_ACCESS,
            _CLASS.DELEGATION,
            _CLASS.WRITE_ACCESS,
        ]

        for index in range(len(ordering) - 1):
            worse, better = ordering[index], ordering[index + 1]
            assert worst_class({worse, better}) is worse

        assert set(ordering) == set(_CLASS)


class TestDeterminism:
    def test_classification_is_deterministic(self) -> None:
        attrs = SecurityAttributes(destructive=True, code_execution=True)

        first = classify_material_capability(attrs, edge_type=EdgeType.INVOKES)
        second = classify_material_capability(attrs, edge_type=EdgeType.INVOKES)

        assert first == second

    def test_result_is_a_frozenset(self) -> None:
        result = classify_material_capability(SecurityAttributes(destructive=True))

        assert isinstance(result, frozenset)
