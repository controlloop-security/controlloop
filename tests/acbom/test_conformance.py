"""Demonstrates the unparseable-input conformance check against a fake
conformant and a fake non-conformant discovery result -- proving the check
itself actually catches a silently dropped input, not just that it exists.
"""

from __future__ import annotations

import pytest
from conformance import assert_unparseable_input_is_not_silently_dropped

from controlloop.acbom import (
    Confidence,
    Diagnostic,
    DiagnosticSeverity,
    Evidence,
    incomplete_diagnostic,
)


def _conformant_discover(unparseable_input: str) -> tuple[Diagnostic, ...]:
    """A fake adapter that does the right thing: it represents what it
    could not parse as an explicit unknown."""
    return (
        incomplete_diagnostic(
            code="INCOMPLETE-UNPARSED-REGION",
            message="A region of the input could not be parsed.",
            evidence=(Evidence(adapter="fake", path="input.json"),),
        ),
    )


def _non_conformant_discover(unparseable_input: str) -> tuple[Diagnostic, ...]:
    """A fake adapter that silently drops what it could not parse --
    exactly the violation the conformance check exists to catch."""
    return ()


def _non_conformant_discover_with_only_complete_diagnostics(
    unparseable_input: str,
) -> tuple[Diagnostic, ...]:
    """A subtler violation: some diagnostic exists, but none of them
    actually flag the unparseable region as incomplete."""
    return (
        Diagnostic(
            code="ORDINARY-INFO",
            severity=DiagnosticSeverity.INFO,
            message="Discovery completed.",
            confidence=Confidence.HIGH,
            incomplete=False,
            evidence=(Evidence(adapter="fake", path="input.json"),),
        ),
    )


def test_conformant_discovery_passes() -> None:
    diagnostics = _conformant_discover("{unparseable")

    assert_unparseable_input_is_not_silently_dropped(diagnostics)


def test_non_conformant_discovery_fails_the_conformance_check() -> None:
    diagnostics = _non_conformant_discover("{unparseable")

    with pytest.raises(AssertionError, match="silently dropped"):
        assert_unparseable_input_is_not_silently_dropped(diagnostics)


def test_non_conformant_discovery_with_only_complete_diagnostics_still_fails() -> None:
    diagnostics = _non_conformant_discover_with_only_complete_diagnostics(
        "{unparseable"
    )

    with pytest.raises(AssertionError, match="silently dropped"):
        assert_unparseable_input_is_not_silently_dropped(diagnostics)
