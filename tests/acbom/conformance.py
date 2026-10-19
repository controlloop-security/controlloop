"""Reusable conformance check: unparseable input is never silently dropped.

This is a test-suite helper rather than production code -- an adapter test
suite imports `assert_unparseable_input_is_not_silently_dropped` and calls
it against its own discovery output.
"""

from __future__ import annotations

from collections.abc import Sequence

from controlloop.acbom import Diagnostic


def assert_unparseable_input_is_not_silently_dropped(
    diagnostics: Sequence[Diagnostic],
) -> None:
    """Fail if a discovery result silently dropped unparseable input.

    A conformant discovery result represents anything it could not
    resolve, parse, or stay within bounds for as an explicit
    ``incomplete=True`` diagnostic. An empty (or all-complete)
    diagnostics collection in the presence of unparseable input means
    the input was silently dropped instead -- exactly the "confident
    pass" failure mode the product exists to avoid.
    """

    if not any(diagnostic.incomplete for diagnostic in diagnostics):
        raise AssertionError(
            "no incomplete=True diagnostic found -- unparseable input may "
            "have been silently dropped instead of represented as unknown"
        )
