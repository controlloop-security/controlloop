"""Exit codes live in one module, enumerated in one test."""

from controlloop.exit_codes import ExitCode


def test_every_exit_code_is_defined_exactly_once() -> None:
    assert list(ExitCode) == [
        ExitCode.PASS,
        ExitCode.POLICY_FAIL,
        ExitCode.INVALID_INPUT,
        ExitCode.INCOMPLETE_ANALYSIS,
        ExitCode.ENTITLEMENT,
        ExitCode.INTERNAL_ERROR,
    ]


def test_exit_code_values_match_the_requirements_contract() -> None:
    assert int(ExitCode.PASS) == 0
    assert int(ExitCode.POLICY_FAIL) == 1
    assert int(ExitCode.INVALID_INPUT) == 2
    assert int(ExitCode.INCOMPLETE_ANALYSIS) == 3
    assert int(ExitCode.ENTITLEMENT) == 4
    assert int(ExitCode.INTERNAL_ERROR) == 5
