"""Tests for controlloop.diagnostics."""

from __future__ import annotations

import inspect
import re

import pytest
from pydantic import ValidationError

from controlloop.acbom.models import DiagnosticSeverity
from controlloop.diagnostics import (
    CLI_DIAGNOSTIC_REGISTRY,
    CliDiagnostic,
    cli_diagnostic,
    render_text,
    sort_key,
)

_CODE_PATTERN = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*$")


class TestCliDiagnostic:
    def test_carries_code_severity_message_and_location(self) -> None:
        """A diagnostic carries a code, severity, message, and location."""
        diagnostic = cli_diagnostic(
            code="CLI-INVALID-INPUT",
            severity=DiagnosticSeverity.ERROR,
            message="the supplied path does not exist",
            location="/tmp/missing.json",
        )

        assert diagnostic.code == "CLI-INVALID-INPUT"
        assert diagnostic.severity is DiagnosticSeverity.ERROR
        assert diagnostic.message == "the supplied path does not exist"
        assert diagnostic.location == "/tmp/missing.json"

    def test_location_defaults_to_none(self) -> None:
        diagnostic = cli_diagnostic(
            code="CLI-INTERNAL-ERROR",
            severity=DiagnosticSeverity.ERROR,
            message="something went wrong",
        )

        assert diagnostic.location is None

    def test_serializes_to_json_with_every_field(self) -> None:
        """Serializes identically regardless of output format --
        proven here against the model's own ordinary JSON form, the
        form any future machine output reuses."""
        diagnostic = cli_diagnostic(
            code="CLI-INVALID-CONFIG",
            severity=DiagnosticSeverity.ERROR,
            message="the repository file is malformed",
            location="controlloop.toml",
        )

        payload = diagnostic.model_dump(mode="json")

        assert payload == {
            "code": "CLI-INVALID-CONFIG",
            "severity": "error",
            "message": "the repository file is malformed",
            "location": "controlloop.toml",
        }

    def test_location_accepts_an_absolute_path(self) -> None:
        """`location` is deliberately not the ACBOM layer's
        `RelativePath` -- a user-supplied CLI path can be absolute or
        outside the repository, and rejecting it here would turn
        *reporting* an ordinary user error into a second, unrelated
        validation failure."""
        diagnostic = cli_diagnostic(
            code="CLI-INVALID-INPUT",
            severity=DiagnosticSeverity.ERROR,
            message="could not be written",
            location="/absolute/outside/the/repo.json",
        )

        assert diagnostic.location == "/absolute/outside/the/repo.json"

    def test_unknown_field_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            CliDiagnostic.model_validate(
                {
                    "code": "CLI-INVALID-INPUT",
                    "severity": "error",
                    "message": "x",
                    "extra_field": "leaked",
                }
            )


class TestCliDiagnosticFunction:
    def test_unregistered_code_is_rejected(self) -> None:
        """A code outside the registry is rejected before any
        model is built."""
        with pytest.raises(ValueError, match="not a registered CLI diagnostic code"):
            cli_diagnostic(
                code="CLI-BOGUS-CODE",
                severity=DiagnosticSeverity.ERROR,
                message="x",
            )

    @pytest.mark.parametrize("code", tuple(CLI_DIAGNOSTIC_REGISTRY))
    def test_every_registered_code_constructs_successfully(self, code: str) -> None:
        diagnostic = cli_diagnostic(
            code=code, severity=DiagnosticSeverity.WARNING, message="a message"
        )

        assert diagnostic.code == code


class TestRegistry:
    def test_every_code_matches_the_diagnostic_code_pattern(self) -> None:
        assert all(_CODE_PATTERN.fullmatch(code) for code in CLI_DIAGNOSTIC_REGISTRY)

    def test_every_description_is_nonempty(self) -> None:
        assert all(
            description.strip() for description in CLI_DIAGNOSTIC_REGISTRY.values()
        )

    def test_registry_names_every_known_cli_diagnostic_category(self) -> None:
        """Adding a code to the registry without updating this literal set
        fails this test, so the registry cannot grow unnoticed."""
        assert set(CLI_DIAGNOSTIC_REGISTRY) == {
            "CLI-INVALID-INPUT",
            "CLI-INVALID-CONFIG",
            "CLI-INVALID-ACBOM",
            "CLI-NOT-IMPLEMENTED",
            "CLI-INTERNAL-ERROR",
            "CLI-NONINTERACTIVE-ENVIRONMENT",
            # The Team codes. Reachable only when
            # `team_enabled` is true; a Community run emits none of them.
            "CLI-TEAM-STATUS",
            "CLI-TEAM-ENTITLEMENT",
            "CLI-TEAM-POLICY-REJECTED",
            "CLI-TEAM-EXCEPTION-EXPIRED",
            "CLI-TEAM-EXCEPTION-APPLIED",
            "CLI-TEAM-UPLOAD",
            "CLI-TEAM-UPLOAD-SKIPPED",
        }


class TestRenderText:
    @pytest.mark.parametrize(
        ("severity", "glyph"),
        [
            (DiagnosticSeverity.ERROR, "✕"),
            (DiagnosticSeverity.WARNING, "!"),
            (DiagnosticSeverity.INFO, "•"),
        ],
    )
    def test_glyph_matches_severity(
        self, severity: DiagnosticSeverity, glyph: str
    ) -> None:
        diagnostic = cli_diagnostic(
            code="CLI-INVALID-INPUT", severity=severity, message="a message"
        )

        assert render_text(diagnostic).startswith(glyph)

    def test_label_is_derived_from_the_code(self) -> None:
        diagnostic = cli_diagnostic(
            code="CLI-NOT-IMPLEMENTED",
            severity=DiagnosticSeverity.WARNING,
            message="x is not implemented yet.",
        )

        assert render_text(diagnostic) == "! NOT IMPLEMENTED  x is not implemented yet."

    def test_location_is_omitted_when_absent(self) -> None:
        diagnostic = cli_diagnostic(
            code="CLI-INTERNAL-ERROR",
            severity=DiagnosticSeverity.ERROR,
            message="boom",
        )

        assert render_text(diagnostic) == "✕ INTERNAL ERROR  boom"

    def test_location_is_appended_in_parentheses_when_present(self) -> None:
        diagnostic = cli_diagnostic(
            code="CLI-INVALID-INPUT",
            severity=DiagnosticSeverity.ERROR,
            message="could not be read: No such file or directory",
            location="/tmp/missing.json",
        )

        assert render_text(diagnostic) == (
            "✕ INVALID INPUT  could not be read: No such file or directory "
            "(/tmp/missing.json)"
        )


class TestSortKey:
    def test_orders_by_code_then_location_then_message(self) -> None:
        """Deterministic ordering for a collection of
        diagnostics, independent of construction order."""
        first = cli_diagnostic(
            code="CLI-INVALID-CONFIG", severity=DiagnosticSeverity.ERROR, message="a"
        )
        second = cli_diagnostic(
            code="CLI-INVALID-INPUT",
            severity=DiagnosticSeverity.ERROR,
            message="a",
            location="a.json",
        )
        third = cli_diagnostic(
            code="CLI-INVALID-INPUT",
            severity=DiagnosticSeverity.ERROR,
            message="a",
            location="b.json",
        )

        shuffled = [third, first, second]
        ordered = sorted(shuffled, key=sort_key)

        assert ordered == [first, second, third]

    def test_ordering_is_repeatable(self) -> None:
        diagnostics = [
            cli_diagnostic(
                code="CLI-INVALID-INPUT",
                severity=DiagnosticSeverity.ERROR,
                message=f"message-{index}",
            )
            for index in range(5)
        ]

        first_order = sorted(diagnostics, key=sort_key)
        second_order = sorted(reversed(diagnostics), key=sort_key)

        assert first_order == second_order


class TestNoExitCodeDependency:
    def test_module_never_imports_exit_codes_or_process_exit(self) -> None:
        """A `CliDiagnostic` never changes the exit code on its
        own -- verified structurally, the same way this codebase already
        proves other isolation guarantees (for example the adapter
        sandbox's "canonical layer holds no format-specific branches"
        test): the module's actual `import` statements never bind
        `ExitCode`, `sys`, or `typer`, so there is no code path inside it
        that could touch process exit status -- checked against the
        parsed import tree, not a raw substring scan of the source
        (which would also match this docstring's own prose). Every
        actual exit-code decision remains the caller's, in
        `controlloop.cli`."""
        import ast

        from controlloop import diagnostics

        tree = ast.parse(inspect.getsource(diagnostics))
        imported_names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import | ast.ImportFrom):
                imported_names.update(
                    alias.asname or alias.name for alias in node.names
                )

        assert "ExitCode" not in imported_names
        assert "sys" not in imported_names
        assert "typer" not in imported_names
