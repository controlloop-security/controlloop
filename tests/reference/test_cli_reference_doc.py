"""Tests for `docs/reference/cli.md` and `docs/reference/configuration.md`.

Lives beside `cli_doc_fixtures.py` in `tests/reference/`, mirroring
`tests/concepts/`'s own established layout for a doc-fixture module and
its drift-guard test.

- `TestGeneratedFragmentsMatch` -- the exit-code table and the
  configuration-key table are real generated fragments (see
  `tests/reference/cli_doc_fixtures.py`), extracted from the committed
  docs via `tests/concepts/reference_fixture.py`'s own established
  marker convention and compared byte-for-byte against a fresh render,
  so drift is structurally impossible rather than merely reviewed at
  authoring time.
- `TestEveryExitCodeDocumented` -- every `ExitCode` member has a
  non-empty meaning, trigger condition, and remediation.
- `TestEveryConfigKeyDocumented` -- every real configuration key is
  covered by the flag mapping and named with its real default in the
  generated fragment.
- `TestFlagCoverage` -- every flag Typer actually registers (the real
  object it parses arguments with at runtime, not a hand-maintained
  mirror) is named as inline code somewhere in `cli.md`'s real text.
"""

from __future__ import annotations

import re
from pathlib import Path

from cli_doc_fixtures import (
    CLI_FLAG_BY_KEY,
    extract_generated_fragments,
    render_config_key_table,
    render_exit_code_table,
)
from typer.core import TyperGroup, TyperOption
from typer.main import get_command

from controlloop.cli import app
from controlloop.config import _KEY_SPECS
from controlloop.exit_codes import EXIT_CODE_INFO, ExitCode

_CLI_DOC_PATH = Path(__file__).resolve().parents[2] / "docs" / "reference" / "cli.md"
_CONFIG_DOC_PATH = (
    Path(__file__).resolve().parents[2] / "docs" / "reference" / "configuration.md"
)


def _cli_doc_text() -> str:
    return _CLI_DOC_PATH.read_text(encoding="utf-8")


def _flag_documented(flag: str, doc_text: str) -> bool:
    """A flag counts as documented when it opens an inline-code span in
    `doc_text` -- either alone (`` `--format` ``) or followed by more
    text within the same span, such as its choices (`` `--format
    {text,json}` ``, the shape `cli.md` actually uses for several
    flags). A bare, unquoted textual mention does not count."""

    return re.search(rf"`{re.escape(flag)}[ `]", doc_text) is not None


def _config_doc_text() -> str:
    return _CONFIG_DOC_PATH.read_text(encoding="utf-8")


class TestGeneratedFragmentsMatch:
    """Reference content is generated from the implementation, so
    drift is impossible."""

    def test_cli_doc_exit_code_fragment_matches_a_fresh_render(self) -> None:
        fragments = extract_generated_fragments(_cli_doc_text())
        assert fragments["exit-codes"] == render_exit_code_table()

    def test_configuration_doc_key_fragment_matches_a_fresh_render(self) -> None:
        fragments = extract_generated_fragments(_config_doc_text())
        assert fragments["configuration-keys"] == render_config_key_table()

    def test_both_docs_contain_exactly_one_generated_marker_each(self) -> None:
        assert set(extract_generated_fragments(_cli_doc_text())) == {"exit-codes"}
        assert set(extract_generated_fragments(_config_doc_text())) == {
            "configuration-keys"
        }


class TestEveryExitCodeDocumented:
    """Every exit code is documented with when it occurs and what
    to do about it."""

    def test_every_exit_code_member_has_an_info_entry(self) -> None:
        assert set(EXIT_CODE_INFO) == set(ExitCode)

    def test_every_info_entry_has_non_empty_fields(self) -> None:
        for code, info in EXIT_CODE_INFO.items():
            assert info.meaning.strip(), f"{code} has an empty meaning"
            assert info.when_it_occurs.strip(), f"{code} has an empty when_it_occurs"
            assert info.remediation.strip(), f"{code} has an empty remediation"

    def test_generated_table_names_every_code_and_remediation(self) -> None:
        table = render_exit_code_table()
        for code, info in EXIT_CODE_INFO.items():
            assert f"| {int(code)} |" in table
            assert info.remediation in table


class TestEveryConfigKeyDocumented:
    """Every configuration key is documented with its default and
    precedence."""

    def test_flag_mapping_covers_exactly_the_real_key_registry(self) -> None:
        assert set(CLI_FLAG_BY_KEY) == set(_KEY_SPECS)

    def test_generated_table_names_every_key_and_its_real_default(self) -> None:
        """Every key appears, and so does its real default -- rendered the
        way a user would write it in `controlloop.toml`, which is not
        always the way Python spells it.

        Two deliberate renderings: a boolean shows as `true`/`false`,
        because `team_enabled = False` is not valid TOML; and an
        empty-string default shows as `(none)`, because an empty pair of
        backticks in a table cell reads as a rendering bug rather than as
        "unset".
        """

        table = render_config_key_table()
        for key, spec in _KEY_SPECS.items():
            assert f"`{key}`" in table
            if isinstance(spec.default, tuple):
                continue
            if isinstance(spec.default, bool):
                assert f"`{str(spec.default).lower()}`" in table
            elif spec.default == "":
                assert "(none)" in table
            else:
                assert f"`{spec.default}`" in table

    def test_precedence_order_is_documented_once_for_every_key(self) -> None:
        """ "Precedence" is the shared four-tier order documented once in
        prose above the table, by design -- this asserts that shared
        explanation exists and names all four tiers, rather than requiring
        a per-key repeat."""

        text = _config_doc_text()
        assert "Default" in text
        assert "Repository file" in text
        assert "Environment" in text
        assert "Flag" in text


class TestFlagCoverage:
    """A flag added without documentation fails CI."""

    def test_every_registered_flag_is_named_in_the_cli_reference(self) -> None:
        click_app = get_command(app)
        assert isinstance(click_app, TyperGroup)
        doc_text = _cli_doc_text()

        missing: list[str] = []
        for param in click_app.params:
            if not isinstance(param, TyperOption):
                continue
            for opt in param.opts:
                if not _flag_documented(opt, doc_text):
                    missing.append(f"(top-level) {opt}")

        for command_name, command in click_app.commands.items():
            for param in command.params:
                if not isinstance(param, TyperOption):
                    continue
                for opt in param.opts:
                    if not _flag_documented(opt, doc_text):
                        missing.append(f"{command_name}: {opt}")

        assert missing == [], f"flag(s) not documented in cli.md: {missing}"

    def test_every_registered_command_is_named_in_the_cli_reference(self) -> None:
        click_app = get_command(app)
        assert isinstance(click_app, TyperGroup)
        doc_text = _cli_doc_text()

        for command_name in click_app.commands:
            assert f"`{command_name}`" in doc_text, (
                f"command {command_name!r} is registered but not named in cli.md"
            )

    def test_detects_a_deliberately_undocumented_flag(self) -> None:
        """Proves `_flag_documented` itself would actually fail on real
        drift -- constructed independently of the real doc, so this test
        cannot itself go stale alongside the page (mirrors
        `tests/test_fixture_corpus_doc.py`'s own
        `test_detects_a_deliberately_nonexistent_cited_path`)."""

        doc_text = "no flags mentioned here"
        assert _flag_documented("--totally-new-flag", doc_text) is False

    def test_flag_documented_accepts_both_bare_and_choice_annotated_forms(
        self,
    ) -> None:
        assert _flag_documented("--format", "documented as `--format`.") is True
        assert (
            _flag_documented("--format", "documented as `--format {text,json}`.")
            is True
        )
        assert _flag_documented("--format", "mentions --format unquoted.") is False
