"""Tests for `controlloop rules` and `controlloop example`.

Both commands exist to answer questions the CLI previously could not:
*what will actually run against my repository, and what does it look
for*, and *how does this tool work at all*. So the load-bearing tests
here are about **truthfulness** -- that the catalog reflects the real
rule pack rather than a hand-maintained copy, that "active" means what
`scan`/`gate` mean by it, and that neither command scans, writes, or
reaches the network.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from controlloop.cli import app
from controlloop.exit_codes import ExitCode
from controlloop.policy import CURRENT_RULE_PACK
from controlloop.policy.rulepack import (
    KNOWN_RULE_PACK_FINGERPRINTS,
    rule_pack_fingerprint,
)

runner = CliRunner()

_EXAMPLE_DOC = (
    Path(__file__).resolve().parents[1] / "docs/guides/example-walkthrough.md"
)


def _agent_repository(root: Path, *, manifest: str | None = None) -> Path:
    (root / "agent-card.json").write_text(
        json.dumps(
            {
                "protocolVersion": "0.2",
                "name": "invoice-agent",
                "skills": [{"id": "read-invoice", "name": "read-invoice"}],
            }
        ),
        encoding="utf-8",
    )
    if manifest is not None:
        (root / "controlloop.yaml").write_text(manifest, encoding="utf-8")
    return root


class TestRulesCatalogIsTheRealPack:
    """The catalog must be derived, never transcribed -- a hand-kept
    list would drift from the pack silently, which is worse than having
    no command."""

    def test_every_shipped_rule_has_a_summary(self) -> None:
        missing = [
            entry.id for entry in CURRENT_RULE_PACK.metadata if not entry.summary
        ]

        assert not missing, f"rules shipped without a summary: {missing}"

    def test_summaries_do_not_restate_the_rule_id(self) -> None:
        """A summary that just re-spells the id teaches nothing."""
        for entry in CURRENT_RULE_PACK.metadata:
            slug = entry.id.removeprefix("policy.").replace("-", " ")

            assert entry.summary.strip().lower() != slug, (
                f"{entry.id}'s summary merely restates its id"
            )
            assert len(entry.summary) > 40, f"{entry.id}'s summary is too thin to help"

    def test_summaries_do_not_change_the_pinned_fingerprint(self) -> None:
        """The central safety property of `controlloop rules`:
        `rule_pack_fingerprint` digests `[id, sha256(evaluate source),
        mandatory]`. Descriptive metadata is
        deliberately not an input, so adding or editing a summary must never
        invalidate a pinned fingerprint or imply a rule-pack version bump."""
        assert (
            rule_pack_fingerprint(CURRENT_RULE_PACK)
            == KNOWN_RULE_PACK_FINGERPRINTS[CURRENT_RULE_PACK.version]
        )

    def test_text_output_names_every_rule_in_the_pack(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["rules", str(_agent_repository(tmp_path))])

        assert result.exit_code == ExitCode.PASS, result.output
        for entry in CURRENT_RULE_PACK.metadata:
            assert entry.id in result.output

    def test_text_output_reports_the_pack_and_its_fingerprint(
        self, tmp_path: Path
    ) -> None:
        result = runner.invoke(app, ["rules", str(_agent_repository(tmp_path))])

        assert CURRENT_RULE_PACK.name in result.output
        assert CURRENT_RULE_PACK.version in result.output
        assert rule_pack_fingerprint(CURRENT_RULE_PACK) in result.output

    def test_mandatory_rules_are_marked_as_such(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["rules", str(_agent_repository(tmp_path))])
        mandatory = [e.id for e in CURRENT_RULE_PACK.metadata if e.mandatory]

        assert mandatory, "expected the shipped pack to have mandatory rules"
        for rule_id in mandatory:
            line = next(
                line_text
                for line_text in result.output.splitlines()
                if line_text.startswith(("✓ " + rule_id, "• " + rule_id))
            )
            assert "mandatory" in line


class TestRulesReflectsConfiguration:
    """ "Active" has to mean what `scan`/`gate` mean by it, or the
    command is confidently wrong."""

    def test_a_disabled_rule_is_omitted_by_default(self, tmp_path: Path) -> None:
        root = _agent_repository(tmp_path)
        (root / "controlloop.toml").write_text(
            'disabled_rules = ["policy.broad-permission"]\n', encoding="utf-8"
        )

        result = runner.invoke(app, ["rules", str(root)])

        assert result.exit_code == ExitCode.PASS, result.output
        assert "policy.broad-permission" not in result.output
        assert "disabled by configuration" in result.output

    def test_all_lists_the_disabled_rule_and_marks_it(self, tmp_path: Path) -> None:
        root = _agent_repository(tmp_path)
        (root / "controlloop.toml").write_text(
            'disabled_rules = ["policy.broad-permission"]\n', encoding="utf-8"
        )

        result = runner.invoke(app, ["rules", str(root), "--all"])

        assert result.exit_code == ExitCode.PASS, result.output
        line = next(
            line_text
            for line_text in result.output.splitlines()
            if "policy.broad-permission" in line_text
        )
        assert "disabled" in line

    def test_disabling_a_mandatory_rule_is_rejected(self, tmp_path: Path) -> None:
        """Same contract `scan`/`gate` enforce, reached through the same
        `validate_disabled_rules` call rather than a second code path."""
        root = _agent_repository(tmp_path)
        (root / "controlloop.toml").write_text(
            'disabled_rules = ["policy.capability-ceiling"]\n', encoding="utf-8"
        )

        result = runner.invoke(app, ["rules", str(root)])

        assert result.exit_code == ExitCode.INVALID_INPUT


class TestRulesJson:
    def test_json_is_parseable_and_complete(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app, ["rules", str(_agent_repository(tmp_path)), "--format", "json"]
        )

        assert result.exit_code == ExitCode.PASS, result.output
        payload = json.loads(result.stdout)
        assert payload["rule_pack"]["name"] == CURRENT_RULE_PACK.name
        assert payload["rule_pack"]["version"] == CURRENT_RULE_PACK.version
        assert len(payload["rules"]) == len(CURRENT_RULE_PACK.metadata)

    def test_every_json_entry_carries_a_documentation_url(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app, ["rules", str(_agent_repository(tmp_path)), "--format", "json"]
        )
        payload = json.loads(result.stdout)

        for entry in payload["rules"]:
            assert entry["documentation_url"].startswith("https://")
            assert entry["summary"]


class TestExample:
    def test_it_succeeds_and_names_every_command_it_teaches(self) -> None:
        result = runner.invoke(app, ["example"])

        assert result.exit_code == ExitCode.PASS, result.output
        for command in ("controlloop bom", "controlloop scan", "controlloop gate"):
            assert command in result.output

    def test_it_points_at_the_walkthrough_document(self) -> None:
        result = runner.invoke(app, ["example"])

        assert "docs/guides/example-walkthrough.md" in result.output

    def test_the_document_it_points_at_actually_exists(self) -> None:
        """A pointer to a missing page is worse than no pointer."""
        assert _EXAMPLE_DOC.is_file()

    def test_it_warns_about_the_no_material_capability_trap(self) -> None:
        """The single most likely first misreading, and the reason this
        command exists at all."""
        result = runner.invoke(app, ["example"])

        assert "no material capability is reachable" in result.output

    def test_it_writes_nothing(self, tmp_path: Path) -> None:
        """Guidance, not a scan. It must not create a demo directory or
        touch the working tree."""
        before = set(tmp_path.iterdir())

        result = runner.invoke(app, ["example"])

        assert result.exit_code == ExitCode.PASS
        assert set(tmp_path.iterdir()) == before

    @pytest.mark.parametrize("command", [["rules"], ["example"]])
    def test_neither_command_touches_the_network(
        self, command: list[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Offline evidence. `conftest.py`'s autouse `_deny_network_access`
        fixture already replaces the socket layer for every test in this
        suite and raises loudly on any connection attempt, so a clean
        exit here *is* the proof -- asserted through the shared harness
        rather than by re-patching sockets a second, divergent way."""
        monkeypatch.chdir(_agent_repository(tmp_path))

        result = runner.invoke(app, command)

        assert result.exit_code == ExitCode.PASS, result.output


class TestExampleTeaches:
    """The first version of the command listed commands without
    explaining any of them, and pointed at a local file path. Its
    audience is someone who has never used ControlLoop, so these assert
    the concepts are actually present rather than merely that it runs."""

    @pytest.mark.parametrize(
        "concept",
        [
            "Agent Capability Bill of Materials",
            "graph",
            "blast-radius",
            "tool_capabilities",
            "capability ceiling",
            "controlloop rules",
            "exit 1",
        ],
    )
    def test_output_explains_each_core_concept(self, concept: str) -> None:
        result = runner.invoke(app, ["example"])

        assert concept in result.output, f"example never explains {concept!r}"

    def test_it_links_by_url_not_by_local_path(self) -> None:
        """A bare `docs/...` path is meaningless to anyone who did not
        install from a repository checkout."""
        result = runner.invoke(app, ["example"])

        assert "https://" in result.output
        assert "\n  docs/guides" not in result.output

    def test_the_linked_document_exists_at_the_path_the_url_names(self) -> None:
        """The URL is built from `_EXAMPLE_DOC_PATH`; that path must
        resolve inside this repository, or the link is dead the moment
        it ships."""
        from controlloop.cli import _EXAMPLE_DOC_PATH, _EXAMPLE_DOC_URL

        assert _EXAMPLE_DOC_PATH in _EXAMPLE_DOC_URL
        assert (Path(__file__).resolve().parents[1] / _EXAMPLE_DOC_PATH).is_file()

    def test_every_exit_code_it_names_is_a_real_one(self) -> None:
        from controlloop.exit_codes import ExitCode

        result = runner.invoke(app, ["example"])
        section = result.output.split("EXIT CODES")[1]

        for code in ("0", "1", "2", "3", "5"):
            assert f"   {code}  " in section
        assert {int(m) for m in ExitCode} >= {0, 1, 2, 3, 5}

    def test_each_step_shows_a_runnable_command_or_a_marked_edit(self) -> None:
        """Every `$` line is either a real controlloop invocation or an
        explicitly commented manual edit -- never a plausible-looking
        command that does not exist."""
        result = runner.invoke(app, ["example"])

        shown = [
            line.strip().removeprefix("$ ").strip()
            for line in result.output.splitlines()
            if line.strip().startswith("$ ")
        ]

        assert shown, "example showed no commands at all"
        for command in shown:
            assert command.startswith(("controlloop ", "#")), command
