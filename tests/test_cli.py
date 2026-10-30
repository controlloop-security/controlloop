"""Smoke tests for the ControlLoop command."""

import hashlib
import inspect
import json
import runpy
import subprocess
from importlib.metadata import PackageNotFoundError
from pathlib import Path
from unittest.mock import Mock

import pytest
from pytest import MonkeyPatch
from typer.testing import CliRunner

import controlloop
from controlloop import __version__
from controlloop import cli as cli_module
from controlloop.acbom import ACBOMDocument
from controlloop.acbom.versioning import CURRENT_SCHEMA_URL, CURRENT_SCHEMA_VERSION
from controlloop.adapters import SUPPORTED_OASF_VERSIONS
from controlloop.baseline import CONVENTIONAL_BASELINE_RELATIVE_PATH
from controlloop.cli import app
from controlloop.config import CONFIG_FILENAME
from controlloop.diff import BaselineOrigin, ComparisonScope, DiffReport
from controlloop.exit_codes import ExitCode
from controlloop.manifest import load_manifest
from controlloop.output import NonInteractiveEnvironmentError
from controlloop.policy.rulepack import CURRENT_RULE_PACK
from controlloop.reporting import EvidenceArtifact

_CLI_ROOT = Path(__file__).resolve().parent
_MINIMAL_BASELINE_FIXTURE = _CLI_ROOT / "fixtures/baseline/minimal-baseline.json"

runner = CliRunner()


def test_help_lists_product_purpose() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "Inspect and gate AI agent capabilities." in result.stdout


def test_version_is_machine_stable() -> None:
    """Four stable lines: the CLI's own version, the declared,
    possibly-empty set of supported OASF versions (declared in one place,
    reported by --version), the documentation date each agent host adapter's
    key set is pinned to, and the bundled rule pack's own name, version, and
    rule count."""
    result = runner.invoke(app, ["--version"])

    supported = (
        ", ".join(SUPPORTED_OASF_VERSIONS) if SUPPORTED_OASF_VERSIONS else "none yet"
    )
    assert result.exit_code == 0
    assert result.stdout == (
        f"ControlLoop {__version__}\n"
        f"Supported OASF versions: {supported}\n"
        "Agent host key sets (documentation read on): claude-code 2026-10-17, "
        "codex 2026-10-17, cursor 2026-10-17, gemini-cli 2026-10-17, "
        "kiro 2026-10-17, roo-code 2026-10-29\n"
        f"Rule pack: {CURRENT_RULE_PACK.name} {CURRENT_RULE_PACK.version} "
        f"({len(CURRENT_RULE_PACK.rules)} rules)\n"
    )
    assert result.stderr == ""


def test_version_reports_the_real_populated_rule_pack() -> None:
    """A direct, hardcoded assertion -- not merely one derived from
    `CURRENT_RULE_PACK` itself, which would pass trivially even if
    `CURRENT_RULE_PACK` regressed back to zero rules, a bug this once had.
    Pins the actual reported line to the real 23-rule, `0.8.0`
    state."""
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert "Rule pack: controlloop-community 0.8.0 (23 rules)\n" in result.stdout
    assert CURRENT_RULE_PACK.version == "0.8.0"
    assert len(CURRENT_RULE_PACK.rules) == 23
    assert len(CURRENT_RULE_PACK.metadata) == 23


def test_uninstalled_source_tree_has_safe_version(monkeypatch: MonkeyPatch) -> None:
    def missing_distribution(_: str) -> str:
        raise PackageNotFoundError

    monkeypatch.setattr(controlloop, "version", missing_distribution)

    assert controlloop._distribution_version() == "0.0.0+uninstalled"


def test_main_invokes_typer_app(monkeypatch: MonkeyPatch) -> None:
    app_mock = Mock()
    monkeypatch.setattr(cli_module, "app", app_mock)

    cli_module.main()

    app_mock.assert_called_once_with()


def test_main_fails_closed_on_noninteractive_environment_error(
    monkeypatch: MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A command that raises NonInteractiveEnvironmentError (because stdout
    is not a terminal) must exit with the documented invalid-input code and
    write its diagnostic to stderr only, never stdout, and never as an
    uncaught traceback."""

    def raising_app() -> None:
        raise NonInteractiveEnvironmentError("stdout is not a terminal")

    monkeypatch.setattr(cli_module, "app", raising_app)

    with pytest.raises(SystemExit) as excinfo:
        cli_module.main()

    assert excinfo.value.code == ExitCode.INVALID_INPUT

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "stdout is not a terminal" in captured.err


def test_python_module_entry_invokes_main(monkeypatch: MonkeyPatch) -> None:
    main_mock = Mock()
    monkeypatch.setattr(cli_module, "main", main_mock)

    runpy.run_module("controlloop", run_name="__main__")

    main_mock.assert_called_once_with()


def test_help_lists_all_five_subcommands_with_descriptions() -> None:
    """`--help` names every subcommand with its one-line description."""
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "init" in result.stdout
    assert "Discover candidate agents and draft a reviewable security manifest." in (
        result.stdout
    )
    assert "bom" in result.stdout
    assert "Generate or validate an Agent Capability Bill of Materials." in (
        result.stdout
    )
    assert "diff" in result.stdout
    assert "Compare two ACBOMs, or the repository against a baseline." in (
        result.stdout
    )
    assert "scan" in result.stdout
    assert "Discover, build the ACBOM, evaluate policy, and report results." in (
        result.stdout
    )
    assert "gate" in result.stdout
    assert "Evaluate policy noninteractively" in result.stdout


def test_deliberate_exit_code_survives_main_exception_handler(
    monkeypatch: MonkeyPatch,
) -> None:
    """A command's own deliberate `typer.Exit` must not be caught as an
    internal error by `main()`'s generic `except Exception` handler.

    Formerly exercised via the `gate` stub (`_not_implemented`), the last
    stub command in this codebase; `gate` is real now, so this uses
    `bom --validate` against a nonexistent path instead -- a different,
    durable, already-real command that also raises its own `typer.Exit`
    deliberately (`ExitCode.INVALID_INPUT`), proving the identical `main()`
    mechanism.
    """
    monkeypatch.setattr(
        "sys.argv", ["controlloop", "bom", "/no/such/acbom.json", "--validate"]
    )

    with pytest.raises(SystemExit) as excinfo:
        cli_module.main()

    assert excinfo.value.code == ExitCode.INVALID_INPUT


def test_unknown_subcommand_exits_invalid_input() -> None:
    """An unknown subcommand exits with the invalid-input code."""
    result = runner.invoke(app, ["nosuchcommand"])

    assert result.exit_code == ExitCode.INVALID_INPUT


def test_malformed_flag_exits_invalid_input() -> None:
    """A malformed flag exits with the invalid-input code."""
    result = runner.invoke(app, ["--no-such-flag"])

    assert result.exit_code == ExitCode.INVALID_INPUT


def test_unhandled_exception_exits_internal_error_with_stable_envelope(
    monkeypatch: MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """An unhandled exception exits with a stable, minimal envelope.

    A raw exception message can carry arbitrary interpolated content (a
    path, a value), so the envelope must never include it -- only the
    exception's class name, and never a traceback.
    """
    secret_shaped_value = "/Users/example/private-repo-path"
    app_mock = Mock(side_effect=ValueError(f"kaboom with {secret_shaped_value}"))
    monkeypatch.setattr(cli_module, "app", app_mock)

    with pytest.raises(SystemExit) as excinfo:
        cli_module.main()

    assert excinfo.value.code == ExitCode.INTERNAL_ERROR
    captured = capsys.readouterr()
    assert "INTERNAL ERROR" in captured.err
    assert "ValueError" in captured.err
    assert secret_shaped_value not in captured.err
    assert secret_shaped_value not in captured.out
    assert "Traceback" not in captured.err
    assert "Traceback" not in captured.out


class TestShowConfig:
    """`--show-config` integration tests through the real Typer entry point.
    Each test that cares about the repository configuration file
    `monkeypatch.chdir`s into an isolated `tmp_path` with no enclosing
    `.git`, so `resolve_repository_root` falls back to that directory rather
    than finding this checkout's own root."""

    def test_default_output_lists_all_four_keys_as_default(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["--show-config"])

        assert result.exit_code == 0
        assert result.stderr == ""
        for key in (
            "max_file_size_bytes",
            "max_total_bytes",
            "max_file_count",
            "max_depth",
        ):
            assert f"{key} = " in result.stdout
            assert "(default)" in result.stdout
        assert "max_depth = 100  (default)" in result.stdout

    def test_repository_file_changes_reported_source_and_value(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / CONFIG_FILENAME).write_text("max_depth = 33\n")

        result = runner.invoke(app, ["--show-config"])

        assert result.exit_code == 0
        assert "max_depth = 33  (repository file)" in result.stdout

    def test_environment_overrides_repository_file(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / CONFIG_FILENAME).write_text("max_depth = 33\n")
        monkeypatch.setenv("CONTROLLOOP_MAX_DEPTH", "77")

        result = runner.invoke(app, ["--show-config"])

        assert result.exit_code == 0
        assert "max_depth = 77  (environment)" in result.stdout

    def test_flag_overrides_environment_and_repository_file(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / CONFIG_FILENAME).write_text("max_depth = 33\n")
        monkeypatch.setenv("CONTROLLOOP_MAX_DEPTH", "77")

        result = runner.invoke(app, ["--max-depth", "9", "--show-config"])

        assert result.exit_code == 0
        assert "max_depth = 9  (flag)" in result.stdout

    def test_unknown_repository_key_exits_invalid_input(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / CONFIG_FILENAME).write_text("bogus_key = 1\n")

        result = runner.invoke(app, ["--show-config"])

        assert result.exit_code == ExitCode.INVALID_INPUT
        assert "INVALID CONFIG" in result.stderr
        assert "bogus_key" in result.stderr
        assert result.stdout == ""

    def test_malformed_repository_file_exits_invalid_input_without_content(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        secret_shaped_value = "ghp_" + "a" * 36
        (tmp_path / CONFIG_FILENAME).write_text(
            f"max_depth = [1,2\nfoo = {secret_shaped_value}"
        )

        result = runner.invoke(app, ["--show-config"])

        assert result.exit_code == ExitCode.INVALID_INPUT
        assert "INVALID CONFIG" in result.stderr
        assert "line" in result.stderr
        assert secret_shaped_value not in result.stderr
        assert secret_shaped_value not in result.stdout
        assert result.stdout == ""

    def test_show_config_runs_offline_and_deterministically(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """`--show-config` reads at most one local file and never touches
        the network (covered by the autouse offline harness in
        `conftest.py`), and repeated invocations over the same inputs
        produce byte-identical output."""
        monkeypatch.chdir(tmp_path)

        first = runner.invoke(app, ["--show-config"])
        second = runner.invoke(app, ["--show-config"])

        assert first.exit_code == 0
        assert first.stdout == second.stdout


class TestVerbosity:
    """`--log-level`/`--log-format` integration tests through the real Typer
    entry point. Each test that resolves a repository root
    `monkeypatch.chdir`s into an isolated `tmp_path`, matching
    `TestShowConfig`'s and `TestBom`'s isolation pattern."""

    @pytest.mark.parametrize("level", ["quiet", "default"])
    def test_show_config_emits_no_operator_log_lines_below_verbose(
        self, monkeypatch: MonkeyPatch, tmp_path: Path, level: str
    ) -> None:
        """Quiet and default are both selectable; today they are observably
        identical since no default-level optional diagnostic exists yet for
        quiet to suppress (a known limitation, stated here rather than
        silently implied otherwise)."""
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["--log-level", level, "--show-config"])

        assert result.exit_code == 0
        assert result.stderr == ""

    def test_show_config_verbose_flag_adds_one_operator_line(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """Verbose is selectable by flag."""
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["--log-level", "verbose", "--show-config"])

        assert result.exit_code == 0
        assert "VERBOSE" in result.stderr
        assert "DEBUG" not in result.stderr

    def test_show_config_debug_flag_adds_verbose_and_debug_lines(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """Debug is selectable by flag."""
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["--log-level", "debug", "--show-config"])

        assert result.exit_code == 0
        assert "VERBOSE" in result.stderr
        assert "DEBUG" in result.stderr

    def test_environment_variable_selects_level(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """Also selectable via CONTROLLOOP_LOG_LEVEL."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("CONTROLLOOP_LOG_LEVEL", "debug")

        result = runner.invoke(app, ["--show-config"])

        assert result.exit_code == 0
        assert "DEBUG" in result.stderr

    def test_flag_overrides_environment(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("CONTROLLOOP_LOG_LEVEL", "quiet")

        result = runner.invoke(app, ["--log-level", "debug", "--show-config"])

        assert result.exit_code == 0
        assert "DEBUG" in result.stderr

    def test_invalid_log_level_flag_exits_invalid_input(self) -> None:
        """Negative case: Typer/Click's own enum-choice validation rejects
        an unrecognized --log-level value before it ever reaches
        controlloop.verbosity."""
        result = runner.invoke(app, ["--log-level", "loud", "--show-config"])

        assert result.exit_code == ExitCode.INVALID_INPUT

    def test_malformed_log_level_environment_value_exits_invalid_input(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """Malformed case: an unrecognized CONTROLLOOP_LOG_LEVEL is a hard
        error, never silently ignored or defaulted."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("CONTROLLOOP_LOG_LEVEL", "loud")

        result = runner.invoke(app, ["--show-config"])

        assert result.exit_code == ExitCode.INVALID_INPUT
        assert "INVALID INPUT" in result.stderr
        assert result.stdout == ""

    def test_malformed_log_format_environment_value_exits_invalid_input(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("CONTROLLOOP_LOG_FORMAT", "xml")

        result = runner.invoke(app, ["--show-config"])

        assert result.exit_code == ExitCode.INVALID_INPUT
        assert "INVALID INPUT" in result.stderr

    def test_show_config_output_is_identical_across_every_verbosity_level(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """Verbosity never alters findings, gate result, or exit code --
        demonstrated against `--show-config`'s deterministic output, since
        `scan`/`gate` are not implemented yet. Stderr line counts must also
        be monotonically non-decreasing with level."""
        monkeypatch.chdir(tmp_path)

        results = {
            level: runner.invoke(app, ["--log-level", level, "--show-config"])
            for level in ("quiet", "default", "verbose", "debug")
        }

        stdouts = {level: result.stdout for level, result in results.items()}
        assert len(set(stdouts.values())) == 1
        for result in results.values():
            assert result.exit_code == 0
        stderr_line_counts = {
            level: len([line for line in result.stderr.splitlines() if line])
            for level, result in results.items()
        }
        assert stderr_line_counts["quiet"] == 0
        assert stderr_line_counts["default"] == 0
        assert stderr_line_counts["verbose"] == 1
        assert stderr_line_counts["debug"] == 2

    def test_bom_output_is_identical_across_every_verbosity_level(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """The same guarantee against a second, independent deterministic
        command: the generated ACBOM document's digest and the exit code
        never change with verbosity."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "file.txt").write_text("hello\n")

        results = {
            level: runner.invoke(app, ["--log-level", level, "bom"])
            for level in ("quiet", "default", "verbose", "debug")
        }

        digests = {
            level: ACBOMDocument.model_validate_json(result.stdout).digest
            for level, result in results.items()
        }
        assert len(set(digests.values())) == 1
        for result in results.values():
            assert result.exit_code == 0

    def test_debug_log_line_redacts_a_secret_shaped_repository_path(
        self,
        monkeypatch: MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Privacy canary: the debug line interpolates the resolved
        repository root path. Plant a credential-shaped substring in the
        directory name itself (the same `_SECRET_SHAPED_CANARY` shape used
        elsewhere in this suite) and assert it never reaches stdout or
        stderr raw, only the redaction boundary's stable placeholder.

        Exercised through `cli_module.main()`, not
        `CliRunner.invoke(app, ...)`: the redaction boundary is installed
        by `main()`'s `with redaction.redirected_streams():` block, not
        by the Typer app object itself, so a `CliRunner`-based test never
        exercises it -- only a real invocation of `main()` (what the
        installed `controlloop` entry point actually calls) does.
        """
        secret_shaped_value = "ghp_" + "b" * 36
        repo_dir = tmp_path / f"repo-{secret_shaped_value}"
        repo_dir.mkdir()
        monkeypatch.chdir(repo_dir)
        monkeypatch.setattr(
            "sys.argv", ["controlloop", "--log-level", "debug", "--show-config"]
        )

        with pytest.raises(SystemExit) as excinfo:
            cli_module.main()

        assert excinfo.value.code == 0
        captured = capsys.readouterr()
        assert secret_shaped_value not in captured.err
        assert secret_shaped_value not in captured.out
        assert "controlloop:redacted:sha256:" in captured.err

    def test_log_format_json_produces_parseable_structured_lines(
        self,
        monkeypatch: MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Logs are structured (JSON Lines) when a machine format is
        selected, and stay on stderr only -- stdout still parses as exactly
        one ACBOM document. Exercised through `cli_module.main()` for the
        same reason as the canary test above."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "file.txt").write_text("hello\n")
        monkeypatch.setattr(
            "sys.argv",
            ["controlloop", "--log-level", "debug", "--log-format", "json", "bom"],
        )

        with pytest.raises(SystemExit) as excinfo:
            cli_module.main()

        assert excinfo.value.code == 0
        captured = capsys.readouterr()
        lines = [line for line in captured.err.splitlines() if line]
        assert len(lines) == 2
        for line in lines:
            payload = json.loads(line)
            assert set(payload) == {"level", "message"}
            assert payload["level"] in {"verbose", "debug"}
        ACBOMDocument.model_validate_json(captured.out)


def _init_repo(path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)


class TestBom:
    """`controlloop bom` integration tests through the real Typer entry
    point. Each test that resolves a repository root `monkeypatch.chdir`s
    into an isolated `tmp_path`, matching `TestShowConfig`'s isolation
    pattern, so a real ancestor `.git` in the developer's or CI's own
    checkout is never picked up by accident."""

    def test_generate_writes_a_valid_acbom_to_stdout(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """Stdout carries exactly one canonical ACBOM document and nothing
        else."""
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["bom"])

        assert result.exit_code == 0
        document = ACBOMDocument.model_validate_json(result.stdout)
        assert document.schema_version == CURRENT_SCHEMA_VERSION
        assert document.schema_url == CURRENT_SCHEMA_URL
        assert document.repository.commit == "unknown"

    def test_generate_writes_to_an_output_file(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """`--output` writes the same canonical document to a file instead
        of stdout, and stdout stays empty."""
        monkeypatch.chdir(tmp_path)
        destination = tmp_path / "acbom.json"

        result = runner.invoke(app, ["bom", "--output", str(destination)])

        assert result.exit_code == 0
        assert result.stdout == ""
        document = ACBOMDocument.model_validate_json(destination.read_bytes())
        assert document.schema_version == CURRENT_SCHEMA_VERSION

    def test_generate_output_write_failure_exits_invalid_input(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """`--output` naming an unwritable destination (here, an existing
        directory) is reported as invalid input, never an internal error."""
        monkeypatch.chdir(tmp_path)
        destination = tmp_path / "a-directory"
        destination.mkdir()

        result = runner.invoke(app, ["bom", "--output", str(destination)])

        assert result.exit_code == ExitCode.INVALID_INPUT
        assert "could not be written" in result.stderr

    def test_generate_requires_no_policy_configuration(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """Generation succeeds with zero configuration of any kind -- no
        `controlloop.toml`, no rule pack, nothing beyond a readable
        directory."""
        monkeypatch.chdir(tmp_path)
        assert list(tmp_path.iterdir()) == []

        result = runner.invoke(app, ["bom"])

        assert result.exit_code == 0

    def test_generate_finds_a_real_git_commit(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        _init_repo(tmp_path)
        (tmp_path / "file.txt").write_text("hello\n")
        subprocess.run(["git", "add", "file.txt"], cwd=tmp_path, check=True)
        subprocess.run(
            [
                "git",
                "-c",
                "user.email=t@t.com",
                "-c",
                "user.name=t",
                "commit",
                "-q",
                "-m",
                "x",
            ],
            cwd=tmp_path,
            check=True,
        )
        expected_commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=tmp_path,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

        result = runner.invoke(app, ["bom"])

        document = ACBOMDocument.model_validate_json(result.stdout)
        assert document.repository.commit == expected_commit

    def test_generate_is_deterministic_across_repeated_invocations(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """Deterministic, and runs offline (covered by the autouse harness
        in `conftest.py`, which denies all socket access for the whole
        suite)."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "file.txt").write_text("hello\n")

        first = runner.invoke(app, ["bom"])
        second = runner.invoke(app, ["bom"])

        assert first.exit_code == 0
        assert first.stdout == second.stdout

    def test_generate_reports_no_completeness_diagnostics_when_none_exist(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """An empty scan has nothing incomplete to report, and the
        completeness line is omitted entirely rather than printed empty."""
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["bom"])

        assert result.exit_code == 0
        assert "COMPLETENESS" not in result.stderr

    def test_generate_reports_a_completeness_summary_on_stderr(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """When the scan is incomplete, a summary reaches stderr, never
        stdout, so stdout keeps parsing as a single JSON document."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".mcp.json").write_text(
            '{"mcpServers": {"broken": {"command": 123}}}'
        )

        result = runner.invoke(app, ["bom"])

        assert result.exit_code == 0
        document = ACBOMDocument.model_validate_json(result.stdout)
        assert any(diagnostic.incomplete for diagnostic in document.diagnostics)
        assert "COMPLETENESS" in result.stderr

    def test_nonexistent_repository_path_exits_invalid_input(self) -> None:
        result = runner.invoke(app, ["bom", str(Path("/no/such/repository/path"))])

        assert result.exit_code == ExitCode.INVALID_INPUT
        assert "INVALID INPUT" in result.stderr
        assert result.stdout == ""

    def test_validate_accepts_a_valid_acbom(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """Exit 0 for a valid ACBOM."""
        monkeypatch.chdir(tmp_path)
        generated = runner.invoke(app, ["bom"])
        acbom_path = tmp_path / "acbom.json"
        acbom_path.write_text(generated.stdout)

        result = runner.invoke(app, ["bom", "--validate", str(acbom_path)])

        assert result.exit_code == ExitCode.PASS
        assert "VALID" in result.stdout

    def test_validate_rejects_a_malformed_acbom(self, tmp_path: Path) -> None:
        """Exit 2 for an invalid ACBOM."""
        bad_path = tmp_path / "bad.json"
        bad_path.write_text('{"not": "an acbom"}')

        result = runner.invoke(app, ["bom", "--validate", str(bad_path)])

        assert result.exit_code == ExitCode.INVALID_INPUT
        assert "INVALID ACBOM" in result.stderr
        assert result.stdout == ""

    def _generated_acbom_with_an_agent(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> dict[str, object]:
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "agent-card.json").write_text(
            '{"protocolVersion": "0.2", "name": "invoice-agent",'
            ' "skills": [{"id": "read-invoice", "name": "read-invoice"}]}'
        )
        monkeypatch.chdir(repo)
        generated = runner.invoke(app, ["bom"])
        assert generated.exit_code == ExitCode.PASS
        data: dict[str, object] = json.loads(generated.stdout)
        return data

    def test_validate_rejects_an_acbom_edited_after_generation(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """The declared digest no longer matches the content: exit 2,
        never `VALID`."""
        data = self._generated_acbom_with_an_agent(monkeypatch, tmp_path)
        nodes = data["nodes"]
        assert isinstance(nodes, list)
        nodes[0]["name"] = "renamed"
        edited = tmp_path / "edited.json"
        edited.write_text(json.dumps(data))

        result = runner.invoke(app, ["bom", "--validate", str(edited)])

        assert result.exit_code == ExitCode.INVALID_INPUT
        assert "INVALID ACBOM" in result.stderr
        assert "digest does not match" in result.stderr
        assert "VALID  " not in result.stdout

    def test_validate_reports_a_schema_violation_instead_of_crashing(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """A value the schema rejects is invalid input (exit 2) reported
        on one line, never an internal error (exit 5)."""
        data = self._generated_acbom_with_an_agent(monkeypatch, tmp_path)
        nodes = data["nodes"]
        assert isinstance(nodes, list)
        nodes[0]["type"] = "banana"
        broken = tmp_path / "broken.json"
        broken.write_text(json.dumps(data))

        result = runner.invoke(app, ["bom", "--validate", str(broken)])

        assert result.exit_code == ExitCode.INVALID_INPUT
        assert "INVALID ACBOM" in result.stderr
        assert "nodes.0.type" in result.stderr
        assert "INTERNAL ERROR" not in result.stderr
        assert len(result.stderr.strip().splitlines()) == 1

    def test_validate_reports_invalid_json_instead_of_crashing(
        self, tmp_path: Path
    ) -> None:
        truncated = tmp_path / "truncated.json"
        truncated.write_text('{"schema_version": "1.2.0", "nodes": [')

        result = runner.invoke(app, ["bom", "--validate", str(truncated)])

        assert result.exit_code == ExitCode.INVALID_INPUT
        assert "not valid JSON" in result.stderr
        assert "INTERNAL ERROR" not in result.stderr

    def test_validate_without_a_path_exits_invalid_input(self) -> None:
        result = runner.invoke(app, ["bom", "--validate"])

        assert result.exit_code == ExitCode.INVALID_INPUT
        assert "INVALID INPUT" in result.stderr

    def test_validate_of_a_missing_file_exits_invalid_input(
        self, tmp_path: Path
    ) -> None:
        result = runner.invoke(
            app, ["bom", "--validate", str(tmp_path / "missing.json")]
        )

        assert result.exit_code == ExitCode.INVALID_INPUT
        assert "could not be read" in result.stderr

    def test_validate_combined_with_output_exits_invalid_input(
        self, tmp_path: Path
    ) -> None:
        result = runner.invoke(
            app,
            [
                "bom",
                "--validate",
                str(tmp_path / "acbom.json"),
                "--output",
                str(tmp_path / "out.json"),
            ],
        )

        assert result.exit_code == ExitCode.INVALID_INPUT
        assert "cannot be combined" in result.stderr

    def test_generate_honors_max_depth_override(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """The four existing traversal-bound flags reach `bom`'s own
        `walk_repository` call, not just `--show-config`."""
        monkeypatch.chdir(tmp_path)
        nested = tmp_path / "a" / "b"
        nested.mkdir(parents=True)
        (nested / "deep.json").write_text("{}")

        shallow = runner.invoke(app, ["--max-depth", "1", "bom"])
        unlimited = runner.invoke(app, ["bom"])

        assert shallow.exit_code == 0
        assert unlimited.exit_code == 0
        shallow_document = ACBOMDocument.model_validate_json(shallow.stdout)
        unlimited_document = ACBOMDocument.model_validate_json(unlimited.stdout)
        assert shallow_document.repository.root_digest != (
            unlimited_document.repository.root_digest
        )


class TestInit:
    """`controlloop init` integration tests through the real Typer entry
    point. Each test that resolves a repository root `monkeypatch.chdir`s
    into an isolated `tmp_path`, matching `TestBom`'s isolation pattern, so
    a real ancestor `.git` in the developer's or CI's own checkout is never
    picked up by accident."""

    def test_generate_writes_a_valid_manifest_file(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """A manifest is written to controlloop.yaml at the resolved
        repository root, and it passes the manifest schema validator without
        edits."""
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["init"])

        assert result.exit_code == 0
        assert result.stdout == ""
        manifest_path = tmp_path / "controlloop.yaml"
        assert manifest_path.exists()
        document = load_manifest(
            manifest_path.read_text(encoding="utf-8"), path="controlloop.yaml"
        )
        assert document.owner == "TODO-owner"

    def test_generate_requires_no_policy_configuration(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """Mirrors the same check for bom: generation succeeds with zero
        configuration of any kind -- no controlloop.toml, no rule pack,
        nothing beyond a readable directory."""
        monkeypatch.chdir(tmp_path)
        assert list(tmp_path.iterdir()) == []

        result = runner.invoke(app, ["init"])

        assert result.exit_code == 0

    def test_dry_run_prints_the_draft_without_creating_a_file(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """`--dry-run` prints the draft and creates no file."""
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["init", "--dry-run"])

        assert result.exit_code == 0
        assert not (tmp_path / "controlloop.yaml").exists()
        document = load_manifest(result.stdout, path="controlloop.yaml")
        assert document.owner == "TODO-owner"

    def test_dry_run_discovers_a_real_agent(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """A discovered candidate agent is pre-filled into trust_boundaries,
        not left as a TODO placeholder."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "agent-card.json").write_text(
            json.dumps(
                {
                    "protocolVersion": "0.3",
                    "name": "refund-agent",
                    "skills": [{"id": "issue-refund", "name": "issue-refund"}],
                }
            )
        )

        result = runner.invoke(app, ["init", "--dry-run"])

        assert result.exit_code == 0
        document = load_manifest(result.stdout, path="controlloop.yaml")
        assert document.trust_boundaries[0].agents == ("refund-agent",)
        assert "issue-refund" in result.stdout

    def test_generate_write_failure_exits_invalid_input(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """A write failure at the resolved root (here, an unwritable
        directory) is reported as invalid input, never an internal
        error -- mirrors bom's --output failure handling."""
        monkeypatch.chdir(tmp_path)
        tmp_path.chmod(0o500)
        try:
            result = runner.invoke(app, ["init"])
        finally:
            tmp_path.chmod(0o700)

        assert result.exit_code == ExitCode.INVALID_INPUT
        assert "could not be written" in result.stderr

    def test_existing_manifest_is_never_overwritten(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """Exit 2, and the existing file's bytes are unchanged."""
        monkeypatch.chdir(tmp_path)
        manifest_path = tmp_path / "controlloop.yaml"
        original_content = 'schema_version: "1.0.0"\nowner: security-team\n'
        manifest_path.write_text(original_content)

        result = runner.invoke(app, ["init"])

        assert result.exit_code == ExitCode.INVALID_INPUT
        assert "already exists" in result.stderr
        assert "controlloop.yaml" in result.stderr
        assert manifest_path.read_text() == original_content

    def test_existing_manifest_refuses_dry_run_too(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """The refusal applies identically under --dry-run: a real init
        would refuse, so the preview must not imply otherwise."""
        monkeypatch.chdir(tmp_path)
        manifest_path = tmp_path / "controlloop.yaml"
        original_content = 'schema_version: "1.0.0"\nowner: security-team\n'
        manifest_path.write_text(original_content)

        result = runner.invoke(app, ["init", "--dry-run"])

        assert result.exit_code == ExitCode.INVALID_INPUT
        assert "already exists" in result.stderr
        assert result.stdout == ""
        assert manifest_path.read_text() == original_content

    def test_nonexistent_repository_path_exits_invalid_input(self) -> None:
        result = runner.invoke(app, ["init", str(Path("/no/such/repository/path"))])

        assert result.exit_code == ExitCode.INVALID_INPUT
        assert "INVALID INPUT" in result.stderr
        assert result.stdout == ""

    def test_dry_run_is_deterministic_across_repeated_invocations(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """Determinism evidence for the wired command, and runs offline
        (covered by the autouse harness in conftest.py, which denies all
        socket access for the whole suite)."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "agent-card.json").write_text(
            json.dumps({"protocolVersion": "0.3", "name": "refund-agent"})
        )

        first = runner.invoke(app, ["init", "--dry-run"])
        second = runner.invoke(app, ["init", "--dry-run"])

        assert first.exit_code == 0
        assert first.stdout == second.stdout

    def test_generate_reports_a_completeness_summary_on_stderr(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """Mirrors bom's completeness reporting: an incomplete discovery is
        surfaced on stderr, distinct from the manifest content itself."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".mcp.json").write_text(
            '{"mcpServers": {"broken": {"command": 123}}}'
        )

        result = runner.invoke(app, ["init", "--dry-run"])

        assert result.exit_code == 0
        assert "COMPLETENESS" in result.stderr

    def test_generate_honors_max_depth_override(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """The four existing traversal-bound flags reach init's own
        build_acbom_document call, matching bom's existing wiring."""
        monkeypatch.chdir(tmp_path)
        nested = tmp_path / "a" / "b"
        nested.mkdir(parents=True)
        (nested / "deep.json").write_text("{}")

        result = runner.invoke(app, ["--max-depth", "1", "init", "--dry-run"])

        assert result.exit_code == 0


def _diff_init_repo(path: Path, *, branch: str = "main") -> None:
    subprocess.run(["git", "init", "-q", "-b", branch], cwd=path, check=True)


def _diff_commit_all(path: Path, message: str) -> None:
    subprocess.run(["git", "add", "-A"], cwd=path, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.email=t@t.com",
            "-c",
            "user.name=t",
            "commit",
            "-q",
            "-m",
            message,
        ],
        cwd=path,
        check=True,
    )


def _diff_head(path: Path) -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _diff_clone(source: Path, dest: Path, *extra_args: str) -> None:
    subprocess.run(
        ["git", "clone", "-q", *extra_args, f"file://{source}", str(dest)],
        check=True,
        capture_output=True,
    )


def _diff_checkout_new_branch(path: Path, branch: str) -> None:
    subprocess.run(["git", "checkout", "-q", "-b", branch], cwd=path, check=True)


def _diff_checkout(path: Path, ref: str) -> None:
    subprocess.run(["git", "checkout", "-q", ref], cwd=path, check=True)


def _write_conventional_baseline(root: Path, content: str) -> Path:
    target = root / CONVENTIONAL_BASELINE_RELATIVE_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return target


class TestDiff:
    """`controlloop diff` integration tests through the real Typer entry
    point. Mirrors `TestBom`/`TestInit`'s isolation style
    (`monkeypatch.chdir(tmp_path)`) and `test_merge_base.py`'s real git
    fixture helpers (`_diff_init_repo`/`_diff_commit_all`/etc. above, kept
    `_diff_`-prefixed to avoid colliding with `TestBom`'s own
    branch-agnostic `_init_repo`)."""

    def test_two_acbom_files_with_a_real_difference(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """Two ACBOM files compared directly, full scope."""
        baseline_dir = tmp_path / "baseline-repo"
        current_dir = tmp_path / "current-repo"
        baseline_dir.mkdir()
        current_dir.mkdir()
        (current_dir / ".mcp.json").write_text(
            '{"mcpServers": {"files": {"command": "npx"}}}'
        )
        monkeypatch.chdir(baseline_dir)
        baseline_result = runner.invoke(app, ["bom"])
        assert baseline_result.exit_code == 0
        baseline_file = tmp_path / "baseline.json"
        baseline_file.write_text(baseline_result.stdout)
        monkeypatch.chdir(current_dir)
        current_result = runner.invoke(app, ["bom"])
        assert current_result.exit_code == 0
        current_file = tmp_path / "current.json"
        current_file.write_text(current_result.stdout)

        result = runner.invoke(
            app, ["diff", str(baseline_file), str(current_file), "--format", "json"]
        )

        assert result.exit_code == 0
        report = DiffReport.model_validate_json(result.stdout)
        assert report.baseline_origin is BaselineOrigin.TWO_ACBOMS
        assert report.comparison_scope is ComparisonScope.FULL
        assert report.result.is_empty is False
        assert any(
            change.kind.value == "added" for change in report.result.node_changes
        )

    def test_an_acbom_edited_after_generation_is_rejected(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """`diff` refuses to compare a document whose digest no longer
        matches its content, the same check `bom --validate` applies."""
        monkeypatch.chdir(tmp_path)
        generated = runner.invoke(app, ["bom"])
        assert generated.exit_code == 0
        baseline_file = tmp_path / "baseline.json"
        baseline_file.write_text(generated.stdout)
        edited = json.loads(generated.stdout)
        edited["generator"]["version"] = "9.9.9"
        current_file = tmp_path / "current.json"
        current_file.write_text(json.dumps(edited))

        result = runner.invoke(app, ["diff", str(baseline_file), str(current_file)])

        assert result.exit_code == ExitCode.INVALID_INPUT
        assert "INVALID ACBOM" in result.stderr
        assert "digest does not match" in result.stderr

    def test_two_identical_acbom_files_produce_an_empty_diff(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """Identical input on both sides is an empty diff, exit 0."""
        monkeypatch.chdir(tmp_path)
        bom_result = runner.invoke(app, ["bom"])
        assert bom_result.exit_code == 0
        acbom_file = tmp_path / "acbom.json"
        acbom_file.write_text(bom_result.stdout)

        result = runner.invoke(
            app,
            ["diff", str(acbom_file), str(acbom_file), "--format", "json"],
        )

        assert result.exit_code == 0
        report = DiffReport.model_validate_json(result.stdout)
        assert report.result.is_empty is True

    def test_malformed_acbom_file_in_two_file_mode_exits_invalid_input(
        self, tmp_path: Path
    ) -> None:
        good = tmp_path / "good.json"
        bad = tmp_path / "bad.json"
        good.write_text("{}")
        bad.write_text("not json at all")

        result = runner.invoke(app, ["diff", str(good), str(bad)])

        assert result.exit_code == ExitCode.INVALID_INPUT
        assert "not a valid ACBOM" in result.stderr
        assert result.stdout == ""

    def test_two_positional_files_combined_with_baseline_is_rejected(
        self, tmp_path: Path
    ) -> None:
        """The two usage forms are mutually exclusive."""
        first = tmp_path / "a.json"
        second = tmp_path / "b.json"
        first.write_text("{}")
        second.write_text("{}")

        result = runner.invoke(
            app, ["diff", str(first), str(second), "--baseline", "main"]
        )

        assert result.exit_code == ExitCode.INVALID_INPUT
        assert "--baseline is not valid together with two ACBOM file" in result.stderr

    def test_repository_mode_with_committed_baseline_is_effective_authority_only(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """A `BaselineDocument` carries no nodes/edges, so this scope is a
        legitimate, expected state."""
        monkeypatch.chdir(tmp_path)
        _write_conventional_baseline(
            tmp_path, _MINIMAL_BASELINE_FIXTURE.read_text(encoding="utf-8")
        )

        result = runner.invoke(app, ["diff", "--format", "json"])

        assert result.exit_code == 0
        report = DiffReport.model_validate_json(result.stdout)
        assert report.baseline_origin is BaselineOrigin.COMMITTED_BASELINE
        assert report.comparison_scope is ComparisonScope.EFFECTIVE_AUTHORITY_ONLY
        assert report.result.node_changes == ()
        assert report.result.edge_changes == ()
        # The fixture's one effective-authority entry is absent from this
        # (empty) repository's live scan, so it is REMOVED, not silently
        # dropped.
        assert len(report.result.effective_authority_changes) == 1
        assert report.result.effective_authority_changes[0].kind.value == "removed"

    def test_repository_mode_falls_back_to_merge_base_with_no_committed_baseline(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """No committed baseline, but a resolvable merge-base -- full
        scope."""
        repo = tmp_path
        _diff_init_repo(repo)
        (repo / ".mcp.json").write_text('{"mcpServers": {"files": {"command": "npx"}}}')
        _diff_commit_all(repo, "c1")
        merge_base_commit = _diff_head(repo)
        monkeypatch.chdir(repo)

        result = runner.invoke(app, ["diff", "--format", "json"])

        assert result.exit_code == 0
        report = DiffReport.model_validate_json(result.stdout)
        assert report.baseline_origin is BaselineOrigin.MERGE_BASE
        assert report.comparison_scope is ComparisonScope.FULL
        assert merge_base_commit in report.baseline_description
        # Current scan equals the merge-base scan exactly (nothing changed
        # since the one commit), so the diff is empty.
        assert report.result.is_empty is True

    def test_repository_mode_with_no_git_history_reports_no_comparison_possible(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """No committed baseline and no git history at all reports plainly
        that no comparison is possible -- distinct from an empty diff, and
        never exit 3 (`diff` overrides `NoGitHistoryError`'s own `exit_code`
        attribute for this command)."""
        monkeypatch.chdir(tmp_path)
        assert list(tmp_path.iterdir()) == []

        result = runner.invoke(app, ["diff"])

        assert result.exit_code == ExitCode.INVALID_INPUT
        assert result.exit_code != 3
        assert "no comparison is possible" in result.stderr
        assert "zero changes" not in result.stderr.lower()
        assert result.stdout == ""

    def test_baseline_option_with_an_explicit_file_path(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """`--baseline` tried first as an existing file path."""
        monkeypatch.chdir(tmp_path)
        # Lives inside the resolved repository root but *not* at the
        # conventional `.controlloop/baseline.json` path, so it is only
        # ever found via the explicit `--baseline` value below, never
        # automatic discovery.
        explicit_baseline = tmp_path / "explicit-baseline.json"
        explicit_baseline.write_text(
            _MINIMAL_BASELINE_FIXTURE.read_text(encoding="utf-8")
        )

        result = runner.invoke(
            app, ["diff", "--baseline", str(explicit_baseline), "--format", "json"]
        )

        assert result.exit_code == 0
        report = DiffReport.model_validate_json(result.stdout)
        assert report.baseline_origin is BaselineOrigin.EXPLICIT_BASELINE_FILE
        assert report.comparison_scope is ComparisonScope.EFFECTIVE_AUTHORITY_ONLY

    def test_baseline_option_with_a_git_revision(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """A `--baseline` value that does not exist as a file is tried as a
        git revision, resolved and scanned for a full diff."""
        repo = tmp_path
        _diff_init_repo(repo)
        (repo / "a.txt").write_text("a\n")
        _diff_commit_all(repo, "c1")
        first_commit = _diff_head(repo)
        subprocess.run(["git", "tag", "v1"], cwd=repo, check=True)
        (repo / ".mcp.json").write_text('{"mcpServers": {"files": {"command": "npx"}}}')
        _diff_commit_all(repo, "c2")
        monkeypatch.chdir(repo)

        result = runner.invoke(app, ["diff", "--baseline", "v1", "--format", "json"])

        assert result.exit_code == 0
        report = DiffReport.model_validate_json(result.stdout)
        assert report.baseline_origin is BaselineOrigin.EXPLICIT_REVISION
        assert report.comparison_scope is ComparisonScope.FULL
        assert first_commit in report.baseline_description
        # The mcp.json tool was added after v1, so it shows up as ADDED.
        assert any(
            change.kind.value == "added" for change in report.result.node_changes
        )

    def test_baseline_option_neither_path_nor_revision_exits_invalid_input(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        repo = tmp_path
        _diff_init_repo(repo)
        (repo / "a.txt").write_text("a\n")
        _diff_commit_all(repo, "c1")
        monkeypatch.chdir(repo)

        result = runner.invoke(app, ["diff", "--baseline", "no-such-file-or-revision"])

        assert result.exit_code == ExitCode.INVALID_INPUT
        assert "neither an existing file path nor" in result.stderr
        assert result.stdout == ""

    def test_tampered_committed_baseline_exits_invalid_input(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """A committed baseline whose declared digest does not match its
        recomputed one is rejected outright (`BaselineIntegrityError`),
        never silently trusted or fallen back from."""
        monkeypatch.chdir(tmp_path)
        tampered = json.loads(_MINIMAL_BASELINE_FIXTURE.read_text(encoding="utf-8"))
        tampered["generator"]["version"] = "9.9.9"  # digest now stale
        _write_conventional_baseline(tmp_path, json.dumps(tampered))

        result = runner.invoke(app, ["diff"])

        assert result.exit_code == ExitCode.INVALID_INPUT
        assert "tampered" in result.stderr or "digest" in result.stderr
        assert result.stdout == ""

    def test_shallow_clone_reports_an_actionable_error(self, tmp_path: Path) -> None:
        """Mirrors `test_merge_base.py`'s own empirically verified
        shallow-clone fixture (`TestResolveMergeBase.
        test_shallow_clone_reports_shallow_as_likely_cause`): a shallow,
        multi-branch-tip clone that genuinely fails `git merge-base`,
        surfaced here as `MergeBaseResolutionError`'s already actionable
        message at exit 2, never a generic failure."""
        origin = tmp_path / "origin"
        origin.mkdir()
        _diff_init_repo(origin)
        (origin / "a.txt").write_text("a\n")
        _diff_commit_all(origin, "c1")
        _diff_checkout_new_branch(origin, "feature")
        (origin / "b.txt").write_text("b\n")
        _diff_commit_all(origin, "c2 on feature")
        (origin / "c.txt").write_text("c\n")
        _diff_commit_all(origin, "c3 on feature")
        _diff_checkout(origin, "main")

        clone = tmp_path / "clone"
        _diff_clone(
            origin, clone, "--no-single-branch", "--depth", "1", "--branch", "feature"
        )

        result = runner.invoke(app, ["diff", str(clone)])

        assert result.exit_code == ExitCode.INVALID_INPUT
        message = result.stderr.lower()
        assert "shallow clone" in message
        assert "fetch --unshallow" in message or "fetch-depth" in message
        assert result.stdout == ""

    def test_format_json_and_text_both_honor_stream_separation(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """Whichever format is selected, stdout parses as exactly that one
        clean document, and stderr never carries stdout's own payload."""
        repo = tmp_path
        _diff_init_repo(repo)
        (repo / "a.txt").write_text("a\n")
        _diff_commit_all(repo, "c1")
        monkeypatch.chdir(repo)

        json_result = runner.invoke(app, ["diff", "--format", "json"])
        assert json_result.exit_code == 0
        DiffReport.model_validate_json(json_result.stdout)
        assert "CONTROLLOOP" not in json_result.stdout

        text_result = runner.invoke(app, ["diff", "--format", "text"])
        assert text_result.exit_code == 0
        assert "CONTROLLOOP / CAPABILITY DIFF" in text_result.stdout
        with pytest.raises(json.JSONDecodeError):
            json.loads(text_result.stdout)

    def test_diff_is_deterministic_across_repeated_invocations(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """Identical input produces byte-identical `--format json` stdout
        across repeated invocations."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".mcp.json").write_text(
            '{"mcpServers": {"files": {"command": "npx"}}}'
        )
        bom_result = runner.invoke(app, ["bom"])
        assert bom_result.exit_code == 0
        acbom_file = tmp_path / "acbom.json"
        acbom_file.write_text(bom_result.stdout)

        first = runner.invoke(
            app, ["diff", str(acbom_file), str(acbom_file), "--format", "json"]
        )
        second = runner.invoke(
            app, ["diff", str(acbom_file), str(acbom_file), "--format", "json"]
        )

        assert first.exit_code == 0
        assert second.exit_code == 0
        assert first.stdout == second.stdout

    def test_secret_shaped_content_never_appears_in_diff_output(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """Privacy canary, reusing this codebase's synthetic
        GitHub-token-shaped canary convention
        (`tests/test_redaction.py`, `test_merge_base.py`'s own
        materialization canary): a secret-shaped value written into a
        tracked file must never reach `diff`'s stdout or stderr."""
        canary = "ghp_" + "a" * 36
        repo = tmp_path
        _diff_init_repo(repo)
        (repo / "notes.txt").write_text(f"token={canary}\n")
        _diff_commit_all(repo, "c1")
        monkeypatch.chdir(repo)

        result = runner.invoke(app, ["diff", "--format", "json"])

        assert result.exit_code == 0
        assert canary not in result.stdout
        assert canary not in result.stderr

    def test_format_text_renders_change_lines_and_a_summary(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """`--format text` with an actual (non-empty) diff exercises the
        per-change rendering loop and the trailing count summary, not
        only the empty-diff and effective-authority-only shapes the
        other format tests already cover."""
        baseline_dir = tmp_path / "baseline-repo"
        current_dir = tmp_path / "current-repo"
        baseline_dir.mkdir()
        current_dir.mkdir()
        (current_dir / ".mcp.json").write_text(
            '{"mcpServers": {"files": {"command": "npx"}}}'
        )
        monkeypatch.chdir(baseline_dir)
        baseline_file = tmp_path / "baseline.json"
        baseline_file.write_text(runner.invoke(app, ["bom"]).stdout)
        monkeypatch.chdir(current_dir)
        current_file = tmp_path / "current.json"
        current_file.write_text(runner.invoke(app, ["bom"]).stdout)

        result = runner.invoke(
            app, ["diff", str(baseline_file), str(current_file), "--format", "text"]
        )

        assert result.exit_code == 0
        assert "• ADDED" in result.stdout
        assert "node" in result.stdout
        # The server and the Claude Code host `.mcp.json` declares, the
        # host's edge to it, and the effective authority that edge grants.
        assert "4 changes: 4 added" in result.stdout

    def test_malformed_log_level_in_repository_mode_exits_invalid_input(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("CONTROLLOOP_LOG_LEVEL", "not-a-real-level")

        result = runner.invoke(app, ["diff"])

        assert result.exit_code == ExitCode.INVALID_INPUT
        assert result.stdout == ""

    def test_unresolvable_repository_path_exits_invalid_input(self) -> None:
        result = runner.invoke(app, ["diff", "/no/such/repository/path/exists"])

        assert result.exit_code == ExitCode.INVALID_INPUT
        assert result.stdout == ""

    def test_malformed_explicit_baseline_file_exits_invalid_input(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """`--baseline PATH` where `PATH` exists but is not a valid baseline
        document (`resolve_baseline` with `explicit_path` given) is a
        distinct, actionable exit-2 error, never a silent fallback."""
        monkeypatch.chdir(tmp_path)
        garbage = tmp_path / "not-a-baseline.json"
        garbage.write_text("not json at all")

        result = runner.invoke(app, ["diff", "--baseline", str(garbage)])

        assert result.exit_code == ExitCode.INVALID_INPUT
        assert result.stdout == ""


def _write_agent_card_with_a_prohibited_tool(root: Path) -> None:
    """A single-adapter fixture (A2A agent card) that discovers one AGENT
    node and one TOOL node connected by an `invokes` edge, paired with a
    `controlloop.yaml` ceiling that prohibits reaching that exact tool by
    name -- the smallest real, end-to-end path from repository content to a
    blocking `policy.capability-ceiling` finding, used to exercise `scan`'s
    own policy-failure exit code and `Verdict.DEPLOYMENT_BLOCKED`."""

    (root / "agent-card.json").write_text(
        json.dumps(
            {
                "name": "refund-agent",
                "skills": [{"id": "delete-database", "name": "delete-database"}],
            }
        )
    )
    (root / "controlloop.yaml").write_text(
        "schema_version: '1.0.0'\n"
        "owner: security-team\n"
        "ceilings:\n"
        "  - agent: refund-agent\n"
        "    prohibited_resources: [delete-database]\n"
    )


class TestScan:
    """`controlloop scan` integration tests through the real Typer entry
    point. Each test that resolves a repository root `monkeypatch.chdir`s
    into an isolated `tmp_path`, matching `TestBom`/`TestDiff`'s own
    isolation pattern."""

    def test_empty_repository_passes_with_no_findings(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """Nothing discovered, nothing to evaluate, a clean pass."""
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["scan", "--format", "json"])

        assert result.exit_code == ExitCode.PASS
        report = json.loads(result.stdout)
        assert report["verdict"] == "passed"
        assert report["findings"] == []
        assert report["blast_radius"] is None

    def test_no_baseline_reports_current_state_without_change_classification(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """No git history and no committed baseline at all -- `scan` still
        succeeds, with `material_changes` honestly `None` (never attempted),
        unlike `diff`'s own hard error for the identical "no usable git
        history" condition."""
        monkeypatch.chdir(tmp_path)
        assert list(tmp_path.iterdir()) == []

        result = runner.invoke(app, ["scan", "--format", "json"])

        assert result.exit_code == ExitCode.PASS
        report = json.loads(result.stdout)
        assert report["material_changes"] is None

    def test_committed_baseline_gives_no_material_changes(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """A committed baseline carries no nodes/edges, only effective
        authority -- `material_changes` stays `None` even though a baseline
        *was* found (distinct from the "no baseline at all" case above,
        which this same field value cannot itself distinguish --
        `RuleContext.diff` is what differs internally)."""
        monkeypatch.chdir(tmp_path)
        _write_conventional_baseline(
            tmp_path, _MINIMAL_BASELINE_FIXTURE.read_text(encoding="utf-8")
        )

        result = runner.invoke(app, ["scan", "--format", "json"])

        assert result.exit_code == ExitCode.PASS
        report = json.loads(result.stdout)
        assert report["material_changes"] is None

    def test_merge_base_fallback_computes_material_changes(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """Only the merge-base fallback path (a real baseline ACBOM, both
        sides' full graphs) ever produces a real `MaterialChangeSummary`,
        never `None`."""
        repo = tmp_path
        _diff_init_repo(repo)
        (repo / ".mcp.json").write_text('{"mcpServers": {"files": {"command": "npx"}}}')
        _diff_commit_all(repo, "c1")
        monkeypatch.chdir(repo)

        result = runner.invoke(app, ["scan", "--format", "json"])

        assert result.exit_code == ExitCode.PASS
        report = json.loads(result.stdout)
        assert report["material_changes"] is not None
        assert report["material_changes"]["changes"] == []

    def test_policy_failure_blocks_deployment_and_exits_policy_fail(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """A real, discovered capability outside a declared ceiling blocks
        -- proof this command's own rule-execution wiring actually reaches a
        real `Finding`, not just an empty-graph smoke test."""
        monkeypatch.chdir(tmp_path)
        _write_agent_card_with_a_prohibited_tool(tmp_path)

        result = runner.invoke(app, ["scan", "--format", "json"])

        assert result.exit_code == ExitCode.POLICY_FAIL
        report = json.loads(result.stdout)
        assert report["verdict"] == "deployment_blocked"
        rule_ids = {finding["rule_id"] for finding in report["findings"]}
        assert "policy.capability-ceiling" in rule_ids

    def test_disabling_the_blocking_rule_removes_its_finding_entirely(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """By design, a disabled rule's findings never appear in the report
        at all, not merely excluded from the gate decision.

        `policy.capability-ceiling` is classified
        `RuleMetadata.mandatory=True` (a ceiling breach cannot be silenced
        by disabling it) and can no longer be disabled at all -- see
        `test_disabling_a_mandatory_rule_exits_invalid_input` below for that
        behavior. This test now demonstrates the same "disabling a rule
        removes its finding entirely" behavior with
        `policy.undeclared-tools` instead (classified `mandatory=False`),
        using `_write_undeclared_tool_fixture` (below) with the severity
        threshold lowered to `medium` via `CONTROLLOOP_SEVERITY_THRESHOLD`
        so its own medium-severity finding blocks when the rule is enabled
        -- disabling it removes the finding entirely and the scan passes,
        the identical shape this test always proved."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("CONTROLLOOP_SEVERITY_THRESHOLD", "medium")
        _write_undeclared_tool_fixture(tmp_path)
        (tmp_path / CONFIG_FILENAME).write_text(
            'disabled_rules = ["policy.undeclared-tools"]\n'
        )

        result = runner.invoke(app, ["scan", "--format", "json"])

        assert result.exit_code == ExitCode.PASS
        report = json.loads(result.stdout)
        rule_ids = {finding["rule_id"] for finding in report["findings"]}
        assert "policy.undeclared-tools" not in rule_ids

    def test_disabling_a_mandatory_rule_exits_invalid_input(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """`validate_disabled_rules` rejects a real attempt, through the
        real `scan` command, to disable `policy.capability-ceiling` --
        classified `RuleMetadata.mandatory=True` in `CURRENT_RULE_PACK` --
        proving `scan`'s own catalog is sourced from
        `CURRENT_RULE_PACK.metadata` (the real governance decision), not a
        fabricated all-`False` stub. No repository content is needed:
        `validate_disabled_rules` runs before any rule executes, per its own
        docstring."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / CONFIG_FILENAME).write_text(
            'disabled_rules = ["policy.capability-ceiling"]\n'
        )

        result = runner.invoke(app, ["scan"])

        assert result.exit_code == ExitCode.INVALID_INPUT
        assert result.stdout == ""

    def test_disabling_an_unknown_rule_id_exits_invalid_input(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """`validate_disabled_rules` rejects a `disabled_rules` entry naming
        a rule ID this command's own catalog does not recognize, before any
        rule runs at all."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / CONFIG_FILENAME).write_text(
            'disabled_rules = ["policy.no-such-rule"]\n'
        )

        result = runner.invoke(app, ["scan"])

        assert result.exit_code == ExitCode.INVALID_INPUT
        assert result.stdout == ""

    def test_incomplete_analysis_exits_incomplete_analysis_code(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """An ACBOM diagnostic marking analysis incomplete, with no blocking
        finding, is `Verdict.REVIEW_REQUIRED` and
        `ExitCode.INCOMPLETE_ANALYSIS` -- never a silent pass."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".mcp.json").write_text(
            '{"mcpServers": {"broken": {"command": 123}}}'
        )

        result = runner.invoke(app, ["scan", "--format", "json"])

        assert result.exit_code == ExitCode.INCOMPLETE_ANALYSIS
        report = json.loads(result.stdout)
        assert report["verdict"] == "review_required"

    def test_malformed_manifest_exits_invalid_input(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """A `controlloop.yaml` that exists but fails to parse is a real
        repository problem, reported and exited like every other `scan`
        input-resolution failure."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "controlloop.yaml").write_text("not: valid: yaml: [")

        result = runner.invoke(app, ["scan"])

        assert result.exit_code == ExitCode.INVALID_INPUT
        assert result.stdout == ""

    def test_nonexistent_repository_path_exits_invalid_input(self) -> None:
        result = runner.invoke(app, ["scan", "/no/such/repository/path"])

        assert result.exit_code == ExitCode.INVALID_INPUT
        assert "INVALID INPUT" in result.stderr
        assert result.stdout == ""

    def test_all_three_formats_are_selectable_and_honor_stream_separation(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """`text`, `json`, and `sarif` are each independently selectable,
        and each format's own marker is absent from the other two -- stdout
        carries exactly one report, stderr never carries report content."""
        monkeypatch.chdir(tmp_path)
        _write_agent_card_with_a_prohibited_tool(tmp_path)

        text_result = runner.invoke(app, ["scan", "--format", "text"])
        json_result = runner.invoke(app, ["scan", "--format", "json"])
        sarif_result = runner.invoke(app, ["scan", "--format", "sarif"])

        assert text_result.exit_code == ExitCode.POLICY_FAIL
        assert json_result.exit_code == ExitCode.POLICY_FAIL
        assert sarif_result.exit_code == ExitCode.POLICY_FAIL

        json.loads(json_result.stdout)
        json.loads(sarif_result.stdout)
        with pytest.raises(json.JSONDecodeError):
            json.loads(text_result.stdout)

        assert '"$schema"' not in text_result.stdout
        assert '"$schema"' not in json_result.stdout
        assert '"$schema"' in sarif_result.stdout
        assert "DEPLOYMENT BLOCKED" in text_result.stdout or (
            "deployment" in text_result.stdout.lower()
        )

        for result in (text_result, json_result, sarif_result):
            assert "policy.capability-ceiling" not in result.stderr

    def test_scan_is_deterministic_across_repeated_invocations(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """Deterministic, and runs offline (covered by the autouse harness
        in `conftest.py`, which denies all socket access for the whole
        suite). Uses the blocking-finding fixture, not just an empty
        repository, so this also proves finding order/identity is stable
        across runs, not merely that an empty report repeats."""
        monkeypatch.chdir(tmp_path)
        _write_agent_card_with_a_prohibited_tool(tmp_path)

        first = runner.invoke(app, ["scan", "--format", "json"])
        second = runner.invoke(app, ["scan", "--format", "json"])

        assert first.exit_code == ExitCode.POLICY_FAIL
        assert first.stdout == second.stdout

    def test_malformed_log_level_exits_invalid_input(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("CONTROLLOOP_LOG_LEVEL", "not-a-real-level")

        result = runner.invoke(app, ["scan"])

        assert result.exit_code == ExitCode.INVALID_INPUT
        assert result.stdout == ""

    def test_merge_base_baseline_completeness_reaches_stderr(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """The merge-base baseline ACBOM's own completeness summary
        (`_scan_emit_completeness`) reaches stderr, distinct from the
        current document's own diagnostics folded into
        `ScanReport.diagnostics`."""
        repo = tmp_path
        _diff_init_repo(repo)
        (repo / ".mcp.json").write_text('{"mcpServers": {"broken": {"command": 123}}}')
        _diff_commit_all(repo, "c1")
        (repo / ".mcp.json").write_text('{"mcpServers": {"files": {"command": "npx"}}}')
        monkeypatch.chdir(repo)

        result = runner.invoke(app, ["scan", "--format", "json"])

        assert "COMPLETENESS" in result.stderr
        assert "merge-base baseline ACBOM" in result.stderr

    def test_tampered_committed_baseline_exits_invalid_input(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """A malformed *committed* baseline is still a hard error, even
        though a merely absent one is not -- mirrors `diff`'s own identical
        `test_tampered_committed_baseline_exits_invalid_input`."""
        monkeypatch.chdir(tmp_path)
        tampered = json.loads(_MINIMAL_BASELINE_FIXTURE.read_text(encoding="utf-8"))
        tampered["generator"]["version"] = "9.9.9"  # digest now stale
        _write_conventional_baseline(tmp_path, json.dumps(tampered))

        result = runner.invoke(app, ["scan"])

        assert result.exit_code == ExitCode.INVALID_INPUT
        assert result.stdout == ""

    def test_rule_findings_lookup_stays_in_sync_with_all_rules(self) -> None:
        """Structural safety net for the exact integration gap a merge with
        exfiltration triangle detection once exposed:
        `cli_module._RULE_FINDINGS_BY_ID` is keyed by explicit per-rule
        imports, not derived structurally from `ALL_RULES` -- a future rule
        added to `ALL_RULES` without a matching entry here would raise
        `KeyError` on every real `scan` invocation. This test fails loudly
        instead, the moment the two drift, rather than only when someone
        happens to trigger the missing rule's own findings."""
        from controlloop.policy.rules import ALL_RULES

        assert set(cli_module._RULE_FINDINGS_BY_ID) == {rule.id for rule in ALL_RULES}


def _build_minimal_low_confidence_finding() -> "controlloop.findings.models.Finding":
    """A real, directly constructed `Finding` at `Confidence.LOW` and
    `FindingSeverity.HIGH` -- used only to prove `_gate_classify`'s
    `PASSED_WITH_WARNINGS` branch (no rule fixture in this codebase's
    current corpus reaches a warning-only gate verdict through a real
    end-to-end scan, since every current blocking-capable fixture reports
    `Confidence.HIGH`). Mirrors
    `tests/findings/test_finding_construction.py`'s own direct-construction
    pattern."""

    from controlloop.acbom.models import Confidence, EdgeType, Evidence, NodeType
    from controlloop.capability.models import CapabilityPath, PathHop
    from controlloop.findings.identity import finding_id
    from controlloop.findings.models import (
        CURRENT_FINDING_SCHEMA_VERSION,
        Finding,
        FindingChangeState,
        FindingSeverity,
    )

    agent_id = f"clp:agent:sha256:{'a' * 64}"
    tool_id = f"clp:tool:sha256:{'b' * 64}"
    edge_id = f"clp:edge:sha256:{'c' * 64}"
    evidence = (Evidence(adapter="mcp", path="agent.json", line_start=5),)
    hop = PathHop(
        edge_id=edge_id,
        edge_type=EdgeType.INVOKES,
        source_id=agent_id,
        target_id=tool_id,
        evidence=evidence,
    )
    path = CapabilityPath(
        schema_version="1.0.0",
        agent_id=agent_id,
        target_id=tool_id,
        target_type=NodeType.TOOL,
        hops=(hop,),
        confidence=Confidence.LOW,
    )
    identity = finding_id(
        rule_id="policy.undeclared-tools", affected_agent=agent_id, capability_path=path
    )
    return Finding(
        schema_version=CURRENT_FINDING_SCHEMA_VERSION,
        id=identity,
        rule_id="policy.undeclared-tools",
        rule_version="1.0.0",
        message="undeclared tool reachable at low confidence",
        severity=FindingSeverity.HIGH,
        confidence=Confidence.LOW,
        affected_agent=agent_id,
        evidence=evidence,
        capability_path=path,
        change_state=FindingChangeState.NOT_COMPARED,
        remediation="declare the tool",
        documentation_url="https://docs.controlloop.ai/x",
    )


class TestGate:
    """`controlloop gate` integration tests through the real Typer entry
    point. Each test that resolves a repository root `monkeypatch.chdir`s
    into an isolated `tmp_path`, matching `TestScan`'s own isolation
    pattern. Every determinism/repeated-run test writes `--evidence-path`
    to a location *outside* the scanned repository directory -- writing the
    evidence artifact inside the scanned repository would make a second run
    see the first run's own artifact as part of the repository, changing
    `root_digest` (and therefore `acbom_digest`) between runs. This is a
    real, disclosed interaction (documented in `docs/reference/cli.md`), not
    a gate bug; keeping evidence output outside the scanned tree in these
    tests avoids exercising it by accident."""

    def test_empty_repository_passes_and_writes_evidence(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """Nothing discovered, nothing to evaluate, `pass` at exit 0, with a
        real `evidence.json` written to the default path that validates as a
        real `EvidenceArtifact`."""
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["gate"])

        assert result.exit_code == ExitCode.PASS
        evidence_path = tmp_path / "evidence.json"
        assert evidence_path.exists()
        artifact = EvidenceArtifact.model_validate_json(evidence_path.read_text())
        assert artifact.verdict == "passed"
        assert artifact.findings == ()
        assert artifact.baseline_digest is None
        assert artifact.effective_authority_diff is None

    def test_policy_failure_still_writes_evidence_and_exits_policy_fail(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """The central claim: `evidence.json` is written *including on
        failure*. A real, discovered capability outside a declared ceiling
        blocks, exactly as `scan`'s own identical fixture proves for
        `scan`."""
        monkeypatch.chdir(tmp_path)
        _write_agent_card_with_a_prohibited_tool(tmp_path)

        result = runner.invoke(app, ["gate", "--format", "json"])

        assert result.exit_code == ExitCode.POLICY_FAIL
        evidence_path = tmp_path / "evidence.json"
        assert evidence_path.exists(), "evidence.json must be written on failure too"
        artifact = EvidenceArtifact.model_validate_json(evidence_path.read_text())
        assert artifact.verdict == "deployment_blocked"
        rule_ids = {finding.rule_id for finding in artifact.findings or ()}
        assert "policy.capability-ceiling" in rule_ids
        # --format json's stdout is the literal evidence artifact, byte for
        # byte identical to the file.
        assert result.stdout.strip().encode("utf-8") == evidence_path.read_bytes()

    def test_incomplete_analysis_warns_by_default_and_writes_evidence(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """Incomplete analysis with no blocking finding, under the default
        `completeness_enforcement` setting ("warn"), is
        `passed_with_warnings`, exit 0 -- not a wall on a first run.
        `evidence.json` is still written, and its `completeness` reasons are
        populated regardless, along with the resolved setting itself. This
        replaces an earlier, disclosed, deliberately-deferred unconditional
        exit-3 behavior."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".mcp.json").write_text(
            '{"mcpServers": {"broken": {"command": 123}}}'
        )

        result = runner.invoke(app, ["gate", "--format", "json"])

        assert result.exit_code == ExitCode.PASS
        evidence_path = tmp_path / "evidence.json"
        assert evidence_path.exists()
        artifact = EvidenceArtifact.model_validate_json(evidence_path.read_text())
        assert artifact.verdict == "passed_with_warnings"
        assert artifact.completeness != ()
        assert artifact.completeness_enforcement == "warn"
        assert artifact.completeness_enforcement_source == "default"

    def test_completeness_enforcement_enabled_makes_incomplete_analysis_block(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """Opting into `completeness_enforcement = "enforce"` restores the
        `review_required`/exit-3 outcome for the identical incomplete
        analysis `test_incomplete_analysis_warns_by_default_and_writes_
        evidence` above now warns on by default. `evidence.json`'s `completeness`
        reasons are unchanged by the setting."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".mcp.json").write_text(
            '{"mcpServers": {"broken": {"command": 123}}}'
        )
        (tmp_path / CONFIG_FILENAME).write_text(
            'completeness_enforcement = "enforce"\n'
        )

        result = runner.invoke(app, ["gate", "--format", "json"])

        assert result.exit_code == ExitCode.INCOMPLETE_ANALYSIS
        evidence_path = tmp_path / "evidence.json"
        assert evidence_path.exists()
        artifact = EvidenceArtifact.model_validate_json(evidence_path.read_text())
        assert artifact.verdict == "review_required"
        assert artifact.completeness != ()
        assert artifact.completeness_enforcement == "enforce"
        assert artifact.completeness_enforcement_source == "repository file"

    def test_gate_classify_maps_warning_only_findings_to_passed_with_warnings(
        self,
    ) -> None:
        """The `warn` state: no rule fixture in this codebase's current
        corpus reaches a warning-only gate verdict through a real end-to-end
        scan (see `_build_minimal_low_confidence_finding`'s own
        docstring) -- proven instead with a real `Finding` and a real `evaluate_gate`
        call feeding `gate`'s own `_gate_classify`."""
        from controlloop.config import ConfigSource
        from controlloop.findings.models import FindingSeverity
        from controlloop.policy.thresholds import (
            CompletenessEnforcement,
            LowConfidenceAction,
            PolicyConfig,
            evaluate_gate,
        )

        finding = _build_minimal_low_confidence_finding()
        policy_config = PolicyConfig(
            severity_threshold=FindingSeverity.HIGH,
            severity_threshold_source=ConfigSource.DEFAULT,
            low_confidence_action=LowConfidenceAction.WARN,
            low_confidence_action_source=ConfigSource.DEFAULT,
            disabled_rule_ids=frozenset(),
            disabled_rule_ids_source=ConfigSource.DEFAULT,
            completeness_enforcement=CompletenessEnforcement.WARN,
            completeness_enforcement_source=ConfigSource.DEFAULT,
        )
        gate_verdict = evaluate_gate(
            (finding,),
            policy_config,
            scanner_version="0.0.0",
            rule_pack_name="test",
            rule_pack_version="1.0.0",
            rule_pack_fingerprint=f"sha256:{'0' * 64}",
        )

        verdict, exit_code = cli_module._gate_classify(
            gate_verdict,
            analysis_incomplete=False,
            completeness_enforcement=CompletenessEnforcement.WARN,
        )

        assert verdict == "passed_with_warnings"
        assert exit_code == ExitCode.PASS

    def test_gate_classify_incomplete_analysis_warns_by_default(self) -> None:
        """Incomplete analysis alone, with the default
        `CompletenessEnforcement.WARN` setting, never blocks --
        `passed_with_warnings` at exit 0, not `review_required` at exit
        3."""
        from controlloop.config import ConfigSource
        from controlloop.findings.models import FindingSeverity
        from controlloop.policy.thresholds import (
            CompletenessEnforcement,
            LowConfidenceAction,
            PolicyConfig,
            evaluate_gate,
        )

        policy_config = PolicyConfig(
            severity_threshold=FindingSeverity.HIGH,
            severity_threshold_source=ConfigSource.DEFAULT,
            low_confidence_action=LowConfidenceAction.BLOCK,
            low_confidence_action_source=ConfigSource.DEFAULT,
            disabled_rule_ids=frozenset(),
            disabled_rule_ids_source=ConfigSource.DEFAULT,
            completeness_enforcement=CompletenessEnforcement.WARN,
            completeness_enforcement_source=ConfigSource.DEFAULT,
        )
        gate_verdict = evaluate_gate(
            (),
            policy_config,
            scanner_version="0.0.0",
            rule_pack_name="test",
            rule_pack_version="1.0.0",
            rule_pack_fingerprint=f"sha256:{'0' * 64}",
        )

        verdict, exit_code = cli_module._gate_classify(
            gate_verdict,
            analysis_incomplete=True,
            completeness_enforcement=CompletenessEnforcement.WARN,
        )

        assert verdict == "passed_with_warnings"
        assert exit_code == ExitCode.PASS

    def test_gate_classify_incomplete_analysis_blocks_when_enforced(self) -> None:
        """With `CompletenessEnforcement.ENFORCE`, incomplete analysis
        returns `review_required` at exit 3 -- the pre-existing,
        now-conditional behavior."""
        from controlloop.config import ConfigSource
        from controlloop.findings.models import FindingSeverity
        from controlloop.policy.thresholds import (
            CompletenessEnforcement,
            LowConfidenceAction,
            PolicyConfig,
            evaluate_gate,
        )

        policy_config = PolicyConfig(
            severity_threshold=FindingSeverity.HIGH,
            severity_threshold_source=ConfigSource.DEFAULT,
            low_confidence_action=LowConfidenceAction.BLOCK,
            low_confidence_action_source=ConfigSource.DEFAULT,
            disabled_rule_ids=frozenset(),
            disabled_rule_ids_source=ConfigSource.DEFAULT,
            completeness_enforcement=CompletenessEnforcement.ENFORCE,
            completeness_enforcement_source=ConfigSource.REPOSITORY_FILE,
        )
        gate_verdict = evaluate_gate(
            (),
            policy_config,
            scanner_version="0.0.0",
            rule_pack_name="test",
            rule_pack_version="1.0.0",
            rule_pack_fingerprint=f"sha256:{'0' * 64}",
        )

        verdict, exit_code = cli_module._gate_classify(
            gate_verdict,
            analysis_incomplete=True,
            completeness_enforcement=CompletenessEnforcement.ENFORCE,
        )

        assert verdict == "review_required"
        assert exit_code == ExitCode.INCOMPLETE_ANALYSIS

    def test_evidence_path_is_configurable(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """The evidence path is configurable, not hardcoded.
        `--evidence-path`'s parent directory must already exist -- `gate`
        does not create missing parent directories, mirroring
        `bom --output`'s own identical precedent (see
        `test_unwritable_evidence_path_exits_invalid_input` below for the
        negative case)."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "artifacts").mkdir()
        custom_path = tmp_path / "artifacts" / "custom-evidence.json"

        result = runner.invoke(app, ["gate", "--evidence-path", str(custom_path)])

        assert result.exit_code == ExitCode.PASS
        assert custom_path.exists()
        assert not (tmp_path / "evidence.json").exists()

    def test_nonexistent_repository_path_exits_invalid_input_with_no_evidence(
        self, tmp_path: Path
    ) -> None:
        """A pre-verdict `INVALID_INPUT` failure never writes
        `evidence.json` -- there is no verdict or digest to report (a
        disclosed boundary)."""
        evidence_path = tmp_path / "evidence.json"

        result = runner.invoke(
            app,
            ["gate", "/no/such/repository/path", "--evidence-path", str(evidence_path)],
        )

        assert result.exit_code == ExitCode.INVALID_INPUT
        assert "INVALID INPUT" in result.stderr
        assert result.stdout == ""
        assert not evidence_path.exists()

    def test_malformed_manifest_exits_invalid_input_with_no_evidence(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / "controlloop.yaml").write_text("not: valid: yaml: [")

        result = runner.invoke(app, ["gate"])

        assert result.exit_code == ExitCode.INVALID_INPUT
        assert result.stdout == ""
        assert not (tmp_path / "evidence.json").exists()

    def test_disabling_an_unknown_rule_id_exits_invalid_input_with_no_evidence(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / CONFIG_FILENAME).write_text(
            'disabled_rules = ["policy.no-such-rule"]\n'
        )

        result = runner.invoke(app, ["gate"])

        assert result.exit_code == ExitCode.INVALID_INPUT
        assert result.stdout == ""
        assert not (tmp_path / "evidence.json").exists()

    def test_malformed_log_level_exits_invalid_input_with_no_evidence(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("CONTROLLOOP_LOG_LEVEL", "not-a-real-level")

        result = runner.invoke(app, ["gate"])

        assert result.exit_code == ExitCode.INVALID_INPUT
        assert result.stdout == ""
        assert not (tmp_path / "evidence.json").exists()

    def test_unwritable_evidence_path_exits_invalid_input(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """A failure to write the resolved evidence path itself (here: a
        parent that is a file, not a directory) is an input problem, not a
        policy outcome, mirroring `bom --output`'s own `OSError`
        handling."""
        monkeypatch.chdir(tmp_path)
        blocking_file = tmp_path / "not-a-directory"
        blocking_file.write_text("x")

        result = runner.invoke(
            app, ["gate", "--evidence-path", str(blocking_file / "evidence.json")]
        )

        assert result.exit_code == ExitCode.INVALID_INPUT
        assert "INVALID INPUT" in result.stderr

    def test_all_three_formats_are_selectable_and_honor_stream_separation(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """`text`, `json`, and `sarif` are each independently
        selectable, and stdout carries exactly one document -- mirrors
        `TestScan`'s own identical test."""
        monkeypatch.chdir(tmp_path)
        _write_agent_card_with_a_prohibited_tool(tmp_path)

        text_result = runner.invoke(
            app, ["gate", "--format", "text", "--evidence-path", "e-text.json"]
        )
        json_result = runner.invoke(
            app, ["gate", "--format", "json", "--evidence-path", "e-json.json"]
        )
        sarif_result = runner.invoke(
            app, ["gate", "--format", "sarif", "--evidence-path", "e-sarif.json"]
        )

        assert text_result.exit_code == ExitCode.POLICY_FAIL
        assert json_result.exit_code == ExitCode.POLICY_FAIL
        assert sarif_result.exit_code == ExitCode.POLICY_FAIL

        json.loads(json_result.stdout)
        json.loads(sarif_result.stdout)
        with pytest.raises(json.JSONDecodeError):
            json.loads(text_result.stdout)

        assert '"$schema"' not in text_result.stdout
        assert '"$schema"' not in json_result.stdout
        assert '"$schema"' in sarif_result.stdout
        assert "DEPLOYMENT BLOCKED" in text_result.stdout
        assert "Evidence:" in text_result.stdout

        for result in (text_result, json_result, sarif_result):
            assert "policy.capability-ceiling" not in result.stderr

    def test_committed_baseline_populates_baseline_digest_and_diff_together(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """`baseline_digest`/`effective_authority_diff` are both `None` or
        both present (`EvidenceArtifact`'s own existing validator) -- a
        resolved committed baseline populates both, from
        `BaselineDocument.digest` directly."""
        monkeypatch.chdir(tmp_path)
        _write_conventional_baseline(
            tmp_path, _MINIMAL_BASELINE_FIXTURE.read_text(encoding="utf-8")
        )

        result = runner.invoke(app, ["gate", "--format", "json"])

        assert result.exit_code == ExitCode.PASS
        artifact = EvidenceArtifact.model_validate_json(result.stdout)
        assert artifact.baseline_digest is not None
        assert artifact.baseline_digest.startswith("sha256:")
        assert artifact.effective_authority_diff is not None

    def test_merge_base_fallback_populates_baseline_digest_from_the_merge_base_acbom(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """The merge-base fallback has no `BaselineDocument` at all --
        `baseline_digest` is forced to the merge-base `ACBOMDocument`'s own
        digest by `EvidenceArtifact`'s existing validator (not a stylistic
        choice), and `baseline_provenance` stays `None` (no human approved a
        merge-base reference)."""
        repo = tmp_path
        _diff_init_repo(repo)
        (repo / ".mcp.json").write_text('{"mcpServers": {"files": {"command": "npx"}}}')
        _diff_commit_all(repo, "c1")
        monkeypatch.chdir(repo)

        result = runner.invoke(app, ["gate", "--format", "json"])

        assert result.exit_code == ExitCode.PASS
        artifact = EvidenceArtifact.model_validate_json(result.stdout)
        assert artifact.baseline_digest is not None
        assert artifact.baseline_digest.startswith("sha256:")
        assert artifact.baseline_provenance is None
        assert artifact.effective_authority_diff is not None

    def test_tampered_committed_baseline_exits_invalid_input_with_no_evidence(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """A malformed *committed* baseline is a hard error, even though
        a merely absent one is not -- mirrors `TestScan`'s own identical
        `test_tampered_committed_baseline_exits_invalid_input`."""
        monkeypatch.chdir(tmp_path)
        tampered = json.loads(_MINIMAL_BASELINE_FIXTURE.read_text(encoding="utf-8"))
        tampered["generator"]["version"] = "9.9.9"  # digest now stale
        _write_conventional_baseline(tmp_path, json.dumps(tampered))

        result = runner.invoke(app, ["gate"])

        assert result.exit_code == ExitCode.INVALID_INPUT
        assert result.stdout == ""
        assert not (tmp_path / "evidence.json").exists()

    def test_merge_base_baseline_completeness_reaches_stderr(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """The merge-base baseline ACBOM's own completeness summary
        (`_gate_emit_completeness`) reaches stderr, distinct from the
        current document's own diagnostics folded into
        `EvidenceArtifact.completeness` -- mirrors `TestScan`'s own
        identical `test_merge_base_baseline_completeness_reaches_stderr`."""
        repo = tmp_path
        _diff_init_repo(repo)
        (repo / ".mcp.json").write_text('{"mcpServers": {"broken": {"command": 123}}}')
        _diff_commit_all(repo, "c1")
        (repo / ".mcp.json").write_text('{"mcpServers": {"files": {"command": "npx"}}}')
        monkeypatch.chdir(repo)

        result = runner.invoke(app, ["gate", "--format", "json"])

        assert "COMPLETENESS" in result.stderr
        assert "merge-base baseline ACBOM" in result.stderr

    def test_gate_is_deterministic_across_repeated_invocations(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """Determinism, both halves: an identical verdict *and* an identical
        artifact digest -- hashing the real written `evidence.json` bytes
        across two real repeated invocations, not merely comparing in-memory
        objects. Also runs offline, covered by the autouse harness in
        `conftest.py`, which denies all socket access for the whole suite
        (see `test_offline_harness.py` for one additional, explicitly named
        offline proof).

        Both evidence paths are written *outside* the scanned repository
        directory (`repo/`, not `tmp_path` itself) -- see this class's
        own docstring for why writing inside the scanned tree would make
        the second run see the first run's own artifact as part of the
        repository, and so would not actually prove determinism."""
        repo = tmp_path / "repo"
        repo.mkdir()
        _write_agent_card_with_a_prohibited_tool(repo)
        evidence_dir = tmp_path / "evidence-out"
        evidence_dir.mkdir()
        monkeypatch.chdir(repo)

        first = runner.invoke(
            app,
            [
                "gate",
                "--format",
                "json",
                "--evidence-path",
                str(evidence_dir / "run1.json"),
            ],
        )
        second = runner.invoke(
            app,
            [
                "gate",
                "--format",
                "json",
                "--evidence-path",
                str(evidence_dir / "run2.json"),
            ],
        )

        assert first.exit_code == ExitCode.POLICY_FAIL
        assert second.exit_code == ExitCode.POLICY_FAIL
        assert first.stdout == second.stdout

        first_bytes = (evidence_dir / "run1.json").read_bytes()
        second_bytes = (evidence_dir / "run2.json").read_bytes()
        assert (
            hashlib.sha256(first_bytes).hexdigest()
            == hashlib.sha256(second_bytes).hexdigest()
        )

    def test_gate_never_prompts_or_reads_stdin(self) -> None:
        """Never prompts, proven structurally rather than by absence of a
        failing test case: `gate`'s own source, and the source of every
        private helper it calls, contains no call to
        `OutputStreams.confirm_or_exit`, `input(`, or `sys.stdin` -- the
        only mechanisms this codebase has for blocking on interactive input
        (`controlloop.output.OutputStreams.confirm_or_exit`, the sole
        prompt-shaped primitive in this codebase, is never invoked anywhere
        in `gate`'s own call graph)."""
        gate_call_graph = (
            cli_module.gate,
            cli_module._gate_resolve_baseline,
            cli_module._gate_classify,
            cli_module._gate_write_evidence,
            cli_module._gate_render_and_exit,
            cli_module._gate_error,
            cli_module._gate_emit_completeness,
            cli_module._scan_load_manifest,
        )
        for function in gate_call_graph:
            source = inspect.getsource(function)
            assert "confirm_or_exit" not in source
            assert "input(" not in source
            assert "stdin" not in source

    def test_shallow_checkout_fails_clearly_instead_of_silently_skipping_baseline(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """A shallow CI-style checkout that cannot resolve a merge-base now
        exits `INVALID_INPUT` with a clear, actionable message, rather than
        silently proceeding as "no baseline." Fixture construction mirrors
        `tests/baseline/test_merge_base.py`'s own
        `test_shallow_clone_reports_shallow_as_likely_cause` -- `file://` is
        required because a plain path-based local clone silently ignores
        `--depth`."""
        origin = tmp_path / "origin"
        origin.mkdir()
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=origin, check=True)
        (origin / "a.txt").write_text("a\n")
        _commit(origin, "c1")
        subprocess.run(
            ["git", "checkout", "-q", "-b", "feature"], cwd=origin, check=True
        )
        (origin / "b.txt").write_text("b\n")
        _commit(origin, "c2 on feature")
        (origin / "c.txt").write_text("c\n")
        _commit(origin, "c3 on feature")
        subprocess.run(["git", "checkout", "-q", "main"], cwd=origin, check=True)

        dest = tmp_path / "dest"
        subprocess.run(
            [
                "git",
                "clone",
                "-q",
                "--no-single-branch",
                "--depth",
                "1",
                "--branch",
                "feature",
                f"file://{origin}",
                str(dest),
            ],
            check=True,
            capture_output=True,
        )
        monkeypatch.chdir(dest)

        result = runner.invoke(app, ["gate"])

        assert result.exit_code == ExitCode.INVALID_INPUT
        message = result.stderr.lower()
        assert "shallow clone" in message
        assert "fetch --unshallow" in message or "fetch-depth" in message
        assert not (dest / "evidence.json").exists(), (
            "an input-resolution failure never reaches evidence writing"
        )

    def test_no_git_history_still_passes_with_no_baseline_unchanged(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """Regression guard for the shallow-checkout check's narrow scope: a
        repository with genuinely no git history at all
        (`NoGitHistoryError`) must keep its existing, unchanged, silent "no
        baseline" behavior -- only `MergeBaseResolutionError` newly surfaces
        as an error."""
        monkeypatch.chdir(tmp_path)
        subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)

        result = runner.invoke(app, ["gate", "--format", "json"])

        assert result.exit_code == ExitCode.PASS
        artifact = EvidenceArtifact.model_validate_json(
            (tmp_path / "evidence.json").read_text()
        )
        assert artifact.baseline_digest is None

    def test_default_branch_override_resolves_the_named_branch(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """`--default-branch` reaches `resolve_merge_base` and changes which
        branch is treated as the comparison target -- proven by pointing it
        at a branch whose tip commit differs from `main`'s, and confirming
        the run succeeds (no `MergeBaseResolutionError`) using that named
        branch rather than the auto-detected default."""
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=tmp_path, check=True)
        (tmp_path / "a.txt").write_text("a\n")
        _commit(tmp_path, "c1")
        subprocess.run(
            ["git", "checkout", "-q", "-b", "release"], cwd=tmp_path, check=True
        )
        (tmp_path / "b.txt").write_text("b\n")
        _commit(tmp_path, "c2 on release")
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["gate", "--default-branch", "release"])

        assert result.exit_code in (ExitCode.PASS, ExitCode.POLICY_FAIL)
        assert "shallow clone" not in result.stderr.lower()

    def test_sarif_path_written_unconditionally_including_on_failure(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """--sarif-path is written regardless of --format, including on a
        failing (blocked) verdict -- the evidence-path unconditional-write
        guarantee, mirrored. The written document embeds the blast-radius
        statement under runs[0].properties.controlloop.blastRadius."""
        monkeypatch.chdir(tmp_path)
        _write_agent_card_with_a_prohibited_tool(tmp_path)
        sarif_path = tmp_path / "results.sarif"

        result = runner.invoke(
            app, ["gate", "--format", "text", "--sarif-path", str(sarif_path)]
        )

        assert result.exit_code == ExitCode.POLICY_FAIL
        assert sarif_path.exists()
        document = json.loads(sarif_path.read_text())
        assert document["version"] == "2.1.0"
        rule_ids = {result_["ruleId"] for result_ in document["runs"][0]["results"]}
        assert "policy.capability-ceiling" in rule_ids
        blast_radius = document["runs"][0]["properties"]["controlloop"]["blastRadius"]
        assert isinstance(blast_radius, list)
        assert len(blast_radius) >= 1

    def test_sarif_path_matches_format_sarif_stdout_byte_for_byte(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """The unconditional --sarif-path write and --format sarif's own
        stdout rendering compute the identical document once, not two
        independently-drifting renderings."""
        monkeypatch.chdir(tmp_path)
        sarif_path = tmp_path / "results.sarif"

        result = runner.invoke(
            app, ["gate", "--format", "sarif", "--sarif-path", str(sarif_path)]
        )

        assert result.exit_code == ExitCode.PASS
        assert result.stdout.strip().encode("utf-8") == sarif_path.read_bytes()

    def test_omitting_sarif_path_writes_nothing_and_is_unaffected(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """Regression guard: a caller that never passes --sarif-path sees no
        new file and no behavior change from before `--sarif-path`
        existed."""
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["gate"])

        assert result.exit_code == ExitCode.PASS
        assert list(tmp_path.glob("*.sarif")) == []


def _commit(path: Path, message: str) -> None:
    subprocess.run(["git", "add", "-A"], cwd=path, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.email=t@t.com",
            "-c",
            "user.name=t",
            "commit",
            "-q",
            "-m",
            message,
        ],
        cwd=path,
        check=True,
    )


def _write_undeclared_tool_fixture(root: Path) -> None:
    """A single A2A agent card discovering one reachable tool, plus a
    minimal manifest declaring no ceiling -- produces exactly one real,
    medium-severity `policy.undeclared-tools` finding and nothing else (a
    suppression fixture). A manifest must be present for `undeclared_tools`
    to fire at all -- with no manifest, that rule has nothing to compare
    discovered tools against and produces no finding (see that rule module's
    own docstring)."""

    (root / "agent-card.json").write_text(
        json.dumps(
            {
                "name": "refund-agent",
                "skills": [{"id": "delete-database", "name": "delete-database"}],
            }
        )
    )
    (root / "controlloop.yaml").write_text(
        "schema_version: '1.0.0'\nowner: security-team\n"
    )


class TestSuppressions:
    """End-to-end `controlloop.yaml` suppression tests through the real
    `scan`/`gate` Typer entry points. Uses a real two-phase
    discover-then-suppress pattern (run once to learn the real,
    content-addressed finding ID; declare a suppression naming it; run
    again) rather than a hand-typed digest, so these tests exercise the
    exact same stable-identity scheme production does. `--format json`
    output is parsed directly; text-format assertions check the rendered
    `Suppressions:` section verbatim.

    `CONTROLLOOP_SEVERITY_THRESHOLD=medium` is set throughout: the
    fixture's own finding is `medium` severity, below the default `high`
    threshold, so without lowering the threshold every scenario would
    pass regardless of suppression, defeating the point of these tests.
    """

    def _discover_finding_id(self, monkeypatch: MonkeyPatch) -> str:
        monkeypatch.setenv("CONTROLLOOP_SEVERITY_THRESHOLD", "medium")
        result = runner.invoke(app, ["scan", "--format", "json"])
        report = json.loads(result.stdout)
        (finding,) = report["findings"]
        assert finding["rule_id"] == "policy.undeclared-tools"
        return str(finding["id"])

    def test_active_suppression_removes_blocking_and_is_reported(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        _write_undeclared_tool_fixture(tmp_path)
        finding_id = self._discover_finding_id(monkeypatch)

        (tmp_path / "controlloop.yaml").write_text(
            "schema_version: '1.0.0'\n"
            "owner: security-team\n"
            "suppressions:\n"
            "  - rule_id: policy.undeclared-tools\n"
            f"    target: {finding_id}\n"
            '    reason: "reviewed by security team"\n'
            '    expires_at: "2099-01-01"\n'
        )

        result = runner.invoke(app, ["scan", "--format", "json"])
        report = json.loads(result.stdout)

        assert result.exit_code == ExitCode.PASS
        assert report["verdict"] == "passed"
        # The finding itself is never hidden from evidence, only from the
        # gate decision.
        assert len(report["findings"]) == 1
        assert report["suppressions"] == [
            {
                "rule_id": "policy.undeclared-tools",
                "target": finding_id,
                "reason": "reviewed by security team",
                "expires_at": "2099-01-01",
                "status": "active",
            }
        ]

    def test_active_suppression_is_rendered_in_text_output(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        _write_undeclared_tool_fixture(tmp_path)
        finding_id = self._discover_finding_id(monkeypatch)

        (tmp_path / "controlloop.yaml").write_text(
            "schema_version: '1.0.0'\n"
            "owner: security-team\n"
            "suppressions:\n"
            "  - rule_id: policy.undeclared-tools\n"
            f"    target: {finding_id}\n"
            '    reason: "reviewed by security team"\n'
            '    expires_at: "2099-01-01"\n'
        )

        result = runner.invoke(app, ["scan"])

        assert "Suppressions:" in result.stdout
        assert "active" in result.stdout
        assert "reviewed by security team" in result.stdout

    def test_no_suppressions_declared_is_rendered_explicitly(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """The "never hidden" guarantee holds in the negative case too --
        the section is always present, never silently omitted when nothing
        is declared."""
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["scan"])

        assert "Suppressions: none declared" in result.stdout

    def test_expired_suppression_still_blocks_and_is_reported_expired(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        _write_undeclared_tool_fixture(tmp_path)
        finding_id = self._discover_finding_id(monkeypatch)

        (tmp_path / "controlloop.yaml").write_text(
            "schema_version: '1.0.0'\n"
            "owner: security-team\n"
            "suppressions:\n"
            "  - rule_id: policy.undeclared-tools\n"
            f"    target: {finding_id}\n"
            '    reason: "expired"\n'
            '    expires_at: "2020-01-01"\n'
        )

        result = runner.invoke(app, ["scan", "--format", "json"])
        report = json.loads(result.stdout)

        assert report["verdict"] == "deployment_blocked"
        assert report["suppressions"][0]["status"] == "expired"

    def test_stale_suppression_has_no_effect_and_is_reported_stale(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        _write_undeclared_tool_fixture(tmp_path)
        monkeypatch.setenv("CONTROLLOOP_SEVERITY_THRESHOLD", "medium")
        non_matching_target = f"clp:finding:sha256:{'0' * 64}"
        (tmp_path / "controlloop.yaml").write_text(
            "schema_version: '1.0.0'\n"
            "owner: security-team\n"
            "suppressions:\n"
            "  - rule_id: policy.undeclared-tools\n"
            f"    target: {non_matching_target}\n"
            '    reason: "does not match anything"\n'
            '    expires_at: "2099-01-01"\n'
        )

        result = runner.invoke(app, ["scan", "--format", "json"])
        report = json.loads(result.stdout)

        assert report["verdict"] == "deployment_blocked"
        assert report["suppressions"][0]["status"] == "stale"

    def test_missing_required_field_exits_invalid_input(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """A suppression missing a required field (here, `reason`) is a
        malformed manifest -- exit 2, through the real manifest-loading CLI
        path, not merely at the model level."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "controlloop.yaml").write_text(
            "schema_version: '1.0.0'\n"
            "owner: security-team\n"
            "suppressions:\n"
            "  - rule_id: policy.undeclared-tools\n"
            f"    target: clp:finding:sha256:{'a' * 64}\n"
            '    expires_at: "2099-01-01"\n'
        )

        result = runner.invoke(app, ["scan"])

        assert result.exit_code == ExitCode.INVALID_INPUT
        assert result.stdout == ""

    def test_cannot_suppress_a_capability_ceiling_breach(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """End to end: a suppression naming the real
        `policy.capability-ceiling` finding produced by
        `_write_agent_card_with_a_prohibited_tool` never suppresses it,
        regardless of how precisely it is targeted."""
        monkeypatch.chdir(tmp_path)
        _write_agent_card_with_a_prohibited_tool(tmp_path)

        result = runner.invoke(app, ["scan", "--format", "json"])
        report = json.loads(result.stdout)
        ceiling_finding = next(
            f for f in report["findings"] if f["rule_id"] == "policy.capability-ceiling"
        )

        (tmp_path / "controlloop.yaml").write_text(
            "schema_version: '1.0.0'\n"
            "owner: security-team\n"
            "ceilings:\n"
            "  - agent: refund-agent\n"
            "    prohibited_resources: [delete-database]\n"
            "suppressions:\n"
            "  - rule_id: policy.capability-ceiling\n"
            f"    target: {ceiling_finding['id']}\n"
            '    reason: "attempting to suppress a ceiling breach"\n'
            '    expires_at: "2099-01-01"\n'
        )

        result = runner.invoke(app, ["scan", "--format", "json"])
        report = json.loads(result.stdout)

        assert result.exit_code == ExitCode.POLICY_FAIL
        assert report["verdict"] == "deployment_blocked"
        assert report["suppressions"][0]["status"] == "ceiling-protected"

    def test_gate_wires_suppressions_into_the_evidence_artifact(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        _write_undeclared_tool_fixture(tmp_path)
        finding_id = self._discover_finding_id(monkeypatch)
        evidence_path = tmp_path.parent / "evidence.json"

        (tmp_path / "controlloop.yaml").write_text(
            "schema_version: '1.0.0'\n"
            "owner: security-team\n"
            "suppressions:\n"
            "  - rule_id: policy.undeclared-tools\n"
            f"    target: {finding_id}\n"
            '    reason: "reviewed by security team"\n'
            '    expires_at: "2099-01-01"\n'
        )

        result = runner.invoke(
            app, ["gate", "--evidence-path", str(evidence_path), "--format", "json"]
        )
        artifact = json.loads(result.stdout)

        assert result.exit_code == ExitCode.PASS
        assert artifact["verdict"] == "passed"
        assert artifact["suppressions"][0]["status"] == "active"
        assert "Suppressions:" in runner.invoke(app, ["gate"]).stdout
