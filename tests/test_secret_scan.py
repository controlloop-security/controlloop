"""Tests for controlloop.secret_scan: positive, similar negative,
malformed, boundary, fixture/placeholder confidence downgrade, privacy (a
redaction-style canary), offline, and determinism coverage for the
discovery-time secret-shaped-content scanning pass."""

from __future__ import annotations

import ast
import inspect
import socket
from pathlib import Path

import pytest

from controlloop import secret_scan
from controlloop.acbom.models import (
    Confidence,
    Diagnostic,
    DiagnosticSeverity,
    Evidence,
)
from controlloop.repository import resolve_repository_root, walk_repository
from controlloop.secret_scan import SecretScanBounds, scan_repository_for_secrets

_AWS_KEY = "AKIAABCDEFGHIJKLMNOP"
_HIGH_ENTROPY_VALUE = "Zx9kQwLpR7mTnUvBhYs2Jd4Fa8Ke1Wo6"


def _files(tmp_path: Path) -> list[Path]:
    root = resolve_repository_root(tmp_path)
    walked = list(walk_repository(root))
    return [entry for entry in walked if isinstance(entry, Path)]


def _scan(
    tmp_path: Path, *, bounds: SecretScanBounds | None = None
) -> tuple[Diagnostic, ...]:
    root = resolve_repository_root(tmp_path)
    files = _files(tmp_path)
    return scan_repository_for_secrets(root, files, bounds=bounds)


class TestPositive:
    def test_known_credential_shape_is_detected(self, tmp_path: Path) -> None:
        (tmp_path / "config.py").write_text(f'AWS_KEY = "{_AWS_KEY}"\n')

        results = _scan(tmp_path)

        assert len(results) == 1
        assert results[0].code == "SECRET-CREDENTIAL-SHAPE-DETECTED"
        assert results[0].confidence is Confidence.HIGH
        assert results[0].evidence[0].path == "config.py"
        assert results[0].evidence[0].line_start == 1

    def test_every_known_shape_produces_a_detection(self, tmp_path: Path) -> None:
        from controlloop.redaction import known_credential_shapes

        examples = {
            "aws-access-key-id": "AKIAABCDEFGHIJKLMNOP",
            "github-token": "ghp_" + "a" * 36,
            "github-fine-grained-token": "github_pat_" + "a" * 22,
            "slack-token": "xoxb-" + "a" * 10,
            "google-api-key": "AIza" + "a" * 35,
            "stripe-secret-key": "sk_live_" + "a" * 16,
            "private-key-block": (
                "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----"
            ),
            "json-web-token": "ey" + "a" * 10 + "." + "b" * 10 + "." + "c" * 10,
            "anthropic-api-key": "sk-ant-api03-" + "a" * 93 + "AA",
            "anthropic-admin-key": "sk-ant-admin01-" + "a" * 93 + "AA",
            "openai-api-key": "sk-proj-" + "a" * 74 + "T3BlbkFJ" + "b" * 74,
            "openai-legacy-api-key": "sk-" + "a" * 20 + "T3BlbkFJ" + "b" * 20,
        }
        assert set(examples) == set(known_credential_shapes())

        for index, value in enumerate(examples.values()):
            (tmp_path / f"f{index}.txt").write_text(f"token={value}\n")

        results = _scan(tmp_path)

        found_shapes = {
            result.message
            for result in results
            if result.code == "SECRET-CREDENTIAL-SHAPE-DETECTED"
        }
        assert len(found_shapes) == len(examples)

    def test_high_entropy_assignment_is_detected(self, tmp_path: Path) -> None:
        (tmp_path / "settings.py").write_text(f'API_KEY = "{_HIGH_ENTROPY_VALUE}"\n')

        results = _scan(tmp_path)

        assert len(results) == 1
        assert results[0].code == "SECRET-HIGH-ENTROPY-VALUE-DETECTED"
        assert results[0].confidence is Confidence.MEDIUM

    def test_multiple_files_each_produce_their_own_detection(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "a.py").write_text(f'KEY_A = "{_AWS_KEY}"\n')
        (tmp_path / "b.py").write_text(f'KEY_B = "{_AWS_KEY}"\n')

        results = _scan(tmp_path)

        paths = {result.evidence[0].path for result in results}
        assert paths == {"a.py", "b.py"}


class TestSimilarNegative:
    def test_clean_file_produces_no_detections(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("def add(a, b):\n    return a + b\n")

        assert _scan(tmp_path) == ()

    def test_near_miss_credential_shape_is_not_detected(self, tmp_path: Path) -> None:
        (tmp_path / "config.py").write_text(
            'KEY = "AKIAABCDEFGHIJKLMNO"\n'
        )  # one short

        assert _scan(tmp_path) == ()

    def test_high_entropy_value_without_assignment_context_is_not_detected(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "notes.txt").write_text(f"see also {_HIGH_ENTROPY_VALUE}\n")

        assert _scan(tmp_path) == ()

    def test_low_entropy_assignment_is_not_detected(self, tmp_path: Path) -> None:
        (tmp_path / "settings.py").write_text('PASSWORD = "aaaaaaaaaaaaaaaaaaaaaaaa"\n')

        assert _scan(tmp_path) == ()


class TestMalformed:
    def test_undecodable_file_is_isolated_and_scan_continues(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "binary_looking.txt").write_bytes(b"\xff\xfe\x00\x01not utf8 \xff")
        (tmp_path / "clean.py").write_text(f'AWS_KEY = "{_AWS_KEY}"\n')

        results = _scan(tmp_path)

        codes = {result.code for result in results}
        # The undecodable file is either classified binary by
        # walk_repository itself (never reaches this module at all) or,
        # if it sniffs as text, isolated here as INCOMPLETE-UNPARSED-REGION
        # -- either way, the scan continues and clean.py is still found.
        assert "SECRET-CREDENTIAL-SHAPE-DETECTED" in codes
        assert all(code.startswith(("SECRET-", "INCOMPLETE-")) for code in codes)


class TestBoundary:
    def test_many_detections_hit_the_configured_bound(self, tmp_path: Path) -> None:
        for index in range(10):
            (tmp_path / f"secret{index}.py").write_text(f'KEY_{index} = "{_AWS_KEY}"\n')

        results = _scan(tmp_path, bounds=SecretScanBounds(max_detections=3))

        assert len(results) == 4  # 3 detections + one bound-exceeded diagnostic
        codes = [result.code for result in results]
        assert codes.count("INCOMPLETE-BOUND-EXCEEDED") == 1
        assert codes.count("SECRET-CREDENTIAL-SHAPE-DETECTED") == 3
        (bound_diagnostic,) = (
            result for result in results if result.code == "INCOMPLETE-BOUND-EXCEEDED"
        )
        assert bound_diagnostic.incomplete is True

    def test_max_detections_below_one_is_rejected(self) -> None:
        with pytest.raises(ValueError):
            SecretScanBounds(max_detections=0)


class TestFixtureAndPlaceholderConfidenceDowngrade:
    """Test fixtures and documented example values are
    recognized at reduced confidence, never as certain."""

    def test_path_based_fixture_downgrades_a_known_shape_to_medium(
        self, tmp_path: Path
    ) -> None:
        fixtures_dir = tmp_path / "tests" / "fixtures"
        fixtures_dir.mkdir(parents=True)
        (fixtures_dir / "config.py").write_text(f'AWS_KEY = "{_AWS_KEY}"\n')

        (results,) = _scan(tmp_path)

        assert results.confidence is Confidence.MEDIUM

    def test_value_based_placeholder_downgrades_a_known_shape_to_medium(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "config.py").write_text('STRIPE_KEY = "sk_test_' + "a" * 16 + '"\n')

        (results,) = _scan(tmp_path)

        assert results.confidence is Confidence.MEDIUM

    def test_well_known_aws_documentation_example_is_downgraded(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "README.md").write_text(
            'export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"\n'
        )

        (results,) = _scan(tmp_path)

        assert results.confidence is Confidence.MEDIUM

    def test_path_based_fixture_downgrades_an_entropy_match_to_low(
        self, tmp_path: Path
    ) -> None:
        examples_dir = tmp_path / "examples"
        examples_dir.mkdir()
        (examples_dir / "settings.py").write_text(
            f'API_KEY = "{_HIGH_ENTROPY_VALUE}"\n'
        )

        (results,) = _scan(tmp_path)

        assert results.confidence is Confidence.LOW

    def test_real_looking_value_outside_a_fixture_path_stays_high(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "config.py").write_text(f'AWS_KEY = "{_AWS_KEY}"\n')

        (results,) = _scan(tmp_path)

        assert results.confidence is Confidence.HIGH


class TestPrivacyCanary:
    """The matched value never appears in any produced
    Diagnostic's message or evidence."""

    def test_planted_secret_never_appears_in_any_diagnostic(
        self, tmp_path: Path
    ) -> None:
        planted = "AKIA" + "PLANTEDSECRET012"[:16]
        (tmp_path / "config.py").write_text(f'AWS_KEY = "{planted}"\n')

        results = _scan(tmp_path)

        for result in results:
            assert planted not in result.message
            assert planted not in result.code
            for evidence in result.evidence:
                assert planted not in (evidence.path or "")

    def test_planted_high_entropy_secret_never_appears_in_any_diagnostic(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "settings.py").write_text(f'API_KEY = "{_HIGH_ENTROPY_VALUE}"\n')

        results = _scan(tmp_path)

        for result in results:
            assert _HIGH_ENTROPY_VALUE not in result.message
            for evidence in result.evidence:
                assert _HIGH_ENTROPY_VALUE not in (evidence.path or "")


class TestOffline:
    def test_offline_harness_is_active_for_this_module(self) -> None:
        with pytest.raises(RuntimeError, match="offline harness"):
            socket.socket()

    def test_module_never_imports_network_or_subprocess_capable_names(self) -> None:
        """This module deliberately reads files (that is its whole
        purpose, unlike a `Rule`), so the relevant structural proof here
        is narrower than `test_policy_engine.py`'s rule-safety check:
        never subprocess, socket, or network access."""

        forbidden = {
            "subprocess",
            "socket",
            "urllib",
            "http",
            "ftplib",
            "smtplib",
            "requests",
            "httpx",
            "aiohttp",
        }
        tree = ast.parse(inspect.getsource(secret_scan))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported.add(node.module.split(".")[0])
        assert imported & forbidden == set()


class TestDeterminism:
    def test_identical_input_produces_an_identical_result(self, tmp_path: Path) -> None:
        (tmp_path / "config.py").write_text(f'AWS_KEY = "{_AWS_KEY}"\n')
        (tmp_path / "settings.py").write_text(f'API_KEY = "{_HIGH_ENTROPY_VALUE}"\n')

        first = _scan(tmp_path)
        second = _scan(tmp_path)

        assert first == second

    def test_result_order_is_independent_of_file_iteration_order(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "z.py").write_text(f'KEY_Z = "{_AWS_KEY}"\n')
        (tmp_path / "a.py").write_text(f'KEY_A = "{_AWS_KEY}"\n')

        root = resolve_repository_root(tmp_path)
        files = _files(tmp_path)

        forward = scan_repository_for_secrets(root, files)
        backward = scan_repository_for_secrets(root, list(reversed(files)))

        assert forward == backward


# --- agent configuration ----------------------------------------------------


@pytest.mark.parametrize(
    "relative_path",
    [
        ".claude/skills/example-skill/SKILL.md",
        ".mcp.json",
        ".cursor/mcp.json",
        ".codex/config.toml",
        ".gemini/settings.json",
        "examples/plugin/.claude-plugin/plugin.json",
        "tests/cline_mcp_settings.json",
    ],
)
def test_agent_configuration_is_never_a_fixture_path(relative_path: str) -> None:
    from controlloop.secret_scan import _looks_like_fixture_path, is_agent_config_path

    assert is_agent_config_path(relative_path)
    assert not _looks_like_fixture_path(relative_path)


def test_ordinary_fixture_paths_are_still_fixture_paths() -> None:
    from controlloop.secret_scan import _looks_like_fixture_path, is_agent_config_path

    assert not is_agent_config_path("tests/fixtures/config.json")
    assert _looks_like_fixture_path("tests/fixtures/config.json")


def test_a_literal_value_in_an_mcp_env_block_is_detected_without_the_value(
    tmp_path: Path,
) -> None:
    value = "Zq8vN2pL7xR4kT9mW3cY6bH1sD5fG0jA"
    (tmp_path / ".mcp.json").write_text(
        '{"mcpServers": {"mail": {"command": "npx", '
        f'"env": {{"MAIL_API_KEY": "{value}", "OTHER": "${{OTHER}}"}}}}}}}}'
    )
    root = resolve_repository_root(tmp_path)
    files = [entry for entry in walk_repository(root) if isinstance(entry, Path)]

    detections = scan_repository_for_secrets(root, files)

    assert [d.code for d in detections] == ["SECRET-HIGH-ENTROPY-VALUE-DETECTED"]
    assert detections[0].confidence.value == "medium"
    assert value not in repr(detections)


class TestDetectionKind:
    def test_names_the_credential_shape(self) -> None:
        from controlloop.secret_scan import _shape_message, detection_kind

        diagnostic = Diagnostic(
            code="SECRET-CREDENTIAL-SHAPE-DETECTED",
            severity=DiagnosticSeverity.ERROR,
            message=_shape_message("aws-access-key-id"),
            confidence=Confidence.HIGH,
            incomplete=False,
            evidence=(Evidence(adapter="secret-scan", path="config.py"),),
        )

        assert detection_kind(diagnostic) == "aws-access-key-id"

    def test_names_a_high_entropy_value(self) -> None:
        from controlloop.secret_scan import detection_kind

        diagnostic = Diagnostic(
            code="SECRET-HIGH-ENTROPY-VALUE-DETECTED",
            severity=DiagnosticSeverity.WARNING,
            message=(
                "A high-entropy value assigned to a credential-like variable "
                "was detected."
            ),
            confidence=Confidence.MEDIUM,
            incomplete=False,
            evidence=(Evidence(adapter="secret-scan", path="config.py"),),
        )

        assert detection_kind(diagnostic) == "high-entropy-value"

    def test_is_none_for_other_diagnostics(self) -> None:
        from controlloop.secret_scan import detection_kind

        diagnostic = Diagnostic(
            code="INCOMPLETE-BOUND-EXCEEDED",
            severity=DiagnosticSeverity.WARNING,
            message="stopped",
            confidence=Confidence.UNKNOWN,
            incomplete=True,
            evidence=(
                Evidence(adapter="secret-scan", path="<secret-scan-evaluation>"),
            ),
        )

        assert detection_kind(diagnostic) is None
