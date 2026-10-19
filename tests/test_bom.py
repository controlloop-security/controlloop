"""Tests for controlloop.bom."""

from __future__ import annotations

import subprocess
from pathlib import Path

from pytest import MonkeyPatch

from controlloop.acbom.versioning import CURRENT_SCHEMA_URL, CURRENT_SCHEMA_VERSION
from controlloop.bom import (
    _compute_root_digest,
    _resolve_commit,
    build_acbom_document,
)
from controlloop.repository import resolve_repository_root


def _init_repo(path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)


def _commit_all(path: Path, message: str) -> None:
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


class TestResolveCommit:
    def test_returns_head_commit_in_a_real_git_checkout(self, tmp_path: Path) -> None:
        _init_repo(tmp_path)
        (tmp_path / "file.txt").write_text("hello\n")
        _commit_all(tmp_path, "initial")
        expected = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=tmp_path,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

        assert _resolve_commit(tmp_path) == expected

    def test_returns_unknown_outside_a_git_checkout(self, tmp_path: Path) -> None:
        assert _resolve_commit(tmp_path) == "unknown"

    def test_returns_unknown_in_a_git_checkout_with_no_commits(
        self, tmp_path: Path
    ) -> None:
        _init_repo(tmp_path)

        assert _resolve_commit(tmp_path) == "unknown"

    def test_returns_unknown_when_git_is_not_installed(
        self, tmp_path: Path, monkeypatch: MonkeyPatch
    ) -> None:
        monkeypatch.setenv("PATH", "")

        assert _resolve_commit(tmp_path) == "unknown"


class TestComputeRootDigest:
    def test_is_independent_of_input_list_order(self, tmp_path: Path) -> None:
        first = tmp_path / "a.txt"
        second = tmp_path / "b.txt"
        first.write_text("a")
        second.write_text("b")

        forward = _compute_root_digest(tmp_path, [first, second])
        backward = _compute_root_digest(tmp_path, [second, first])

        assert forward == backward

    def test_differs_for_a_different_file_set(self, tmp_path: Path) -> None:
        first = tmp_path / "a.txt"
        second = tmp_path / "b.txt"
        first.write_text("a")
        second.write_text("b")

        one_file = _compute_root_digest(tmp_path, [first])
        two_files = _compute_root_digest(tmp_path, [first, second])

        assert one_file != two_files

    def test_matches_sha256_prefixed_format(self, tmp_path: Path) -> None:
        digest = _compute_root_digest(tmp_path, [])

        assert digest.startswith("sha256:")
        assert len(digest) == len("sha256:") + 64


class TestBuildAcbomDocument:
    def test_produces_a_digested_document_for_an_empty_repository(
        self, tmp_path: Path
    ) -> None:
        root = resolve_repository_root(tmp_path)

        document = build_acbom_document(root)

        assert document.schema_version == CURRENT_SCHEMA_VERSION
        assert document.schema_url == CURRENT_SCHEMA_URL
        assert document.nodes == ()
        assert document.edges == ()
        assert document.repository.commit == "unknown"
        assert document.digest.startswith("sha256:")

    def test_discovers_nodes_from_a_real_adapter(self, tmp_path: Path) -> None:
        (tmp_path / ".mcp.json").write_text(
            '{"mcpServers": {"files": {"command": "npx"}}}'
        )
        root = resolve_repository_root(tmp_path)

        document = build_acbom_document(root)

        # The server, plus the Claude Code host that `.mcp.json` declares.
        assert sorted(node.name for node in document.nodes) == ["Claude Code", "files"]

    def test_repeated_calls_over_unchanged_input_are_identical(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "file.txt").write_text("hello\n")
        root = resolve_repository_root(tmp_path)

        first = build_acbom_document(root)
        second = build_acbom_document(root)

        assert first.digest == second.digest

    def test_commit_override_replaces_resolved_commit(self, tmp_path: Path) -> None:
        """`commit_override` (used by merge-base scanning)
        must actually override, even inside a real git checkout that
        would otherwise resolve a different, real commit -- not merely
        "do no harm when absent"."""

        _init_repo(tmp_path)
        (tmp_path / "file.txt").write_text("hello\n")
        _commit_all(tmp_path, "initial")
        root = resolve_repository_root(tmp_path)
        override = "f" * 40

        document = build_acbom_document(root, commit_override=override)

        assert document.repository.commit == override
        assert document.repository.commit != _resolve_commit(tmp_path)

    def test_commit_override_none_preserves_existing_behavior(
        self, tmp_path: Path
    ) -> None:
        root = resolve_repository_root(tmp_path)

        document = build_acbom_document(root, commit_override=None)

        assert document.repository.commit == "unknown"


class TestSecretScanIntegration:
    """The discovery-time secret scan is wired into
    `build_acbom_document` alongside `walk_repository` and
    `run_adapters`."""

    def test_a_planted_credential_shape_produces_a_diagnostic(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "config.py").write_text('AWS_KEY = "AKIAABCDEFGHIJKLMNOP"\n')
        root = resolve_repository_root(tmp_path)

        document = build_acbom_document(root)

        codes = {diagnostic.code for diagnostic in document.diagnostics}
        assert "SECRET-CREDENTIAL-SHAPE-DETECTED" in codes

    def test_a_clean_repository_produces_no_secret_scan_diagnostics(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "app.py").write_text("def add(a, b):\n    return a + b\n")
        root = resolve_repository_root(tmp_path)

        document = build_acbom_document(root)

        codes = {diagnostic.code for diagnostic in document.diagnostics}
        assert "SECRET-CREDENTIAL-SHAPE-DETECTED" not in codes
        assert "SECRET-HIGH-ENTROPY-VALUE-DETECTED" not in codes

    def test_repeated_calls_with_a_planted_secret_are_still_deterministic(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "config.py").write_text('AWS_KEY = "AKIAABCDEFGHIJKLMNOP"\n')
        root = resolve_repository_root(tmp_path)

        first = build_acbom_document(root)
        second = build_acbom_document(root)

        assert first.digest == second.digest
        assert first.diagnostics == second.diagnostics
